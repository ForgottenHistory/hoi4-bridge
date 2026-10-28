// HOI4 console bridge: run console commands from outside the game, without keyboard input.
// Loaded as version.dll from the HOI4 folder. Writes console_bridge.log next to itself.
//
// Clients connect to the named pipe \\.\pipe\hoi4_console_bridge, send one message holding one or more
// command lines, and get one reply line per command: "OK <message>", "FAIL <message>" or "ERROR <reason>".
// Commands are queued and run at the next frame on the game's render/main thread (the same thread the
// in-game console uses), through the game's own console dispatcher.

#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <cstdio>
#include <cstdint>
#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <string>
#include <deque>
#include <memory>
#include <mutex>
#include <vector>
#include <algorithm>
#include "MinHook.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

// Forward every version.dll export to the real system DLL.
#define FWD(name) __pragma(comment(linker, "/export:" #name "=C:\\Windows\\System32\\version." #name))
FWD(GetFileVersionInfoA) FWD(GetFileVersionInfoByHandle) FWD(GetFileVersionInfoExA) FWD(GetFileVersionInfoExW)
FWD(GetFileVersionInfoSizeA) FWD(GetFileVersionInfoSizeExA) FWD(GetFileVersionInfoSizeExW) FWD(GetFileVersionInfoSizeW)
FWD(GetFileVersionInfoW) FWD(VerFindFileA) FWD(VerFindFileW) FWD(VerInstallFileA) FWD(VerInstallFileW)
FWD(VerLanguageNameA) FWD(VerLanguageNameW) FWD(VerQueryValueA) FWD(VerQueryValueW)

static const char* kPipeName = "\\\\.\\pipe\\hoi4_console_bridge";
static const int   kMaxPerFrame = 8;        // commands run per frame
static const DWORD kReplyTimeoutMs = 15000; // how long a client waits for its commands to run

// ---------------------------------------------------------------- logging
static CRITICAL_SECTION g_logLock;
static char g_logPath[MAX_PATH];

static void Log(const char* fmt, ...) {
    char line[1024];
    SYSTEMTIME t; GetLocalTime(&t);
    int n = snprintf(line, sizeof line, "%02d:%02d:%02d.%03d [tid %5lu] ", t.wHour, t.wMinute, t.wSecond,
                     t.wMilliseconds, GetCurrentThreadId());
    va_list ap; va_start(ap, fmt);
    vsnprintf(line + n, sizeof line - n - 2, fmt, ap);
    va_end(ap);
    strcat_s(line, "\n");
    EnterCriticalSection(&g_logLock);
    FILE* f = nullptr;
    if (fopen_s(&f, g_logPath, "a") == 0 && f) { fputs(line, f); fclose(f); }
    LeaveCriticalSection(&g_logLock);
}

// ---------------------------------------------------------------- pattern scan
static uint8_t* FindPattern(uint8_t* from, uint8_t* to, const char* pat) {
    int bytes[128], n = 0;
    for (const char* p = pat; *p && n < 128;) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (p[0] == '?') { bytes[n++] = -1; p += (p[1] == '?') ? 2 : 1; }
        else { bytes[n++] = (int)strtol(p, nullptr, 16); p += 2; }
    }
    for (uint8_t* c = from; c + n <= to; c++) {
        int i = 0;
        while (i < n && (bytes[i] < 0 || c[i] == bytes[i])) i++;
        if (i == n) return c;
    }
    return nullptr;
}
static uint8_t* Rel32(uint8_t* insn, int dispOffset, int insnLen) {
    return insn + insnLen + *(int32_t*)(insn + dispOffset);
}

// ---------------------------------------------------------------- game data layouts (MSVC x64)
struct MsvcString { union { char buf[16]; char* ptr; }; size_t size; size_t cap; };
static const char* StrData(const MsvcString* s) { return s->cap > 15 ? s->ptr : s->buf; }
struct PdxArray { void* data; int capacity; int size; void* alloc; };

using DispatchFn = void*(__fastcall*)(void* mgr, void* out, PdxArray* words);
using SplitFn    = void*(__fastcall*)(MsvcString* line, PdxArray* out, char sep);
using GetInstFn  = void(__fastcall*)();

static uint8_t*   g_base;
static uint8_t*   g_textStart;  // hoi4.exe code section
static uint8_t*   g_textEnd;
static DispatchFn g_dispatch;  // CConsoleCmdManager::Execute wrapper
static SplitFn    g_split;     // CString::Split
static GetInstFn  g_getInst;   // creates the console manager and stores it in the slot
static void**     g_slot;      // global CConsoleCmdManager*

static bool ScanGame() {
    g_base = (uint8_t*)GetModuleHandleW(nullptr);
    auto dos = (IMAGE_DOS_HEADER*)g_base;
    auto nt = (IMAGE_NT_HEADERS*)(g_base + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    uint8_t *ts = nullptr, *te = nullptr;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
        if (!memcmp(sec->Name, ".text", 5)) { ts = g_base + sec->VirtualAddress; te = ts + sec->Misc.VirtualSize; }
    if (!ts) { Log("scan: no .text section"); return false; }

    // Inside the `run` console command: line.Split(&words, ' ')
    uint8_t* split = FindPattern(ts, te, "41 B0 20 48 8D 54 24 ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 90 48 8B D0");
    g_textStart = ts; g_textEnd = te;
    if (!split) { Log("scan: split pattern NOT found"); return false; }
    // A little later: mgr = slot ? slot : create(); mgr->Execute(&result, &words)
    uint8_t* disp = FindPattern(split, split + 0x100,
        "48 8B 0D ?? ?? ?? ?? 48 85 C9 75 ?? E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 4C 8D 44 24 ?? 48 8D 55 ?? E8 ?? ?? ?? ??");
    if (!disp) { Log("scan: dispatch pattern NOT found"); return false; }

    g_split    = (SplitFn)Rel32(split + 13, 1, 5);
    g_slot     = (void**)Rel32(disp, 3, 7);
    g_getInst  = (GetInstFn)Rel32(disp + 12, 1, 5);
    g_dispatch = (DispatchFn)Rel32(disp + 33, 1, 5);
    Log("scan: split=hoi4+%#llx dispatch=hoi4+%#llx getInst=hoi4+%#llx slot=hoi4+%#llx",
        (unsigned long long)((uint8_t*)g_split - g_base), (unsigned long long)((uint8_t*)g_dispatch - g_base),
        (unsigned long long)((uint8_t*)g_getInst - g_base), (unsigned long long)((uint8_t*)g_slot - g_base));
    return true;
}

// ---------------------------------------------------------------- localisation database
// The game keeps all localisation in one database (global pointer below). Its loader for .yml files calls
//   AddEntries(currentLanguage, keys[], values[], count, mode 3 = overwrite if changed, nullptr, filePath)
// We call the same function to change keys without a full `reload loc`.
using AddEntriesFn = void(__fastcall*)(const char* lang, const char** keys, const char** values, int count,
                                        int mode, const char* prefix, const char* file);
using GetLangFn    = const char*(__fastcall*)();
static AddEntriesFn g_addEntries;
static GetLangFn    g_getLang;
static uint8_t**    g_locDb;     // db: +0x20 text buffer, +0x28 capacity (int), +0x2c used (int)
static bool         g_locReady = false;

static bool ScanLoc() {
    auto dos = (IMAGE_DOS_HEADER*)g_base;
    auto nt = (IMAGE_NT_HEADERS*)(g_base + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    uint8_t *ts = nullptr, *te = nullptr;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
        if (!memcmp(sec->Name, ".text", 5)) { ts = g_base + sec->VirtualAddress; te = ts + sec->Misc.VirtualSize; }
    // The .yml loader: call GetLang; ... mode 3 ...; call AddEntries
    uint8_t* p = FindPattern(ts, te,
        "E8 ?? ?? ?? ?? 48 89 5C 24 30 48 C7 44 24 28 00 00 00 00 C7 44 24 20 03 00 00 00 44 8B 4D ?? "
        "48 8B 7D ?? 4C 8B C7 48 8B 5D ?? 48 8B D3 48 8B C8 E8 ?? ?? ?? ??");
    if (!p) { Log("loc scan: loader pattern NOT found; loc commands disabled"); return false; }
    g_getLang    = (GetLangFn)Rel32(p, 1, 5);
    g_addEntries = (AddEntriesFn)Rel32(p + 48, 1, 5);
    uint8_t* gl = (uint8_t*)g_getLang;
    if (gl[0] != 0x48 || gl[1] != 0x8B || gl[2] != 0x05) { Log("loc scan: unexpected GetLang code"); return false; }
    g_locDb = (uint8_t**)Rel32(gl, 3, 7);
    Log("loc scan: addEntries=hoi4+%#llx getLang=hoi4+%#llx db=hoi4+%#llx",
        (unsigned long long)((uint8_t*)g_addEntries - g_base), (unsigned long long)(gl - g_base),
        (unsigned long long)((uint8_t*)g_locDb - g_base));
    return true;
}

struct PoolState { uint8_t* buf; int cap; int used; };
static bool ReadPool(PoolState* s) {
    __try {
        uint8_t* db = *g_locDb;
        if (!db) return false;
        s->buf = *(uint8_t**)(db + 0x20); s->cap = *(int*)(db + 0x28); s->used = *(int*)(db + 0x2c);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static const char* SafeGetLang() {
    __try { return g_getLang(); } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

// returns 1 ok, -1 crashed. SEH only, no C++ objects.
static int RawAddEntries(const char** keys, const char** values, int n, const char* file, char* msg, size_t cap) {
    __try {
        const char* lang = g_getLang();
        if (!lang) { strcpy_s(msg, cap, "no current language (localisation not loaded yet?)"); return 0; }
        g_addEntries(lang, keys, values, n, 3, nullptr, file);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        snprintf(msg, cap, "exception %#lx inside the game's localisation code", GetExceptionCode());
        return -1;
    }
}

// Applies key/value pairs; reports how the shared text buffer changed.
static std::string ApplyLoc(const std::vector<std::pair<std::string, std::string>>& kv, const char* file) {
    if (!g_locReady) return "ERROR localisation support not active (see console_bridge.log)";
    if (kv.empty()) return "FAIL no entries";
    std::vector<const char*> k, v;
    for (auto& e : kv) { k.push_back(e.first.c_str()); v.push_back(e.second.c_str()); }
    PoolState before = {}, after = {};
    ReadPool(&before);
    char msg[512] = "";
    int rc = RawAddEntries(k.data(), v.data(), (int)kv.size(), file, msg, sizeof msg);
    ReadPool(&after);
    if (rc < 0) return std::string("ERROR ") + msg;
    if (rc == 0) return std::string("FAIL ") + msg;
    char out[300];
    snprintf(out, sizeof out, "OK %zu entries applied; text buffer %d/%d bytes%s", kv.size(), after.used, after.cap,
             before.buf && after.buf != before.buf ? " (buffer was enlarged and moved)" : "");
    if (before.buf && after.buf != before.buf)
        Log("NOTE: localisation text buffer moved from %p to %p while the game was running", before.buf, after.buf);
    return out;
}

// Minimal .yml localisation parser:   key:0 "value"   (header line l_xxx: and # comments skipped)
static bool ParseLocFile(const std::string& path, std::vector<std::pair<std::string, std::string>>& out,
                         std::string& err) {
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "rb") != 0 || !f) { err = "cannot open " + path; return false; }
    std::string data; char buf[65536]; size_t got;
    while ((got = fread(buf, 1, sizeof buf, f)) > 0) data.append(buf, got);
    fclose(f);
    if (data.size() >= 3 && (uint8_t)data[0] == 0xEF && (uint8_t)data[1] == 0xBB && (uint8_t)data[2] == 0xBF) data.erase(0, 3);
    size_t pos = 0; int lineNo = 0;
    while (pos < data.size()) {
        size_t nl = data.find('\n', pos); if (nl == std::string::npos) nl = data.size();
        std::string line = data.substr(pos, nl - pos); pos = nl + 1; lineNo++;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t s = line.find_first_not_of(" \t");
        if (s == std::string::npos || line[s] == '#') continue;
        size_t colon = line.find(':', s);
        if (colon == std::string::npos) continue;
        std::string key = line.substr(s, colon - s);
        if (key.find_first_of(" \t\"") != std::string::npos) continue;
        size_t q1 = line.find('"', colon);
        if (q1 == std::string::npos) continue;           // e.g. the l_english: header
        size_t q2 = line.rfind('"');
        if (q2 <= q1) { err = "line " + std::to_string(lineNo) + ": missing closing quote"; return false; }
        out.emplace_back(key, line.substr(q1 + 1, q2 - q1 - 1));
    }
    return true;
}

// ---------------------------------------------------------------- live country data
// The save game writes each country with CCountry::Write(country, CWriter*) (vtable slot 2). A CWriter in text
// mode sends every piece of text to output->vtable[6](output, const char*). We give it our own output object
// that appends to a string, so we get the exact save-file text of one country without saving the game.
using TagParseFn  = int*(__fastcall*)(int* outId, MsvcString* tag);
using CountryFn   = void*(__fastcall*)(int* id);
using TagNameFn   = MsvcString*(__fastcall*)(int* id);
using WriterCtor  = void*(__fastcall*)(void* writer, void* output, char flag);
using BufCtor     = void*(__fastcall*)(void* buf);
using MemFileCtor = void*(__fastcall*)(void* file, void* buf, int textMode, int writeMode, char flag);
static BufCtor     g_bufCtor;
static MemFileCtor g_memFileCtor;
static TagParseFn g_tagParse;
static CountryFn  g_countryById;
static TagNameFn  g_tagName;
static WriterCtor g_writerCtor;
static uint8_t**  g_gamestate;
static bool       g_dataReady = false;

static bool ScanData() {
    auto dos = (IMAGE_DOS_HEADER*)g_base;
    auto nt = (IMAGE_NT_HEADERS*)(g_base + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    uint8_t *ts = nullptr, *te = nullptr;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
        if (!memcmp(sec->Name, ".text", 5)) { ts = g_base + sec->VirtualAddress; te = ts + sec->Misc.VirtualSize; }
    uint8_t* a = FindPattern(ts, te, "48 8B 13 48 83 C2 20 48 8D 4D ?? E8 ?? ?? ?? ?? 8B 08");            // civilwar: tag -> id
    uint8_t* b = FindPattern(ts, te, "48 8D 4D ?? E8 ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 8B 88 D0 00 00 00"); // id -> country
    uint8_t* c = FindPattern(ts, te, "40 53 48 83 EC 30 48 83 3D ?? ?? ?? ?? 00 48 8B D9 0F 84 ?? ?? ?? ?? 83 39 00 0F 84"); // id -> tag name
    uint8_t* d = FindPattern(ts, te, "48 8D 05 ?? ?? ?? ?? C7 41 08 00 00 00 00 48 89 01 44 88 41 19 C6 41 1A 00 83 7A 10 00 48 89 51 10 0F 94 C0 88 41 18"); // CWriter ctor
    // The game writing its state to memory as text: new buffer; new CMemoryFile(buffer, text=1, write=1, 1)
    uint8_t* e = FindPattern(ts, te, "48 8B C8 E8 ?? ?? ?? ?? 48 8B D8 EB ?? 48 8B DF B9 58 00 00 00 E8 ?? ?? ?? ?? "
        "48 89 84 24 ?? ?? ?? ?? 48 85 C0 74 ?? C6 44 24 20 01 41 B9 01 00 00 00 45 8B C1 48 8B D3 48 8B C8 E8 ?? ?? ?? ??");
    if (!a || !b || !c || !d || !e) { Log("data scan: pattern missing (%p %p %p %p %p); country data disabled", a, b, c, d, e); return false; }
    g_bufCtor     = (BufCtor)Rel32(e + 3, 1, 5);
    g_memFileCtor = (MemFileCtor)Rel32(e + 59, 1, 5);
    g_tagParse    = (TagParseFn)Rel32(a + 11, 1, 5);
    g_countryById = (CountryFn)Rel32(b + 4, 1, 5);
    g_tagName     = (TagNameFn)c;
    g_gamestate   = (uint8_t**)Rel32(c + 6, 3, 8);
    g_writerCtor  = (WriterCtor)d;
    Log("data scan: tagParse=hoi4+%#llx countryById=hoi4+%#llx tagName=hoi4+%#llx gamestate=hoi4+%#llx writerCtor=hoi4+%#llx",
        (unsigned long long)((uint8_t*)g_tagParse - g_base), (unsigned long long)((uint8_t*)g_countryById - g_base),
        (unsigned long long)(c - g_base), (unsigned long long)((uint8_t*)g_gamestate - g_base),
        (unsigned long long)(d - g_base));
    return true;
}

static bool InGameCode(void* p) { return (uint8_t*)p >= g_textStart && (uint8_t*)p < g_textEnd; }

// SEH-only helpers (no C++ objects inside)
static void* RawCountryByTag(const char* tag, char* err, size_t cap) {
    __try {
        MsvcString s = {}; size_t n = strlen(tag);
        if (n == 0 || n > 15) { strcpy_s(err, cap, "bad tag"); return nullptr; }
        memcpy(s.buf, tag, n); s.size = n; s.cap = 15;
        int id = 0;
        g_tagParse(&id, &s);
        if (id < 1) { strcpy_s(err, cap, "unknown country tag"); return nullptr; }
        void* country = g_countryById(&id);
        if (!country) { strcpy_s(err, cap, "country does not exist"); return nullptr; }
        return country;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        snprintf(err, cap, "exception %#lx looking up the country", GetExceptionCode());
        return nullptr;
    }
}
// For C++ exceptions (0xE06D7363) thrown inside game code: read the thrown type's name from the ThrowInfo.
static char g_lastThrowType[160];
static int DescribeException(EXCEPTION_POINTERS* ep) {
    g_lastThrowType[0] = 0;
    __try {
        auto* r = ep->ExceptionRecord;
        if (r->ExceptionCode == 0xE06D7363 && r->NumberParameters >= 4) {
            uint8_t* imageBase = (uint8_t*)r->ExceptionInformation[3];
            uint8_t* throwInfo = (uint8_t*)r->ExceptionInformation[2];
            int ctaRva = *(int*)(throwInfo + 12);                 // pCatchableTypeArray
            uint8_t* cta = imageBase + ctaRva;
            int count = *(int*)cta;
            for (int i = 0; i < count && i < 4; i++) {
                uint8_t* ct = imageBase + *(int*)(cta + 4 + 4 * i);
                uint8_t* td = imageBase + *(int*)(ct + 4);          // TypeDescriptor: vfptr, spare, name
                strncat_s(g_lastThrowType, (const char*)(td + 16), _TRUNCATE);
                strncat_s(g_lastThrowType, " ", _TRUNCATE);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return EXCEPTION_EXECUTE_HANDLER;
}

static void AppendText(std::string* dst, const char* p, int n) { dst->append(p, (size_t)n); }

// Writes the country through the game's own CMemoryFile (text mode) and copies the result into *dst.
static int RawWriteCountry(void* country, std::string* dst, char* err, size_t cap) {
    alignas(16) uint8_t buffer[0x40] = {};     // CPdxArray<char>: data, capacity, size (+0xc), allocator (+0x10)
    alignas(16) uint8_t memfile[0x100] = {};   // CMemoryFile is 0x58 bytes
    alignas(16) uint8_t writer[0x40] = {};
    __try {
        void** vt = *(void***)country;
        void* writeFn = vt[2];
        if (!InGameCode(writeFn)) { strcpy_s(err, cap, "country object looks wrong (write slot outside game code)"); return 0; }
        g_bufCtor(buffer);
        g_memFileCtor(memfile, buffer, 1, 1, 1);
        g_writerCtor(writer, memfile, 0);
        *(int*)(writer + 8) = 2;                       // depth: fields of countries={ TAG={ ... } }
        ((void(__fastcall*)(void*, void*))writeFn)(country, writer);
        char* data = *(char**)buffer;
        int size = *(int*)(buffer + 0xc);
        if (data && size > 0) AppendText(dst, data, size);
        void* alloc = *(void**)(buffer + 0x10);
        if (data && alloc) ((void(__fastcall*)(void*, void*))(*(void***)alloc)[2])(alloc, data);
        return 1;
    } __except (DescribeException(GetExceptionInformation())) {
        snprintf(err, cap, "exception %#lx (%s) while the game wrote the country", GetExceptionCode(),
                 g_lastThrowType[0] ? g_lastThrowType : "no C++ type");
        char* data = *(char**)buffer;                  // keep what was written so far, for diagnosis
        int size = *(int*)(buffer + 0xc);
        if (data && size > 0 && size < (64 << 20)) AppendText(dst, data, size);
        return -1;
    }
}
static const char* RawPlayerTag() {
    __try {
        uint8_t* gs = *g_gamestate;
        if (!gs) return nullptr;
        int id = *(int*)(gs + 0x520);
        if (id < 1) id = *(int*)(gs + 0x524);
        if (id < 1) return nullptr;
        MsvcString* s = g_tagName(&id);
        return s ? StrData(s) : nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

static std::string DumpCountry(std::string tag) {
    if (!g_dataReady) return "ERROR country data support not active (see console_bridge.log)";
    for (auto& ch : tag) ch = (char)toupper((unsigned char)ch);
    char err[256] = "";
    void* country = RawCountryByTag(tag.c_str(), err, sizeof err);
    if (!country) return std::string("FAIL ") + err;
    std::string buf; buf.reserve(256 * 1024);
    int rc = RawWriteCountry(country, &buf, err, sizeof err);
    if (rc < 0) {
        std::string tail = buf.size() > 600 ? buf.substr(buf.size() - 600) : buf;
        for (auto& ch : tail) if (ch == '\n') ch = '|'; else if (ch == '\t') ch = ' ';
        Log("country dump %s failed after %zu chars: %s; tail: %s", tag.c_str(), buf.size(), err, tail.c_str());
        return std::string("ERROR ") + err + " after " + std::to_string(buf.size()) + " chars; tail: " + tail;
    }
    if (rc == 0) return std::string("FAIL ") + err;
    return "OK \t" + tag + "={\n" + buf + "\t}";
}

// ---------------------------------------------------------------- surrender
// The war overview's surrender tooltip ("controls X% of Victory Points and will capitulate when it has VAL% or
// less", waroverviewitems.cpp) asks the country three things. Each writes an int64 fixed-point value into *out
// (100000 = 100%) and returns out:
//   progress(country, out)    surrender progress = occupation / limit; the country capitulates at 100%
//   occupation(country, out)  share of its victory points that others control (the tooltip shows 100% - this)
//   limit(country, out)       surrender limit: BASE_SURRENDER_LIMIT + surrender_limit modifier, x0.7 with no
//                             owned cores, clamped to MIN_SURRENDER_LIMIT and 1 - max_surrender_limit_offset,
//                             then + forced_surrender_limit, clamped to 0..1 (the tooltip shows 100% - this)
using FixedFn = long long*(__fastcall*)(void* country, long long* out);
static FixedFn g_surrProgress, g_surrOccupation, g_surrLimit;
static bool    g_surrReady = false;

static bool ScanSurrender() {
    uint8_t* lim = FindPattern(g_textStart, g_textEnd,
        "48 89 5C 24 10 48 89 6C 24 18 48 89 74 24 20 57 48 83 EC 20 48 8B FA 48 8B F1 48 8D 54 24 30 "
        "48 81 C1 B8 05 00 00 41 B8 92 00 00 00 E8 ?? ?? ?? ?? 4C 8B 0D ?? ?? ?? ?? 48 8D 54 24 30");
    uint8_t* occ = FindPattern(g_textStart, g_textEnd,
        "40 53 48 83 EC 30 48 8B DA 48 C7 02 00 00 00 00 48 63 91 40 13 00 00 85 D2 7E ?? 48 63 81 38 13 00 00 "
        "EB ?? 48 63 91 44 13 00 00 85 D2 7E ?? 48 63 81 3C 13 00 00 4C 69 C2 A0 86 01 00");
    uint8_t* prog = FindPattern(g_textStart, g_textEnd,
        "40 55 41 56 41 57 48 83 EC 40 83 B9 34 04 00 00 00 4C 8B FA 4C 8B F1 75 ?? BD A0 86 01 00 48 8B C2 "
        "48 89 2A 48 83 C4 40 41 5F 41 5E 5D C3 48 89 5C 24 68 48 8D 54 24 60 48 89 74 24 70");
    if (!lim || !occ || !prog) {
        Log("surrender scan: pattern missing (%p %p %p); bridge.surrender disabled", lim, occ, prog);
        return false;
    }
    g_surrLimit = (FixedFn)lim; g_surrOccupation = (FixedFn)occ; g_surrProgress = (FixedFn)prog;
    Log("surrender scan: progress=hoi4+%#llx occupation=hoi4+%#llx limit=hoi4+%#llx",
        (unsigned long long)(prog - g_base), (unsigned long long)(occ - g_base), (unsigned long long)(lim - g_base));
    return true;
}

static bool RawSurrender(void* country, long long v[3], char* err, size_t cap) {
    __try {
        g_surrProgress(country, &v[0]);
        g_surrOccupation(country, &v[1]);
        g_surrLimit(country, &v[2]);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        snprintf(err, cap, "exception %#lx while the game computed surrender", GetExceptionCode());
        return false;
    }
}

static std::string Surrender(std::string tag) {
    if (!g_dataReady || !g_surrReady) return "ERROR surrender support not active (see console_bridge.log)";
    for (auto& ch : tag) ch = (char)toupper((unsigned char)ch);
    char err[256] = "";
    void* country = RawCountryByTag(tag.c_str(), err, sizeof err);
    if (!country) return std::string("FAIL ") + err;
    long long v[3] = {};
    if (!RawSurrender(country, v, err, sizeof err)) return std::string("ERROR ") + err;
    char out[160];
    snprintf(out, sizeof out, "OK progress=%.5f occupation=%.5f limit=%.5f", v[0] / 100000.0, v[1] / 100000.0,
             v[2] / 100000.0);
    return out;
}

// ---------------------------------------------------------------- edit boxes
// CEditBox (clausewitz editboxtype.cpp) holds its text buffer as a subobject at +0x80. The buffer stores the text
// as a std::u32string at +0x30 (size +0x40, capacity +0x48; inline when capacity <= 3). Every change that adds
// text goes through Insert(buffer, const u32string*): typing, paste and SetText(buffer, const char* utf8).
// Vtable slot 0xa8 of the box returns its .gui name (const std::string*).
//
// We hook Insert to learn which box has which name, and the destructor to keep the last text of a box that
// closes (a popup's Send button may close it before a client asks). Boxes that only had characters deleted are
// still read live, so the text is always current while the box exists.
struct U32String { union { uint32_t buf[4]; uint32_t* ptr; }; size_t size; size_t cap; };
using EbInsertFn  = void(__fastcall*)(void* buffer, void* text);
using EbSetTextFn = void(__fastcall*)(void* buffer, const char* utf8);
using EbDtorFn    = void*(__fastcall*)(void* box, unsigned flags);
static EbInsertFn  g_ebInsert, o_ebInsert;
static EbSetTextFn g_ebSetText;
static EbDtorFn    g_ebDtor, o_ebDtor;
static void*       g_editBoxVt;
static bool        g_ebReady = false;

struct TrackedBox { void* box = nullptr; std::string text; };   // box == nullptr once destroyed
static std::recursive_mutex g_ebLock;                           // re-entered when our SetText runs Insert
static std::vector<std::pair<std::string, TrackedBox>> g_boxes;    // by name; few entries
// Text buffer flag +0xf0 (box+0x80+0xf0): Enter inserts "\n" when set, otherwise it only notifies observers.
// The buffer constructor clears it, only the Enter handler reads it, and .gui editBoxType can't set it, so
// bridge.editbox.multiline NAME does. The text box itself still draws one line (the one with the cursor);
// show the whole text elsewhere with bridge.editbox.mirror.
static const size_t kEbEnterNewline = 0x80 + 0xf0;
static std::vector<std::string> g_multilineNames;

// Mirrors: show a text box's whole text in an instant text box (which wraps and draws many lines).
// CInstantTextBox::SetText(box, std::string by value) is hooked to learn the page's address by its .gui
// name; every frame, a changed text is set on the page through the same function.
// original: the text the game itself last gave the page (its .gui text), shown while the box is empty.
struct Mirror { std::string box, page, original; void* pagePtr = nullptr; std::string shown; bool dirty = true; };
static std::vector<Mirror> g_mirrors;                                    // guarded by g_ebLock
using TbSetTextFn = void(__fastcall*)(void* textbox, MsvcString* byValue);   // callee frees the string
using StrCopyFn   = MsvcString*(__fastcall*)(MsvcString* dst, const MsvcString* src);
static TbSetTextFn g_tbSetText, o_tbSetText;
static StrCopyFn   g_strCopy;                    // the game's std::string copy: its allocator owns the result
static bool        g_tbReady = false, g_inMirrorSet = false;

static bool ScanEditBox() {
    uint8_t *ts = g_textStart, *te = g_textEnd;
    uint8_t* ins = FindPattern(ts, te, "48 89 74 24 18 57 48 83 EC 40 83 7A 10 01 48 8B F2 48 8B F9 75 ?? 48 8B 81 D8 00 00 00 48 85 C0 74 ?? 48 8B 52 18 48 8B CE 48 83 FA 03 76 ??");
    uint8_t* set = FindPattern(ts, te, "48 89 5C 24 10 57 48 83 EC 40 48 8B D9 0F 57 C0 0F 11 44 24 20 66 0F 6F 0D ?? ?? ?? ?? F3 0F 7F 4C 24 30 33 FF 89 7C 24 20 48 8D 4C 24 20");
    // 1.19.4 split the deleting destructor from the plain one (no flags argument, vftable lea at +0x12);
    // earlier versions hook the deleting destructor (flags in edx, lea at +0x19).
    uint8_t* dtor = FindPattern(ts, te, "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B D9 48 8D 05 ?? ?? ?? ?? 48 89 01 48 8D 05 ?? ?? ?? ?? 48 89 81 80 00 00 00 48 8D 05 ?? ?? ?? ?? 48 89 81 A0 01 00 00");
    size_t vtOff = 0x12;
    if (!dtor) {
        dtor = FindPattern(ts, te, "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 8B EA 48 8B D9 48 8D 05 ?? ?? ?? ?? 48 89 01 48 8D 05 ?? ?? ?? ?? 48 89 81 80 00 00 00 48 8D 05 ?? ?? ?? ?? 48 89 81 A0 01 00 00");
        vtOff = 0x19;
    }
    if (!ins || !set || !dtor) { Log("editbox scan: pattern missing (%p %p %p); editbox support disabled", ins, set, dtor); return false; }
    g_ebInsert  = (EbInsertFn)ins;
    g_ebSetText = (EbSetTextFn)set;
    g_ebDtor    = (EbDtorFn)dtor;
    g_editBoxVt = Rel32(dtor + vtOff, 3, 7);                    // lea rax, [CEditBox::vftable]
    Log("editbox scan: insert=hoi4+%#llx settext=hoi4+%#llx dtor=hoi4+%#llx vftable=hoi4+%#llx",
        (unsigned long long)(ins - g_base), (unsigned long long)(set - g_base), (unsigned long long)(dtor - g_base),
        (unsigned long long)((uint8_t*)g_editBoxVt - g_base));
    return true;
}

// SEH-only helpers. name gets the box's .gui name; returns false if p isn't a CEditBox.
static bool RawBoxName(void* box, char* name, size_t cap) {
    __try {
        if (*(void**)box != g_editBoxVt) return false;
        auto getName = (const MsvcString*(__fastcall*)(void*))(*(void***)box)[0xa8 / 8];
        if (!InGameCode((void*)getName)) return false;
        const MsvcString* s = getName(box);
        if (!s || s->size == 0 || s->size >= cap) return false;
        memcpy(name, StrData(s), s->size); name[s->size] = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
// Copies up to cap UTF-32 code points; returns the count, or -1 if the box can't be read.
static long long RawBoxText(void* box, uint32_t* out, size_t cap) {
    __try {
        if (*(void**)box != g_editBoxVt) return -1;
        auto* s = (U32String*)((uint8_t*)box + 0x80 + 0x30);
        size_t n = s->size;
        if (n > cap) n = cap;
        const uint32_t* d = s->cap > 3 ? s->ptr : s->buf;
        memcpy(out, d, n * 4);
        return (long long)n;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
}
static bool RawBoxSetMultiline(void* box, bool on) {
    __try {
        if (*(void**)box != g_editBoxVt) return false;
        ((uint8_t*)box)[kEbEnterNewline] = on ? 1 : 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
static bool IsMultilineName(const char* name) {               // caller holds g_ebLock
    for (auto& n : g_multilineNames) if (n == name) return true;
    return false;
}
// .gui name of any GUI object (vtable slot 0xa8 is the same getter for all of them).
static bool RawGuiName(void* obj, char* name, size_t cap) {
    __try {
        auto getName = (const MsvcString*(__fastcall*)(void*))(*(void***)obj)[0xa8 / 8];
        if (!InGameCode((void*)getName)) return false;
        const MsvcString* s = getName(obj);
        if (!s || s->size == 0 || s->size >= cap) return false;
        memcpy(name, StrData(s), s->size); name[s->size] = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
static bool RawPageSetText(void* page, const char* data, size_t n) {
    __try {
        MsvcString src = {}, dst = {};
        if (n < 16) { memcpy(src.buf, data, n); src.buf[n] = 0; src.cap = 15; }
        else { src.ptr = (char*)data; src.cap = n; }
        src.size = n;
        g_strCopy(&dst, &src);
        g_tbSetText(page, &dst);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
static bool RawBoxSetText(void* box, const char* utf8) {
    __try {
        if (*(void**)box != g_editBoxVt) return false;
        g_ebSetText((uint8_t*)box + 0x80, utf8);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static void AppendUtf8(std::string& out, uint32_t c) {
    if (c < 0x80) out += (char)c;
    else if (c < 0x800) { out += (char)(0xC0 | (c >> 6)); out += (char)(0x80 | (c & 0x3F)); }
    else if (c < 0x10000) { out += (char)(0xE0 | (c >> 12)); out += (char)(0x80 | ((c >> 6) & 0x3F)); out += (char)(0x80 | (c & 0x3F)); }
    else if (c < 0x110000) { out += (char)(0xF0 | (c >> 18)); out += (char)(0x80 | ((c >> 12) & 0x3F));
                             out += (char)(0x80 | ((c >> 6) & 0x3F)); out += (char)(0x80 | (c & 0x3F)); }
}
static long long RawBoxLen(void* box) {
    __try {
        if (*(void**)box != g_editBoxVt) return -1;
        return (long long)((U32String*)((uint8_t*)box + 0x80 + 0x30))->size;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
}
static bool ReadBoxUtf8(void* box, std::string& out) {
    long long len = RawBoxLen(box);
    if (len < 0) return false;
    std::vector<uint32_t> tmp((size_t)(len < 65536 ? len : 65536) + 1);
    long long n = RawBoxText(box, tmp.data(), tmp.size());
    if (n < 0) return false;
    out.clear();
    for (long long i = 0; i < n; i++) AppendUtf8(out, tmp[i]);
    return true;
}
static TrackedBox* FindBox(const std::string& name) {          // caller holds g_ebLock
    for (auto& e : g_boxes) if (e.first == name) return &e.second;
    return nullptr;
}

static void __fastcall hk_ebInsert(void* buffer, void* text) {
    o_ebInsert(buffer, text);
    void* box = (uint8_t*)buffer - 0x80;
    char name[128];
    if (!RawBoxName(box, name, sizeof name)) return;
    std::string utf8;
    if (!ReadBoxUtf8(box, utf8)) return;
    std::lock_guard<std::recursive_mutex> lk(g_ebLock);
    TrackedBox* t = FindBox(name);
    if (!t) { g_boxes.push_back({ name, TrackedBox() }); t = &g_boxes.back().second; Log("editbox: tracking \"%s\"", name); }
    t->box = box;
    t->text = std::move(utf8);
    if (IsMultilineName(name)) RawBoxSetMultiline(box, true);
}
static void* __fastcall hk_ebDtor(void* box, unsigned flags) {
    {
        std::lock_guard<std::recursive_mutex> lk(g_ebLock);
        char name[128];
        if (!g_mirrors.empty() && RawBoxName(box, name, sizeof name))
            for (auto& m : g_mirrors) if (m.box == name) { m.pagePtr = nullptr; m.dirty = true; }
        for (auto& e : g_boxes) {
            if (e.second.box != box) continue;
            std::string last;
            if (ReadBoxUtf8(box, last)) e.second.text = std::move(last);
            e.second.box = nullptr;
        }
    }
    return o_ebDtor(box, flags);
}

// Pages are drawn from the game's own encoding (Windows-1252); colour-code markers are dropped.
static std::string Utf8ToGameText(const std::string& u) {
    if (u.empty()) return u;
    int wn = MultiByteToWideChar(CP_UTF8, 0, u.data(), (int)u.size(), nullptr, 0);
    std::wstring w(wn, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, u.data(), (int)u.size(), &w[0], wn);
    w.erase(std::remove(w.begin(), w.end(), L'\u00a7'), w.end());
    int n = WideCharToMultiByte(1252, 0, w.data(), (int)w.size(), nullptr, 0, "?", nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(1252, 0, w.data(), (int)w.size(), &out[0], n, "?", nullptr);
    return out;
}

static bool RawCopyText(const MsvcString* s, std::vector<char>& buf, size_t* n) {
    __try {
        *n = s->size < buf.size() ? s->size : buf.size();
        memcpy(buf.data(), StrData(s), *n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static void __fastcall hk_tbSetText(void* textbox, MsvcString* text) {
    // The callee frees `text`, so look at it before calling the original.
    if (!g_inMirrorSet && text) {
        std::lock_guard<std::recursive_mutex> lk(g_ebLock);
        char name[128];
        if (!g_mirrors.empty() && RawGuiName(textbox, name, sizeof name)) {
            for (auto& m : g_mirrors) {
                if (m.page != name) continue;
                std::vector<char> buf(8192); size_t n = 0;
                if (RawCopyText(text, buf, &n)) m.original.assign(buf.data(), n);
                m.pagePtr = textbox;
                m.dirty = true;                                       // (re)applied next frame
            }
        }
    }
    o_tbSetText(textbox, text);
}

// Runs every frame on the game's thread: copy changed text box text onto its page.
static void MirrorTick() {
    std::lock_guard<std::recursive_mutex> lk(g_ebLock);
    for (auto& m : g_mirrors) {
        if (!m.pagePtr) continue;
        TrackedBox* t = FindBox(m.box);
        if (!t || !t->box) continue;                  // nothing typed in this box yet: the page keeps its text
        std::string live;
        if (!ReadBoxUtf8(t->box, live)) { t->box = nullptr; continue; }
        if (!m.dirty && live == m.shown) continue;
        std::string disp = live.empty() ? m.original : Utf8ToGameText(live);   // original is game text already
        g_inMirrorSet = true;
        bool ok = RawPageSetText(m.pagePtr, disp.data(), disp.size());
        g_inMirrorSet = false;
        if (!ok) { Log("mirror: page \"%s\" could not be set; waiting for it again", m.page.c_str()); m.pagePtr = nullptr; continue; }
        m.shown = std::move(live);
        m.dirty = false;
    }
}

static bool ScanTextBox() {
    uint8_t* set = FindPattern(g_textStart, g_textEnd,
        "48 89 5C 24 08 48 89 74 24 18 48 89 54 24 10 57 48 83 EC 20 48 8B F2 48 8B F9 48 81 C1 10 01 00 00 E8 ?? ?? ?? ?? 48 8D 97 10 01 00 00");
    uint8_t* cpy = FindPattern(g_textStart, g_textEnd,
        "48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 18 41 56 48 83 EC 20 33 C0 0F 57 C0 0F 11 01 48 89 41 10 4C 8B F2 48 89 41 18 48 8B D9 48 83 7A 18 0F");
    if (!set || !cpy) { Log("textbox scan: pattern missing (%p %p); bridge.editbox.mirror disabled", set, cpy); return false; }
    g_tbSetText = (TbSetTextFn)set;
    g_strCopy = (StrCopyFn)cpy;
    Log("textbox scan: settext=hoi4+%#llx strcopy=hoi4+%#llx", (unsigned long long)(set - g_base),
        (unsigned long long)(cpy - g_base));
    return true;
}

// Replies are one line: backslash and line breaks are escaped (\\ \n).
static std::string EscapeLine(const std::string& s) {
    std::string o; o.reserve(s.size() + 8);
    for (char c : s) { if (c == '\\') o += "\\\\"; else if (c == '\n') o += "\\n"; else if (c != '\r') o += c; }
    return o;
}
// Replies are UTF-8, but the game mixes encodings inside its own text: localisation is Windows-1252, while
// character names (from save data) are UTF-8, and one formatted line can hold both. Valid UTF-8 sequences are
// kept; any other byte is read as Windows-1252.
static size_t Utf8SeqLen(const unsigned char* p, size_t left) {
    unsigned char c = p[0];
    size_t n = c >= 0xC2 && c <= 0xDF ? 2 : c >= 0xE0 && c <= 0xEF ? 3 : c >= 0xF0 && c <= 0xF4 ? 4 : 0;
    if (!n || n > left) return 0;
    for (size_t i = 1; i < n; i++) if ((p[i] & 0xC0) != 0x80) return 0;
    return n;
}
static std::string Cp1252ToUtf8(const char* s, size_t n) {
    std::string out; out.reserve(n + n / 8);
    auto* p = (const unsigned char*)s;
    for (size_t i = 0; i < n;) {
        if (p[i] < 0x80) { out += (char)p[i++]; continue; }
        size_t len = Utf8SeqLen(p + i, n - i);
        if (len) { out.append(s + i, len); i += len; continue; }
        wchar_t w = 0;
        MultiByteToWideChar(1252, 0, s + i, 1, &w, 1);
        AppendUtf8(out, w ? (uint32_t)w : 0xFFFD);
        i++;
    }
    return out;
}
static std::string UnescapeLine(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '\\' && i + 1 < s.size()) { char n = s[++i]; o += n == 'n' ? '\n' : n; }
        else o += s[i];
    }
    return o;
}

static std::string EditBoxCommand(const std::string& sub, const std::string& args) {
    if (!g_ebReady) return "ERROR editbox support not active (see console_bridge.log)";
    if (sub == "list") {
        std::lock_guard<std::recursive_mutex> lk(g_ebLock);
        std::string o = "OK";
        for (auto& e : g_boxes) o += " " + e.first + (e.second.box ? "(open)" : "(closed)");
        return o;
    }
    std::string name = args, value;
    size_t sp = args.find_first_of(" \t");
    if (sp != std::string::npos) {
        name = args.substr(0, sp);
        size_t v = args.find_first_not_of(" \t", sp);
        if (v != std::string::npos) value = args.substr(v);
    }
    if (name.empty()) return "FAIL usage: bridge.editbox NAME | bridge.editbox.set NAME [text] | bridge.editbox.list";
    std::lock_guard<std::recursive_mutex> lk(g_ebLock);
    TrackedBox* t = FindBox(name);
    if (sub == "get") {
        if (!t) return "OK ";                                        // never typed into: empty
        if (t->box) { std::string live; if (ReadBoxUtf8(t->box, live)) t->text = std::move(live); else t->box = nullptr; }
        return "OK " + EscapeLine(t->text);
    }
    if (sub == "multiline") {
        bool on = value != "0" && value != "off" && value != "no";
        auto it = std::find(g_multilineNames.begin(), g_multilineNames.end(), name);
        if (on && it == g_multilineNames.end()) g_multilineNames.push_back(name);
        if (!on && it != g_multilineNames.end()) g_multilineNames.erase(it);
        if (t && t->box && !RawBoxSetMultiline(t->box, on)) t->box = nullptr;
        return std::string("OK ") + name + (on ? " is multi-line" : " is single-line") +
               (t && t->box ? " (applied to the open box)" : " (applied when it is next typed into)");
    }
    if (sub == "mirror") {
        if (!g_tbReady) return "ERROR text box mirroring not active (see console_bridge.log)";
        auto it = std::find_if(g_mirrors.begin(), g_mirrors.end(), [&](const Mirror& m) { return m.box == name; });
        if (value.empty() || value == "off") {
            if (it != g_mirrors.end()) g_mirrors.erase(it);
            return "OK mirror removed";
        }
        if (it != g_mirrors.end() && it->page == value) return "OK mirror already set";
        if (it != g_mirrors.end()) g_mirrors.erase(it);
        Mirror m; m.box = name; m.page = value;
        g_mirrors.push_back(m);
        return "OK " + name + " is shown in " + value + " (from the next time the page's text is set)";
    }
    if (sub == "set") {
        std::string text = UnescapeLine(value);
        if (!t) return "OK not open yet; nothing to change";
        t->text = text;
        if (!t->box) return "OK box is closed; stored text changed";
        if (!RawBoxSetText(t->box, text.c_str())) {
            if ((t = FindBox(name)) != nullptr) t->box = nullptr;   // our Insert hook ran inside; re-find
            return "FAIL box could not be changed";
        }
        return "OK";
    }
    return "FAIL unknown editbox command";
}

static std::string Query(const std::string& effect);   // log capture, below

// ---------------------------------------------------------------- localisation lookup (bridge.loc)
// Localize(std::string* out, const char* key, args, nargs) (clausewitz localize.cpp), as used by the game's own
// UI code. The result string is left to leak (it was allocated by the game's allocator); lookups are small.
using LocalizeFn = MsvcString*(__fastcall*)(MsvcString* out, const char* key, void* args, int nargs);
static LocalizeFn g_localize;

static bool ScanLocalize() {
    uint8_t* p = FindPattern(g_textStart, g_textEnd,
        "48 89 6C 24 18 48 89 74 24 20 57 41 56 41 57 48 83 EC 50 45 33 FF 41 8B E9 44 38 3D ?? ?? ?? ?? 4D 8B F0 48 8B F2 48 8B F9 74 ??");
    if (!p) { Log("localize scan: pattern missing; bridge.loc disabled"); return false; }
    g_localize = (LocalizeFn)p;
    Log("localize scan: localize=hoi4+%#llx", (unsigned long long)(p - g_base));
    return true;
}
// Copies the localised text into out (up to cap-1 bytes). Returns false on a crash inside the game.
static bool RawLocalize(const char* key, char* out, size_t cap) {
    __try {
        MsvcString s = {};
        g_localize(&s, key, nullptr, 0);
        size_t n = s.size < cap - 1 ? s.size : cap - 1;
        memcpy(out, StrData(&s), n); out[n] = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
// bridge.loc KEY [KEY ...] -> values separated by \x1e, each escaped like other one-line replies.
static std::string LocLookup(const std::string& args) {
    if (!g_localize) return "ERROR localisation lookup not active (see console_bridge.log)";
    std::vector<char> buf(64 * 1024);
    std::string out = "OK ";
    size_t pos = 0; bool first = true;
    while (pos < args.size()) {
        size_t s = args.find_first_not_of(" \t", pos);
        if (s == std::string::npos) break;
        size_t e = args.find_first_of(" \t", s);
        if (e == std::string::npos) e = args.size();
        std::string key = args.substr(s, e - s);
        pos = e;
        if (!first) out += '\x1e';
        first = false;
        if (!RawLocalize(key.c_str(), buf.data(), buf.size())) return "ERROR crash looking up " + key;
        out += EscapeLine(Cp1252ToUtf8(buf.data(), strlen(buf.data())));
    }
    return first ? "FAIL usage: bridge.loc KEY [KEY ...]" : out;
}

static std::string HandleBridgeCommand(const std::string& cmd) {
    if (cmd.rfind("bridge.query ", 0) == 0) return Query(cmd.substr(13));
    if (cmd.rfind("bridge.loc ", 0) == 0) return LocLookup(cmd.substr(11));
    if (cmd == "bridge.editbox.list") return EditBoxCommand("list", "");
    if (cmd.rfind("bridge.editbox.multiline ", 0) == 0) return EditBoxCommand("multiline", cmd.substr(25));
    if (cmd.rfind("bridge.editbox.mirror ", 0) == 0) return EditBoxCommand("mirror", cmd.substr(22));
    if (cmd.rfind("bridge.editbox.set ", 0) == 0) return EditBoxCommand("set", cmd.substr(19));
    if (cmd.rfind("bridge.editbox ", 0) == 0) {
        std::string n = cmd.substr(15);
        while (!n.empty() && (n.back() == ' ' || n.back() == '\t')) n.pop_back();
        return EditBoxCommand("get", n);
    }
    if (cmd == "bridge.player") {
        if (!g_dataReady) return "ERROR country data support not active";
        const char* t = RawPlayerTag();
        return t ? std::string("OK ") + t : "FAIL no player country (not in a game?)";
    }
    if (cmd.rfind("bridge.country ", 0) == 0) {
        std::string tag = cmd.substr(15);
        while (!tag.empty() && (tag.back() == ' ' || tag.back() == '\t')) tag.pop_back();
        return DumpCountry(tag);
    }
    if (cmd.rfind("bridge.surrender ", 0) == 0) {
        std::string tag = cmd.substr(17);
        while (!tag.empty() && (tag.back() == ' ' || tag.back() == '\t')) tag.pop_back();
        return Surrender(tag);
    }
    auto rest = [&](size_t n) { std::string r = cmd.substr(n < cmd.size() ? n : cmd.size()); size_t s = r.find_first_not_of(" \t"); return s == std::string::npos ? std::string() : r.substr(s); };
    if (cmd == "bridge.locinfo") {
        if (!g_locReady) return "ERROR localisation support not active";
        PoolState p = {};
        const char* lang = SafeGetLang();
        if (!ReadPool(&p)) return "FAIL localisation database not available";
        char out[200];
        snprintf(out, sizeof out, "OK language=%s text buffer %d/%d bytes (%d free)", lang ? lang : "?", p.used, p.cap, p.cap - p.used);
        return out;
    }
    if (cmd.rfind("bridge.setloc ", 0) == 0) {
        std::string r = rest(14);
        size_t sp = r.find_first_of(" \t");
        if (r.empty() || sp == std::string::npos) return "FAIL usage: bridge.setloc KEY text";
        std::string key = r.substr(0, sp), val = r.substr(r.find_first_not_of(" \t", sp));
        return ApplyLoc({ {key, val} }, "console_bridge/setloc");
    }
    if (cmd.rfind("bridge.reloadloc ", 0) == 0) {
        std::string path = rest(17);
        if (path.size() >= 2 && path.front() == '"' && path.back() == '"') path = path.substr(1, path.size() - 2);
        std::vector<std::pair<std::string, std::string>> kv; std::string err;
        if (!ParseLocFile(path, kv, err)) return "FAIL " + err;
        return ApplyLoc(kv, path.c_str());
    }
    return "FAIL unknown bridge command (bridge.locinfo, bridge.setloc KEY text, bridge.reloadloc <file>, "
           "bridge.editbox NAME, bridge.editbox.set NAME [text], bridge.editbox.list)";
}

// ---------------------------------------------------------------- running one command
// Mirrors what the `run` console command does for each line of its file. Kept free of C++ objects so the
// whole call can sit inside one SEH block: a crash inside the game's code becomes an error reply instead.
static int RawExecute(const char* text, size_t len, char* msg, size_t msgCap) {
    // returns 1 = ok, 0 = command reported failure, -1 = crashed
    MsvcString line = {};
    char* heap = nullptr;
    if (len < 16) { memcpy(line.buf, text, len); line.buf[len] = 0; line.cap = 15; }
    else { heap = (char*)malloc(len + 1); memcpy(heap, text, len); heap[len] = 0; line.ptr = heap; line.cap = len; }
    line.size = len;

    // Words and result are left to leak (a few hundred bytes per command): they were allocated by the
    // game's allocator and freeing them from here would need more of its internals.
    PdxArray* words = (PdxArray*)calloc(1, 64);
    uint8_t* result = (uint8_t*)calloc(1, 128);
    int rc = -1;
    msg[0] = 0;
    __try {
        if (!*g_slot) g_getInst();
        g_split(&line, words, ' ');
        g_dispatch(*g_slot, result, words);
        auto m = (MsvcString*)(result + 8);
        if (m->size && m->size < 100000) strncpy_s(msg, msgCap, StrData(m), _TRUNCATE);
        rc = result[0] ? 1 : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        snprintf(msg, msgCap, "exception %#lx inside the game's console code", GetExceptionCode());
        rc = -1;
    }
    free(heap);
    return rc;
}

// ---------------------------------------------------------------- job queue
struct Job {
    std::string cmd;
    std::string reply;
    HANDLE done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ~Job() { CloseHandle(done); }
};
static std::mutex g_qLock;
static std::deque<std::shared_ptr<Job>> g_queue;

static volatile DWORD g_frameThread = 0;
static volatile bool  g_ready = false;   // patterns found and hooks on

// ---------------------------------------------------------------- log capture (bridge.query)
// Script's `log = "..."` effect (effectbase.cpp) builds a CLogStream; its destructor hands the finished line to
// the global logger: logger->vtable[1](logger, flags, const std::string* file, int line, const std::string* text).
// We hook that sink. While bridge.query runs an effect on the frame thread, every line logged is also captured
// and returned to the client, so script can answer questions (names, leaders, loops over countries or states)
// directly, formatted by the game's own localisation. Lines still reach game.log as usual.
using LogSinkFn   = void(__fastcall*)(void* logger, unsigned flags, const MsvcString* file, int line, const MsvcString* text);
using GetLoggerFn = void*(__fastcall*)();
static GetLoggerFn g_getLogger;
static void**      g_loggerSlot;
static LogSinkFn   o_logSink;
static bool        g_logScanned = false, g_logHooked = false;
static bool        g_capturing = false;              // only touched on the frame thread
static std::vector<std::string> g_captured;

static bool ScanLog() {
    uint8_t* p = FindPattern(g_textStart, g_textEnd,
        "48 89 5C 24 10 57 48 83 EC 20 33 FF 48 8B 05 ?? ?? ?? ?? 48 85 C0 0F 85 ?? ?? ?? ?? B9 48 00 00 00 E8 ?? ?? ?? ?? 48 8B D8 48 89 44 24 30");
    if (!p) { Log("log scan: GetLogger pattern missing; bridge.query disabled"); return false; }
    g_getLogger  = (GetLoggerFn)p;
    g_loggerSlot = (void**)Rel32(p + 0xc, 3, 7);
    Log("log scan: getLogger=hoi4+%#llx slot=hoi4+%#llx", (unsigned long long)(p - g_base),
        (unsigned long long)((uint8_t*)g_loggerSlot - g_base));
    return true;
}

static void __fastcall hk_logSink(void* logger, unsigned flags, const MsvcString* file, int line, const MsvcString* text) {
    if (g_capturing && text && GetCurrentThreadId() == g_frameThread) {
        size_t n = text->size;
        const char* d = StrData(text);
        while (n && (d[n - 1] == '\n' || d[n - 1] == '\r')) n--;   // the log stream ends each line with \n
        g_captured.push_back(Cp1252ToUtf8(d, n));
    }
    o_logSink(logger, flags, file, line, text);
}

// Hooked lazily on the frame thread: the game creates the logger on first use.
static void* RawLoggerSinkAddr() {
    __try {
        void* logger = *g_loggerSlot ? *g_loggerSlot : g_getLogger();
        if (!logger) return nullptr;
        void* fn = (*(void***)logger)[1];
        return InGameCode(fn) ? fn : nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
static bool EnsureLogHook() {
    if (g_logHooked) return true;
    if (!g_logScanned) return false;
    void* sink = RawLoggerSinkAddr();
    if (!sink) { Log("log hook: logger not available"); return false; }
    if (MH_CreateHook(sink, &hk_logSink, (void**)&o_logSink) != MH_OK || MH_EnableHook(sink) != MH_OK) {
        Log("log hook FAILED"); g_logScanned = false; return false;
    }
    g_logHooked = true;
    Log("log hook on: sink=hoi4+%#llx", (unsigned long long)((uint8_t*)sink - g_base));
    return true;
}

// Runs `eval_effect <effect>` and returns the lines it logged, separated by \x1e (record separator).
// Line breaks inside a line are escaped (\n, \\), so the reply stays one line.
static std::string Query(const std::string& effect) {
    if (!EnsureLogHook()) return "ERROR log capture not active (see console_bridge.log)";
    std::string cmd = "eval_effect " + effect;
    char msg[2048];
    g_captured.clear();
    g_capturing = true;
    int rc = RawExecute(cmd.data(), cmd.size(), msg, sizeof msg);
    g_capturing = false;
    std::vector<std::string> lines;
    lines.swap(g_captured);
    if (rc < 0) return std::string("ERROR ") + msg;
    if (rc == 0) {
        for (char* q = msg; *q; q++) if (*q == '\r' || *q == '\n') *q = ' ';
        return std::string("FAIL ") + msg;
    }
    std::string out = "OK ";
    for (size_t i = 0; i < lines.size(); i++) {
        if (i) out += '\x1e';
        out += EscapeLine(lines[i]);
    }
    return out;
}

static void RunQueued() {
    for (int i = 0; i < kMaxPerFrame; i++) {
        std::shared_ptr<Job> job;
        {
            std::lock_guard<std::mutex> lk(g_qLock);
            if (g_queue.empty()) return;
            job = g_queue.front(); g_queue.pop_front();
        }
        if (job->cmd.rfind("bridge.", 0) == 0) {
            job->reply = HandleBridgeCommand(job->cmd);
        } else {
            char msg[2048];
            int rc = RawExecute(job->cmd.data(), job->cmd.size(), msg, sizeof msg);
            for (char* p = msg; *p; p++) if (*p == '\r' || *p == '\n') *p = ' ';
            job->reply = (rc > 0 ? "OK " : rc == 0 ? "FAIL " : "ERROR ") + std::string(msg);
        }
        Log("ran \"%s\" -> %.300s", job->cmd.c_str(), job->reply.c_str());
        SetEvent(job->done);
    }
}

// ---------------------------------------------------------------- hooks
static DispatchFn o_dispatch;
static void* __fastcall hk_dispatch(void* mgr, void* out, PdxArray* words) {
    // Only watches the player's own console use, to catch a future patch moving it off the frame thread.
    DWORD tid = GetCurrentThreadId();
    if (g_frameThread && tid != g_frameThread)
        Log("WARNING: a console command ran on thread %lu, not the frame thread %lu", tid, g_frameThread);
    return o_dispatch(mgr, out, words);
}

using PresentFn = HRESULT(__stdcall*)(IDXGISwapChain*, UINT, UINT);
static PresentFn o_present;
static HRESULT __stdcall hk_present(IDXGISwapChain* sc, UINT sync, UINT flags) {
    DWORD tid = GetCurrentThreadId();
    if (g_frameThread != tid) {
        Log("Present now on thread %lu (was %lu)", tid, g_frameThread);
        g_frameThread = tid;
    }
    if (g_ready) {
        if (g_tbReady) MirrorTick();
        RunQueued();
    }
    return o_present(sc, sync, flags);
}

static void* PresentAddress() {
    WNDCLASSEXW wc = { sizeof wc, CS_CLASSDC, DefWindowProcW, 0, 0, GetModuleHandleW(nullptr),
                       nullptr, nullptr, nullptr, nullptr, L"hoi4bridge_dummy", nullptr };
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowW(wc.lpszClassName, L"", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, nullptr, nullptr,
                              wc.hInstance, nullptr);
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 1; sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT; sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1; sd.Windowed = TRUE; sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    IDXGISwapChain* sc = nullptr; ID3D11Device* dev = nullptr; ID3D11DeviceContext* ctx = nullptr;
    void* fn = nullptr;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, nullptr, 0,
                                               D3D11_SDK_VERSION, &sd, &sc, &dev, nullptr, &ctx);
    if (FAILED(hr))
        hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, nullptr, 0,
                                           D3D11_SDK_VERSION, &sd, &sc, &dev, nullptr, &ctx);
    if (SUCCEEDED(hr)) fn = (*(void***)sc)[8];
    else Log("dummy D3D11 device failed: %#lx", hr);
    if (sc) sc->Release(); if (ctx) ctx->Release(); if (dev) dev->Release();
    DestroyWindow(hwnd); UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return fn;
}

// ---------------------------------------------------------------- pipe server
static std::string HandleRequest(const std::string& req) {
    if (!g_ready) return "ERROR bridge not active (see console_bridge.log)\n";
    std::deque<std::shared_ptr<Job>> jobs;   // one job per non-empty line
    size_t pos = 0;
    while (pos < req.size()) {
        size_t nl = req.find('\n', pos);
        if (nl == std::string::npos) nl = req.size();
        std::string l = req.substr(pos, nl - pos);
        pos = nl + 1;
        while (!l.empty() && (l.back() == '\r' || l.back() == ' ' || l.back() == '\t')) l.pop_back();
        size_t s = l.find_first_not_of(" \t");
        if (s == std::string::npos) continue;
        auto j = std::make_shared<Job>(); j->cmd = l.substr(s);
        jobs.push_back(j);
    }
    if (jobs.empty()) return "ERROR empty request\n";
    {
        std::lock_guard<std::mutex> lk(g_qLock);
        for (auto& j : jobs) g_queue.push_back(j);
    }
    std::string out;
    DWORD deadline = GetTickCount() + kReplyTimeoutMs;
    for (auto& j : jobs) {
        DWORD now = GetTickCount();
        DWORD wait = (now < deadline) ? deadline - now : 0;
        if (WaitForSingleObject(j->done, wait) == WAIT_OBJECT_0) out += j->reply + "\n";
        else out += "ERROR timeout: no frame rendered (game minimised or frozen?); command still queued\n";
    }
    return out;
}

static DWORD WINAPI ClientThread(void* p) {
    HANDLE pipe = (HANDLE)p;
    std::string req; char buf[4096]; DWORD got = 0;
    for (;;) {
        BOOL ok = ReadFile(pipe, buf, sizeof buf, &got, nullptr);
        if (got) req.append(buf, got);
        if (ok) break;
        if (GetLastError() != ERROR_MORE_DATA) { req.clear(); break; }
    }
    if (!req.empty()) {
        std::string reply = HandleRequest(req);
        DWORD wrote = 0;
        WriteFile(pipe, reply.data(), (DWORD)reply.size(), &wrote, nullptr);
        FlushFileBuffers(pipe);
    }
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    return 0;
}

static DWORD WINAPI PipeThread(void*) {
    // Default pipe security: only this user, SYSTEM and admins may connect. Remote clients are rejected.
    // Each client gets its own thread, and a fresh pipe instance is waiting as soon as one connects,
    // so back-to-back clients never find the pipe missing.
    for (;;) {
        HANDLE pipe = CreateNamedPipeA(kPipeName, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES, 64 * 1024, 64 * 1024, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) { Log("CreateNamedPipe failed: %lu", GetLastError()); Sleep(2000); continue; }
        if (ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
            if (HANDLE h = CreateThread(nullptr, 0, ClientThread, pipe, 0, nullptr)) { CloseHandle(h); continue; }
        }
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
}

// ---------------------------------------------------------------- startup
static DWORD WINAPI InitThread(void*) {
    Log("---- bridge loaded into pid %lu ----", GetCurrentProcessId());
    if (MH_Initialize() != MH_OK) { Log("MinHook init failed"); return 0; }

    bool scanned = ScanGame();
    if (scanned) {
        if (MH_CreateHook(g_dispatch, &hk_dispatch, (void**)&o_dispatch) == MH_OK && MH_EnableHook(g_dispatch) == MH_OK)
            g_dispatch = o_dispatch;  // our own calls skip the watcher
        else Log("console watch hook failed (not needed to run commands)");
        g_locReady = ScanLoc();
        g_dataReady = ScanData();
        g_surrReady = ScanSurrender();
        g_logScanned = ScanLog();
        ScanLocalize();
        if (ScanEditBox()) {
            g_ebReady = MH_CreateHook((void*)g_ebInsert, &hk_ebInsert, (void**)&o_ebInsert) == MH_OK &&
                        MH_CreateHook((void*)g_ebDtor, &hk_ebDtor, (void**)&o_ebDtor) == MH_OK &&
                        MH_EnableHook((void*)g_ebInsert) == MH_OK && MH_EnableHook((void*)g_ebDtor) == MH_OK;
            Log(g_ebReady ? "editbox hooks on" : "editbox hooks FAILED");
        }
        if (g_ebReady && ScanTextBox()) {
            g_tbReady = MH_CreateHook((void*)g_tbSetText, &hk_tbSetText, (void**)&o_tbSetText) == MH_OK &&
                        MH_EnableHook((void*)g_tbSetText) == MH_OK;
            Log(g_tbReady ? "textbox hook on" : "textbox hook FAILED");
        }
    } else {
        Log("patterns not found: this game version needs new patterns. Bridge disabled.");
    }

    void* present = PresentAddress();
    bool hooked = present && MH_CreateHook(present, &hk_present, (void**)&o_present) == MH_OK &&
                  MH_EnableHook(present) == MH_OK;
    Log(hooked ? "Present hook on" : "Present hook FAILED");

    g_ready = scanned && hooked;
    if (HANDLE h = CreateThread(nullptr, 0, PipeThread, nullptr, 0, nullptr)) CloseHandle(h);
    Log(g_ready ? "ready: listening on %s" : "NOT ready (pipe answers with an error): %s", kPipeName);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, void*) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(self);
        InitializeCriticalSection(&g_logLock);
        GetModuleFileNameA(self, g_logPath, MAX_PATH);
        char* slash = strrchr(g_logPath, '\\');
        if (slash) strcpy_s(slash + 1, g_logPath + MAX_PATH - (slash + 1), "console_bridge.log");
        if (HANDLE h = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr)) CloseHandle(h);
    }
    return TRUE;
}
