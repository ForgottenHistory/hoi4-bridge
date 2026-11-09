// HOI4 console bridge: run console commands from outside the game, without keyboard input.
// Loaded as version.dll from the HOI4 folder. Writes console_bridge.log next to itself.
//
// Clients connect to the named pipe \\.\pipe\hoi4_console_bridge, send one message holding one or more
// command lines, and get one reply line per command: "OK <message>", "FAIL <message>" or "ERROR <reason>".
// Commands are queued and run at the next frame on the game's render/main thread (the same thread the
// in-game console uses), through the game's own console dispatcher.

#include <windows.h>
#include <tlhelp32.h>
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
#include <map>
#include <set>
#include <intrin.h>
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

// ---------------------------------------------------------------- a relation of our own in the diplomacy view
// The diplomacy view's relations list (left column: faction, guarantees, pacts ...) is an array of strip objects
// the view creates once (CreateStrips, at view+0x1628), one per relation type and direction. On each update the view
// gives every strip the shown country (strip+0x38, a tag id), asks it for every country whether the relation holds
// (vtable slot 21) and adds the flag of each one that does; strips with flags go into the grid.
// We append one more strip: a standard one with its own icon (GFX_relation_airp_treaty, which the mod defines) and a
// copy of its vtable whose "holds" and tooltip methods use the country pairs set with bridge.treaties. A flag's
// tooltip is the localisation key airp_rel_<A>_<B> (tags in alphabetical order), the icon's AIRP_TREATY_RELATION.
using CreateStripsFn = void(__fastcall*)(uint8_t* view);
using GameNewFn      = void*(__fastcall*)(size_t size);
using StripCtorFn    = void*(__fastcall*)(void* mem, void* factory, int type, int dir);
using PushPtrFn      = void(__fastcall*)(void* array, void** item);
using SetSpriteFn    = void(__fastcall*)(void* icon, MsvcString* name, char flag);
using StrAppendFn    = MsvcString*(__fastcall*)(MsvcString* s, const char* p, size_t n);
static CreateStripsFn g_createStrips, o_createStrips;
static GameNewFn      g_gameNew;
static StripCtorFn    g_stripCtor;
static PushPtrFn      g_pushPtr;
static SetSpriteFn    g_setSprite;
static StrAppendFn    g_strAppend;
static uint8_t**      g_guiGlobal;        // *g_guiGlobal + 0x4f8: the GUI factory the strips are built from
static void*          g_treatyVtbl[24];   // [0] RTTI locator, then the 23 slots
static bool           g_relReady = false;
static const int      kStripType = 0x27f8, kStripDir = 2;   // a type the game uses; only its sprite would show

struct TagPair { char a[8]; char b[8]; };
static SRWLOCK g_pairLock = SRWLOCK_INIT;
static TagPair g_pairs[1024];
static int     g_pairCount = 0;

// Our strip's methods (vtable slots 19-21), defined below.
static bool __fastcall TreatyFlagTip(uint8_t* strip, int* other, MsvcString* out);
static bool __fastcall TreatyStripTip(uint8_t* strip, MsvcString* out);
static bool __fastcall TreatyHolds(uint8_t* strip, int* other);

static bool ScanRelations() {
    uint8_t* cs = FindPattern(g_textStart, g_textEnd,
        "48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 55 48 8B EC 48 83 EC 20 48 8B 05 ?? ?? ?? ?? "
        "48 8B B0 F8 04 00 00 48 8D B9 28 16 00 00 B9 70 00 00 00 E8");
    uint8_t* std_ = cs ? FindPattern(cs, cs + 0x1000, "41 B9 02 00 00 00 41 B8 F8 27 00 00 48 8B D6 48 8B C8 E8") : nullptr;
    uint8_t* spr = FindPattern(g_textStart, g_textEnd, "45 33 C0 48 8D 55 ?? 49 8B 4E 20 E8");
    uint8_t* app = FindPattern(g_textStart, g_textEnd,
        "48 89 74 24 18 57 48 83 EC 30 48 8B F9 49 8B F0 48 8B 49 10 4C 8B 47 18 49 8B C0 48 2B C1 48 3B F0 77");
    if (!cs || !std_ || !spr || !app || !g_localize || !g_dataReady) {
        Log("relations scan: missing (%p %p %p %p, localize %p, data %d); diplomacy-view treaty row disabled",
            cs, std_, spr, app, g_localize, (int)g_dataReady);
        return false;
    }
    g_createStrips = (CreateStripsFn)cs;
    g_guiGlobal    = (uint8_t**)Rel32(cs + 23, 3, 7);
    g_gameNew      = (GameNewFn)Rel32(cs + 49, 1, 5);
    g_pushPtr      = (PushPtrFn)Rel32(cs + 0x5c, 1, 5);
    g_stripCtor    = (StripCtorFn)Rel32(std_ + 18, 1, 5);
    g_setSprite    = (SetSpriteFn)Rel32(spr + 11, 1, 5);
    g_strAppend    = (StrAppendFn)app;
    // The standard strip's ctor sets its vtable: lea rax, [vtable]; mov [rbx], rax
    uint8_t* ctor = (uint8_t*)g_stripCtor;
    if (cs[0x5c] != 0xE8 || ctor[26] != 0x48 || ctor[27] != 0x8D || ctor[28] != 0x05) {
        Log("relations scan: unexpected code around the strip ctor; treaty row disabled");
        return false;
    }
    void** orig = (void**)Rel32(ctor + 26, 3, 7);
    for (int i = 19; i <= 21; i++)
        if (!InGameCode(orig[i])) { Log("relations scan: vtable slot %d not game code; treaty row disabled", i); return false; }
    g_treatyVtbl[0] = orig[-1];
    for (int i = 0; i < 23; i++) g_treatyVtbl[i + 1] = orig[i];
    g_treatyVtbl[1 + 19] = (void*)&TreatyFlagTip;
    g_treatyVtbl[1 + 20] = (void*)&TreatyStripTip;
    g_treatyVtbl[1 + 21] = (void*)&TreatyHolds;
    Log("relations scan: createStrips=hoi4+%#llx stripCtor=hoi4+%#llx vtable=hoi4+%#llx setSprite=hoi4+%#llx append=hoi4+%#llx",
        (unsigned long long)(cs - g_base), (unsigned long long)(ctor - g_base),
        (unsigned long long)((uint8_t*)orig - g_base), (unsigned long long)((uint8_t*)g_setSprite - g_base),
        (unsigned long long)(app - g_base));
    return true;
}

static bool TagOfId(int id, char out[8]) {
    __try {
        if (id < 1) return false;
        MsvcString* s = g_tagName(&id);
        if (!s || s->size == 0 || s->size > 7) return false;
        memcpy(out, StrData(s), s->size); out[s->size] = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool HasPair(const char* a, const char* b) {
    AcquireSRWLockShared(&g_pairLock);
    bool found = false;
    for (int i = 0; i < g_pairCount && !found; i++)
        found = (!strcmp(g_pairs[i].a, a) && !strcmp(g_pairs[i].b, b)) || (!strcmp(g_pairs[i].a, b) && !strcmp(g_pairs[i].b, a));
    ReleaseSRWLockShared(&g_pairLock);
    return found;
}

static void AppendLocalized(MsvcString* out, const char* key) {
    __try {
        MsvcString s = {};
        g_localize(&s, key, nullptr, 0);   // left to leak, as in RawLocalize
        g_strAppend(out, StrData(&s), s.size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// vtable slot 21: does the relation hold between the shown country and `other`?
static bool __fastcall TreatyHolds(uint8_t* strip, int* other) {
    char a[8], b[8];
    return TagOfId(*(int*)(strip + 0x38), a) && TagOfId(*other, b) && HasPair(a, b);
}
// slot 19: tooltip of one flag
static bool __fastcall TreatyFlagTip(uint8_t* strip, int* other, MsvcString* out) {
    char a[8], b[8], key[40];
    if (!TagOfId(*(int*)(strip + 0x38), a) || !TagOfId(*other, b)) return false;
    bool ab = strcmp(a, b) < 0;
    snprintf(key, sizeof key, "airp_rel_%s_%s", ab ? a : b, ab ? b : a);
    AppendLocalized(out, key);
    return true;
}
// slot 20: tooltip of the icon
static bool __fastcall TreatyStripTip(uint8_t* strip, MsvcString* out) {
    AppendLocalized(out, "AIRP_TREATY_RELATION");
    return true;
}

static void AddTreatyStrip(uint8_t* view) {
    __try {
        void* factory = *(void**)(*g_guiGlobal + 0x4f8);
        void* mem = g_gameNew(0x70);
        if (!mem) return;
        uint8_t* strip = (uint8_t*)g_stripCtor(mem, factory, kStripType, kStripDir);
        *(void***)strip = &g_treatyVtbl[1];
        static char sprite[] = "GFX_relation_airp_treaty";
        MsvcString name = {}; name.ptr = sprite; name.size = sizeof sprite - 1; name.cap = name.size;
        g_setSprite(*(void**)(strip + 0x20), &name, 0);
        void* item = strip;
        g_pushPtr(view + 0x1628, &item);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("treaty row: exception %#lx adding the strip", GetExceptionCode());
    }
}

static void __fastcall hk_createStrips(uint8_t* view) {
    o_createStrips(view);
    AddTreatyStrip(view);
}

// bridge.treaties [A:B ...]: the country pairs the treaty row shows (replaces the earlier set; none clears it).
static std::string SetTreatyPairs(const std::string& args) {
    if (!g_relReady) return "ERROR treaty row not active (see console_bridge.log)";
    std::vector<TagPair> pairs;
    size_t pos = 0;
    while (pos < args.size()) {
        size_t s = args.find_first_not_of(" \t", pos);
        if (s == std::string::npos) break;
        size_t e = args.find_first_of(" \t", s);
        if (e == std::string::npos) e = args.size();
        std::string tok = args.substr(s, e - s);
        pos = e;
        size_t c = tok.find(':');
        if (c == std::string::npos || c == 0 || c > 7 || tok.size() - c - 1 == 0 || tok.size() - c - 1 > 7)
            return "FAIL bad pair " + tok + " (usage: bridge.treaties A:B [C:D ...])";
        TagPair p = {};
        memcpy(p.a, tok.data(), c);
        memcpy(p.b, tok.data() + c + 1, tok.size() - c - 1);
        pairs.push_back(p);
        if (pairs.size() > _countof(g_pairs)) return "FAIL too many pairs";
    }
    AcquireSRWLockExclusive(&g_pairLock);
    for (size_t i = 0; i < pairs.size(); i++) g_pairs[i] = pairs[i];
    g_pairCount = (int)pairs.size();
    ReleaseSRWLockExclusive(&g_pairLock);
    return "OK " + std::to_string(pairs.size()) + " pairs";
}

// ---------------------------------------------------------------- war declarations
// Every diplomatic action is carried out by ExecuteAction(action), whoever starts it. An action a country sends (the
// AI, the player's buttons) arrives as a CDiplomaticActionCommand and is run by ExecuteCommand(cmd, depth): depth 0
// for the action sent, deeper for what follows from it in the same go (allies and guarantors declaring war in turn).
// Script (declare_war_on in focuses and events), civil wars and countries joining a faction at war call
// ExecuteAction directly, outside any command. A CDeclareWarAction holds the declarer's country id at +0x14 and the
// target's at +0x1c.
//
// bridge.wars on: a declaration sent as a command (depth 0) by a country other than the player is dropped, unless
// that pair was allowed (bridge.wars allow A:B ...). Script wars, follow-up declarations and the player's own are
// untouched. Each dropped attempt is counted (bridge.wars attempts: who wanted war with whom, then cleared).
using ExecCmdFn = void(__fastcall*)(void* cmd, int depth);
using ExecActFn = void(__fastcall*)(uint8_t* action);
static ExecCmdFn g_execCmd, o_execCmd;
static ExecActFn g_execAct, o_execAct;
static void*     g_declareWarVt;
static bool      g_warReady = false;
static volatile bool g_warsOn = false;
static thread_local int t_cmdDepth = -1;              // depth of the command running on this thread, -1 if none
static SRWLOCK g_warLock = SRWLOCK_INIT;
static std::set<std::string> g_warAllowed;             // "A:B": A may declare war on B
static std::map<std::string, int> g_warAttempts;       // "A:B" -> dropped declarations since last asked

static bool ScanWar() {
    uint8_t* cmd = FindPattern(g_textStart, g_textEnd,
        "48 89 5C 24 08 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 D9 48 81 EC 90 00 00 00 44 8B E2 45 33 FF "
        "44 89 7D 6F 83 FA 0C 7C");
    uint8_t* act = FindPattern(g_textStart, g_textEnd,
        "40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 88 FE FF FF 48 81 EC 78 02 00 00 0F 29 B4 24 60 02 00 00 "
        "48 8B F1 45 33 E4 BA E8 20 00 00");
    // CDeclareWarAction's constructor: base constructor, then this->vtable = &CDeclareWarAction::vftable
    uint8_t* vt = FindPattern(g_textStart, g_textEnd, "4D 8D 4B D8 E8 ?? ?? ?? ?? 90 48 8D 05 ?? ?? ?? ?? 48 89 03 48 8D 4B 78");
    if (!cmd || !act || !vt || !g_dataReady) {
        Log("war scan: pattern missing (%p %p %p) or no country data; bridge.wars disabled", cmd, act, vt);
        return false;
    }
    g_execCmd = (ExecCmdFn)cmd;
    g_execAct = (ExecActFn)act;
    g_declareWarVt = Rel32(vt + 10, 3, 7);
    Log("war scan: executeCommand=hoi4+%#llx executeAction=hoi4+%#llx CDeclareWarAction vt=hoi4+%#llx",
        (unsigned long long)(cmd - g_base), (unsigned long long)(act - g_base),
        (unsigned long long)((uint8_t*)g_declareWarVt - g_base));
    return true;
}

// The two countries of a declaration, as tags; false if the action isn't one or can't be read. SEH only.
static bool RawWarPair(uint8_t* action, char a[16], char b[16]) {
    __try {
        if (*(void**)action != g_declareWarVt) return false;
        int ida = *(int*)(action + 0x14), idb = *(int*)(action + 0x1c);
        if (ida < 1 || idb < 1) return false;
        MsvcString* sa = g_tagName(&ida);
        MsvcString* sb = sa ? g_tagName(&idb) : nullptr;
        if (!sa || !sb) return false;
        strncpy_s(a, 16, StrData(sa), _TRUNCATE);
        strncpy_s(b, 16, StrData(sb), _TRUNCATE);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// ---------------------------------------------------------------- commands (research: logging and blocking)
// Every player or AI action is a CCommand subclass; vtable slot 9 checks it, slot 10 (Execute(this)) carries it out.
// All queued commands, the AI's and the player's, are executed by the command queue (hoi4+0x22c6d10 in 1.19.4).
// The first bridge.cmdlog / bridge.cmdblock call finds every class whose RTTI name ends in "Command" and whose
// vtable has CCommand's base slots, and points its slot 10 at hk_cmdExec.
//
// A command holds no sender. It names game objects by handle, {int type, int id} (type 0x35 = an order: front or
// battle plan), which Resolve(&handle) turns into the object; the country follows from that object's owner.
//
// bridge.cmdlog on|off|dump: count executed commands by class. The first of each class from each caller, and the
// next N of a class after `sample CLASS [N]`, go to the log: fields that read as country ids, and each handle the
// command holds with its object's class and country-like fields.
// bridge.cmdblock: drop commands of a class whose owner is a blocked country. A rule says where the owner is:
// `rule CLASS - OFF` (an int country id at +OFF of the command) or `rule CLASS HOFF OFF` (the handle at +HOFF,
// the country id at +OFF of its object).
static const int kExecSlot = 10;
using CmdExecFn = void(__fastcall*)(void* self, void* a, void* b, void* c);
using ResolveFn = void*(__fastcall*)(const int* handle);
static std::map<void*, CmdExecFn> g_cmdOrig;           // vtable -> original Execute; filled before any patch
static std::map<void*, std::string> g_cmdName;         // vtable -> class name
static bool g_cmdPatched = false;
static ResolveFn g_resolve;
static volatile bool g_cmdLogOn = false;
static SRWLOCK g_cmdLogLock = SRWLOCK_INIT;
static std::map<std::string, int> g_cmdCounts;         // class -> count since last dump
static std::set<std::pair<std::string, uintptr_t>> g_cmdSeen;
static std::map<std::string, int> g_cmdSample;         // class -> how many more to log

struct BlockRule { int handleOff; int ownerOff; };     // handleOff -1: owner read from the command itself,
                                                       // -2 (auto): the first handle with a known owner (as cmdrec)
static SRWLOCK g_blockLock = SRWLOCK_INIT;
static std::map<std::string, BlockRule> g_blockRules;  // class -> rule
static std::set<std::string> g_blockTags;
static std::map<std::string, int> g_blockDropped;      // "Class:TAG" -> dropped since last asked
static volatile bool g_blockOn = false;                // any rule and any tag
static thread_local bool t_bridgeIssued = false;       // the command running now was sent by the bridge (bridge.move)

static bool RawBytes(const void* p, uint8_t* out, size_t n) {
    __try { memcpy(out, p, n); return true; } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// The tag of a country id, if it is one (three letters or digits); false otherwise. SEH only.
static bool RawTagOf(int id, char out[8]) {
    if (id < 1 || id > 2000 || !g_tagName) return false;
    __try {
        MsvcString* s = g_tagName(&id);
        if (!s) return false;
        const char* t = StrData(s);
        for (int i = 0; i < 3; i++) if (!(isupper((unsigned char)t[i]) || isdigit((unsigned char)t[i]))) return false;
        if (t[3] != 0) return false;
        memcpy(out, t, 4);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// The RTTI class name of an object with a vtable; false if it can't be read. SEH only.
static bool RawClassName(void* obj, char out[96]) {
    __try {
        uint8_t* col = ((uint8_t**)*(void**)obj)[-1];
        if (*(uint32_t*)col != 1) return false;
        const char* n = (const char*)(g_base + *(uint32_t*)(col + 12) + 0x10);
        if (n[0] != '.' || n[1] != '?' || n[2] != 'A') return false;
        n += 4;
        size_t i = 0;
        while (i < 95 && n[i] && !(n[i] == '@' && n[i + 1] == '@')) { out[i] = n[i]; i++; }
        out[i] = 0;
        return i > 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// The object a {type, id} handle names, or null. Most types are small (51 division, 53 order, 67 theatre); unit
// leaders are 4713. SEH only.
static void* RawResolve(int type, int id) {
    if (!g_resolve || type < 1 || type > 0xffff || id < 1) return nullptr;
    int h[2] = { type, id };
    __try { return g_resolve(h); } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

// " +0x28=ITA +0x30=GER" for the 4-byte fields of p[from, to) that read as country ids.
static std::string TagFields(const uint8_t* p, size_t from, size_t to) {
    std::string out;
    for (size_t o = from; o + 4 <= to; o += 4) {
        char t[8], b[24];
        if (RawTagOf(*(const int*)(p + o), t)) { snprintf(b, sizeof b, " +%#zx=%s", o, t); out += b; }
    }
    return out;
}

// One object, for the log or a reply: "CClass tags: ..." over its first 0x400 bytes.
static std::string DescribeObject(void* obj) {
    char cls[96];
    if (!RawClassName(obj, cls)) strcpy_s(cls, "?");
    std::vector<uint8_t> buf(0x400);
    std::string tags = RawBytes(obj, buf.data(), buf.size()) ? TagFields(buf.data(), 8, buf.size()) : " (unreadable)";
    return std::string(cls) + " tags:" + tags;
}

static void LogCommandSample(const std::string& name, uintptr_t caller, void* self) {
    uint8_t bytes[0x88];
    char hex[0x88 * 3 + 1] = "";
    if (!RawBytes(self, bytes, sizeof bytes)) { Log("cmdlog: %s unreadable", name.c_str()); return; }
    for (size_t i = 0; i < sizeof bytes; i++) snprintf(hex + i * 3, 4, "%02X ", bytes[i]);
    Log("cmdlog: %s from hoi4+%#llx tid %lu tags:%s | %s", name.c_str(), (unsigned long long)caller,
        GetCurrentThreadId(), TagFields(bytes, 0x24, sizeof bytes).c_str(), hex);
    for (size_t o = 0x24; o + 8 <= sizeof bytes; o += 4) {
        int type = *(int*)(bytes + o), id = *(int*)(bytes + o + 4);
        if (type < 1 || type > 99 || id < 1) continue;
        if (void* obj = RawResolve(type, id))
            Log("cmdlog:   handle +%#zx {%d,%d} -> %s", o, type, id, DescribeObject(obj).c_str());
    }
}

// The owner tag of a command under a rule; false if it can't be read. SEH only.
static bool RawOwner(void* self, const BlockRule& r, char tag[8]) {
    __try {
        uint8_t* base = (uint8_t*)self;
        if (r.handleOff >= 0) {
            const int* h = (const int*)(base + r.handleOff);
            base = (uint8_t*)RawResolve(h[0], h[1]);
            if (!base) return false;
        }
        return RawTagOf(*(int*)(base + r.ownerOff), tag);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// ---- bridge.cmdrec: every executed command, one line each, to a file (research: how a player and the AI play)
// Line: seq, ms since recording began, class, owner tag (or -), how the owner was found, header +0xc (1 queued,
// -1 direct), the handles that resolve ("+0x28=53:447"), the first kRecBytes bytes as hex.
// `mark TEXT` writes "#mark ms TEXT" (the recorder script stamps the game date this way).
// Owner: a cmdblock rule for the class if there is one, else the first handle whose type has a known owner offset.
static const size_t kRecBytes = 0xa0;
static SRWLOCK g_recLock = SRWLOCK_INIT;
static FILE* g_recFile = nullptr;
static volatile bool g_recOn = false;
static std::string g_recPath;
static std::set<std::string> g_recSkip;                // classes not recorded
// handle type -> where its object keeps the owner's country id: a chain of offsets, every one but the last followed
// as a pointer; a type may have several, tried in order. A theatre (67) has no owner field: its armies' list is at
// +0x80 (the first army's owner at +0x3c); while it has no army, its divisions' list at +0x68 (full objects, owner
// at +0x1d8).
static int g_recOwnerType[16] = { 51, 53, 67, 67 }, g_recOwnerN = 4;
static int g_recOwnerOff[16][4] = { { 0x1c8 }, { 0x3c }, { 0x80, 0, 0x3c }, { 0x68, 0, 0x1d8 } };
static int g_recOwnerLen[16] = { 1, 1, 3, 3 };
static unsigned long long g_recSeq = 0, g_recStart = 0;

// Per-class rules for data behind pointers (a last column, "-" if none):
//   list:  a vector, data pointer at +off, int count at +b, elements of c bytes -> "L+0x28=[51:3,51:9]"
//          (each element as its 4-byte ints joined by ':'; at most 64 elements)
//   deref: an object pointer at +off, the int at +b of it -> "D+0x40=CProvince.0xa4=6325"
// The column also names the class of every pointer in the command that leads to an object with RTTI ("P+0x40=CX").
struct RecRule { char kind; int off, b, c; };
static std::map<std::string, std::vector<RecRule>> g_recRules = {
    // CMoveCommand embeds a CUnitMoveAction at +0x28: army handle at +0x38, province ids (the path; the last one is
    // the destination) at +0x40 with count +0x4c, a second province list at +0x58 / +0x64
    { "CMoveCommand",          { { 'L', 0x40, 0x4c, 4 }, { 'L', 0x58, 0x64, 4 } } },
    { "COrderAssignCommand",   { { 'L', 0x28, 0x30, 8 } } },
    { "COrderUnassignCommand", { { 'L', 0x28, 0x30, 8 } } },
    { "COrderNewFrontCommand", { { 'L', 0x38, 0x40, 8 }, { 'L', 0x50, 0x5c, 4 } } },   // divisions; provinces?
};

static std::string RecExtra(const uint8_t* bytes, const std::vector<RecRule>* rules) {
    std::string out;
    char b[160], cls[96];
    for (size_t o = 0x20; o + 8 <= kRecBytes; o += 8) {
        uintptr_t p = *(const uintptr_t*)(bytes + o);
        if (p < 0x10000 || p > 0x7fffffffffffull || (p & 7)) continue;
        if (RawClassName((void*)p, cls)) { snprintf(b, sizeof b, " P+%#zx=%s", o, cls); out += b; }
    }
    if (rules) for (auto& r : *rules) {
        uint8_t* p = *(uint8_t* const*)(bytes + r.off);
        if (r.kind == 'D') {
            int v;
            if (!RawClassName(p, cls)) strcpy_s(cls, "?");
            if (RawBytes(p + r.b, (uint8_t*)&v, 4)) { snprintf(b, sizeof b, " D+%#x=%s.%#x=%d", r.off, cls, r.b, v); out += b; }
        } else if (r.kind == 'L') {
            int n = *(const int*)(bytes + r.b);
            if (n < 0 || n > 64 || r.c < 4 || r.c > 64) continue;
            std::vector<uint8_t> v((size_t)n * r.c);
            if (n && !RawBytes(p, v.data(), v.size())) continue;
            snprintf(b, sizeof b, " L+%#x=[", r.off);
            out += b;
            for (int i = 0; i < n; i++) {
                for (int k = 0; k < r.c / 4; k++) {
                    snprintf(b, sizeof b, "%s%d", k ? ":" : (i ? "," : ""), *(int*)(v.data() + (size_t)i * r.c + k * 4));
                    out += b;
                }
            }
            out += "]";
        }
    }
    return out.empty() ? "-" : out.substr(1);
}

// Owner from the first handle in the command whose type has a known owner offset. No SEH needed here.
static bool RecOwnerFromHandles(const uint8_t* bytes, char tag[8], int* via) {
    for (size_t o = 0x24; o + 8 <= kRecBytes; o += 4) {
        int type = *(const int*)(bytes + o), id = *(const int*)(bytes + o + 4);
        if (id < 1) continue;
        uint8_t* obj = nullptr;
        for (int k = 0; k < g_recOwnerN; k++) {
            if (g_recOwnerType[k] != type) continue;
            if (!obj && !(obj = (uint8_t*)RawResolve(type, id))) break;
            uint8_t* p = obj;
            for (int j = 0; p && j + 1 < g_recOwnerLen[k]; j++)
                if (!RawBytes(p + g_recOwnerOff[k][j], (uint8_t*)&p, 8)) p = nullptr;
            int c;
            if (p && RawBytes(p + g_recOwnerOff[k][g_recOwnerLen[k] - 1], (uint8_t*)&c, 4) && RawTagOf(c, tag)) {
                *via = (int)o;
                return true;
            }
        }
    }
    return false;
}

// The owner of a command under a rule, including auto rules.
static bool BlockOwner(void* self, const BlockRule& r, char tag[8]) {
    if (r.handleOff != -2) return RawOwner(self, r, tag);
    uint8_t b[kRecBytes];
    int via;
    return RawBytes(self, b, sizeof b) && RecOwnerFromHandles(b, tag, &via);
}

static void RecordCommand(const std::string& name, void* self) {
    uint8_t bytes[kRecBytes];
    if (!RawBytes(self, bytes, sizeof bytes)) memset(bytes, 0, sizeof bytes);
    AcquireSRWLockShared(&g_recLock);
    bool skip = g_recSkip.count(name) > 0;
    auto rr = g_recRules.find(name);
    std::string extra = skip ? "" : RecExtra(bytes, rr == g_recRules.end() ? nullptr : &rr->second);
    if (t_bridgeIssued) extra = (extra == "-" ? "" : extra + " ") + "SRC=bridge";
    ReleaseSRWLockShared(&g_recLock);
    if (skip) return;
    char tag[8] = "-", via[16] = "-";
    bool found = false;
    {
        AcquireSRWLockShared(&g_blockLock);
        auto r = g_blockRules.find(name);
        if (r != g_blockRules.end() && BlockOwner(self, r->second, tag)) { found = true; strcpy_s(via, "rule"); }
        ReleaseSRWLockShared(&g_blockLock);
    }
    int vo;
    if (!found && RecOwnerFromHandles(bytes, tag, &vo)) { found = true; snprintf(via, sizeof via, "+%#x", vo); }
    if (!found) strcpy_s(tag, "-");
    std::string handles;
    for (size_t o = 0x24; o + 8 <= kRecBytes; o += 4) {
        int type = *(int*)(bytes + o), id = *(int*)(bytes + o + 4);
        if (type < 1 || type > 99 || id < 1 || !RawResolve(type, id)) continue;
        char b[40];
        snprintf(b, sizeof b, "%s+%#zx=%d:%d", handles.empty() ? "" : ",", o, type, id);
        handles += b;
    }
    char hex[kRecBytes * 2 + 1];
    for (size_t i = 0; i < kRecBytes; i++) snprintf(hex + i * 2, 3, "%02X", bytes[i]);
    AcquireSRWLockExclusive(&g_recLock);
    if (g_recFile)
        fprintf(g_recFile, "%llu\t%llu\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n", ++g_recSeq, GetTickCount64() - g_recStart,
            name.c_str(), tag, via, *(int*)(bytes + 0xc), handles.empty() ? "-" : handles.c_str(), hex, extra.c_str());
    ReleaseSRWLockExclusive(&g_recLock);
}

static void __fastcall hk_cmdExec(void* self, void* a, void* b, void* c) {
    void* vt = *(void**)self;
    auto it = g_cmdOrig.find(vt);
    if (it == g_cmdOrig.end()) return;   // can't happen: only patched vtables lead here
    const std::string& name = g_cmdName.find(vt)->second;
    if (g_recOn) RecordCommand(name, self);   // before Execute: the command and its objects are as sent
    if (g_cmdLogOn) {
        uintptr_t caller = (uintptr_t)((uint8_t*)_ReturnAddress() - g_base);
        AcquireSRWLockExclusive(&g_cmdLogLock);
        g_cmdCounts[name]++;
        bool sample = g_cmdSeen.insert({ name, caller }).second;
        auto s = g_cmdSample.find(name);
        if (s != g_cmdSample.end()) { sample = true; if (--s->second <= 0) g_cmdSample.erase(s); }
        ReleaseSRWLockExclusive(&g_cmdLogLock);
        if (sample) LogCommandSample(name, caller, self);
    }
    if (g_blockOn && !t_bridgeIssued) {
        bool drop = false;
        char tag[8];
        AcquireSRWLockExclusive(&g_blockLock);
        auto r = g_blockRules.find(name);
        if (r != g_blockRules.end() && BlockOwner(self, r->second, tag) && g_blockTags.count(tag)) {
            drop = true;
            g_blockDropped[name + ":" + tag]++;
        }
        ReleaseSRWLockExclusive(&g_blockLock);
        if (drop) return;
    }
    it->second(self, a, b, c);
}

// Finds the command vtables from RTTI and patches their Execute slot. Once, on the game's main thread.
static int PatchCommandVtables() {
    auto dos = (IMAGE_DOS_HEADER*)g_base;
    auto nt = (IMAGE_NT_HEADERS*)(g_base + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    uint8_t *rs = nullptr, *re = nullptr;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
        if (!memcmp(sec->Name, ".rdata", 6)) { rs = g_base + sec->VirtualAddress; re = rs + sec->Misc.VirtualSize; }
    if (!rs) { Log("cmdlog: no .rdata section"); return -1; }

    // Resolve(&handle): {type, id} -> object
    g_resolve = (ResolveFn)FindPattern(g_textStart, g_textEnd,
        "48 83 EC 28 8B 01 3D ?? ?? 00 00 76 ?? 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B D1 48 8B C8 E8");
    Log("cmdlog: handle resolver %s", g_resolve ? "found" : "NOT found (no handle info, no handle rules)");

    // Complete object locators: signature 1, offset 0, self rva at +20; the type descriptor's name at td+0x10.
    std::map<uint8_t*, std::string> cols;   // COL -> class name, for "...Command" classes
    uint8_t* baseCol = nullptr;
    for (uint8_t* p = rs; p + 24 <= re; p += 4) {
        if (*(uint32_t*)p != 1 || *(uint32_t*)(p + 4) != 0 || *(uint32_t*)(p + 20) != (uint32_t)(p - g_base)) continue;
        uint32_t td = *(uint32_t*)(p + 12);
        if (td == 0 || td >= nt->OptionalHeader.SizeOfImage - 0x20) continue;
        const char* n = (const char*)(g_base + td + 0x10);
        if (strncmp(n, ".?AV", 4) != 0) continue;
        std::string name(n + 4);
        size_t at = name.find("@@");
        if (at == std::string::npos) continue;
        name.resize(at);
        if (name == "CCommand") baseCol = p;
        else if (name.size() > 7 && name.compare(name.size() - 7, 7, "Command") == 0) cols[p] = name;
    }
    if (!baseCol) { Log("cmdlog: CCommand RTTI not found"); return -1; }

    // A vtable sits right after a pointer to its COL.
    void** baseVt = nullptr;
    std::vector<std::pair<void**, std::string>> vts;
    for (uint8_t* p = rs; p + 16 <= re; p += 8) {
        uint8_t* col = *(uint8_t**)p;
        if (col < rs || col >= re) continue;
        if (col == baseCol) baseVt = (void**)(p + 8);
        else { auto it = cols.find(col); if (it != cols.end()) vts.push_back({ (void**)(p + 8), it->second }); }
    }
    if (!baseVt) { Log("cmdlog: CCommand vtable not found"); return -1; }

    for (auto& v : vts) {
        bool derived = true;
        for (int s = 1; s <= 4; s++) if (v.first[s] != baseVt[s]) derived = false;
        if (!derived || v.first[kExecSlot] == baseVt[kExecSlot]) continue;  // not a CCommand, or abstract
        g_cmdOrig[v.first] = (CmdExecFn)v.first[kExecSlot];
        g_cmdName[v.first] = v.second;
    }
    int n = 0;
    for (auto& kv : g_cmdOrig) {
        void** slot = (void**)kv.first + kExecSlot;
        DWORD old;
        if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old)) continue;
        InterlockedExchangePointer(slot, (void*)&hk_cmdExec);
        VirtualProtect(slot, sizeof(void*), old, &old);
        n++;
    }
    Log("cmdlog: patched Execute of %d command classes (%zu candidates)", n, vts.size());
    return n;
}

static bool EnsureCommandsPatched() {
    if (!g_cmdPatched) g_cmdPatched = PatchCommandVtables() > 0;
    return g_cmdPatched;
}

static std::vector<std::string> Words(const std::string& s) {
    std::vector<std::string> w;
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) i++;
        size_t j = i;
        while (j < s.size() && s[j] != ' ' && s[j] != '\t') j++;
        if (j > i) w.push_back(s.substr(i, j - i));
        i = j;
    }
    return w;
}

static std::string CmdLogCommand(const std::string& args) {
    auto w = Words(args);
    std::string a = w.empty() ? "" : w[0];
    if (a == "on") {
        if (!EnsureCommandsPatched()) return "FAIL could not find the command vtables (see console_bridge.log)";
        g_cmdLogOn = true;
        return "OK command log on (" + std::to_string(g_cmdOrig.size()) + " command classes)";
    }
    if (a == "off") { g_cmdLogOn = false; return "OK command log off"; }
    if (a == "sample" && w.size() >= 2) {
        int n = w.size() > 2 ? atoi(w[2].c_str()) : 5;
        if (n < 1) return "FAIL usage: bridge.cmdlog sample CLASS [N]";
        AcquireSRWLockExclusive(&g_cmdLogLock);
        g_cmdSample[w[1]] = n;
        ReleaseSRWLockExclusive(&g_cmdLogLock);
        return "OK logging the next " + std::to_string(n) + " " + w[1];
    }
    if (a == "dump") {
        AcquireSRWLockExclusive(&g_cmdLogLock);
        std::vector<std::pair<int, std::string>> v;
        for (auto& kv : g_cmdCounts) v.push_back({ kv.second, kv.first });
        g_cmdCounts.clear();
        ReleaseSRWLockExclusive(&g_cmdLogLock);
        std::sort(v.rbegin(), v.rend());
        std::string out = "OK";
        for (auto& e : v) out += " " + e.second + "=" + std::to_string(e.first);
        return out;
    }
    if (a.empty()) return std::string("OK command log ") + (g_cmdLogOn ? "on" : "off");
    return "FAIL usage: bridge.cmdlog [on | off | dump | sample CLASS [N]]";
}

static std::string CmdBlockCommand(const std::string& args) {
    auto w = Words(args);
    if (!EnsureCommandsPatched()) return "FAIL could not find the command vtables (see console_bridge.log)";
    std::string out = "OK";
    AcquireSRWLockExclusive(&g_blockLock);
    if (w.size() == 3 && w[0] == "rule" && w[2] == "off") {
        g_blockRules.erase(w[1]);
        out += " rule for " + w[1] + " removed";
    } else if (w.size() == 3 && w[0] == "rule" && w[2] == "auto") {
        if (!g_resolve) out = "FAIL no handle resolver";
        else { g_blockRules[w[1]] = BlockRule{ -2, 0 }; out += " auto rule for " + w[1]; }
    } else if (w.size() == 4 && w[0] == "rule") {
        BlockRule r;
        r.handleOff = w[2] == "-" ? -1 : (int)strtol(w[2].c_str(), nullptr, 0);
        r.ownerOff = (int)strtol(w[3].c_str(), nullptr, 0);
        if (r.handleOff >= 0 && !g_resolve) out = "FAIL no handle resolver; only `rule CLASS - OFF` works";
        else { g_blockRules[w[1]] = r; out += " rule for " + w[1]; }
    } else if (w.size() >= 2 && (w[0] == "add" || w[0] == "remove")) {
        for (size_t i = 1; i < w.size(); i++) {
            std::string t = w[i];
            for (auto& ch : t) ch = (char)toupper((unsigned char)ch);
            if (w[0] == "add") g_blockTags.insert(t); else g_blockTags.erase(t);
        }
    } else if (w.size() == 1 && w[0] == "clear") {
        g_blockTags.clear();
    } else if (w.size() == 1 && w[0] == "dropped") {
        for (auto& kv : g_blockDropped) out += " " + kv.first + "=" + std::to_string(kv.second);
        g_blockDropped.clear();
    } else if (!w.empty()) {
        out = "FAIL usage: bridge.cmdblock [rule CLASS -|HOFF OFF | rule CLASS auto | rule CLASS off | add TAG.. | remove TAG.. | clear | dropped]";
    }
    if (w.empty()) {
        out += " tags:";
        for (auto& t : g_blockTags) out += " " + t;
        out += " rules:";
        for (auto& kv : g_blockRules) {
            char b[64];
            if (kv.second.handleOff == -2) snprintf(b, sizeof b, "(auto)");
            else if (kv.second.handleOff < 0) snprintf(b, sizeof b, "(-,%#x)", kv.second.ownerOff);
            else snprintf(b, sizeof b, "(%#x,%#x)", kv.second.handleOff, kv.second.ownerOff);
            out += " " + kv.first + b;
        }
    }
    g_blockOn = !g_blockRules.empty() && !g_blockTags.empty();
    ReleaseSRWLockExclusive(&g_blockLock);
    return out;
}

// " P+0x1e0=CProvince ..." for the 8-aligned fields of p[from, to) that point to an object with RTTI.
static std::string PtrFields(const uint8_t* p, size_t from, size_t to) {
    std::string out;
    char cls[96], b[140];
    for (size_t o = from; o + 8 <= to; o += 8) {
        uintptr_t v = *(const uintptr_t*)(p + o);
        if (v < 0x10000 || v > 0x7fffffffffffull || (v & 7)) continue;
        if (RawClassName((void*)v, cls)) { snprintf(b, sizeof b, " P+%#zx=%s", o, cls); out += b; }
    }
    return out;
}

// bridge.object TYPE ID: the object a handle names: "CClass @addr tags: +0x..=TAG ... ptrs: P+0x..=CClass ..."
static std::string ObjectCommand(const std::string& args) {
    auto w = Words(args);
    if (w.size() != 2) return "FAIL usage: bridge.object TYPE ID";
    EnsureCommandsPatched();
    if (!g_resolve) return "FAIL no handle resolver";
    void* obj = RawResolve((int)strtol(w[0].c_str(), nullptr, 0), (int)strtol(w[1].c_str(), nullptr, 0));
    if (!obj) return "FAIL no such object";
    std::vector<uint8_t> buf(0x800);
    char at[40];
    snprintf(at, sizeof at, " @%#llx", (unsigned long long)(uintptr_t)obj);
    std::string ptrs = RawBytes(obj, buf.data(), buf.size()) ? PtrFields(buf.data(), 8, buf.size()) : "";
    return "OK " + DescribeObject(obj) + at + " ptrs:" + ptrs;
}

// bridge.mem ADDR LEN: LEN (<= 0x1000) bytes at ADDR (hex) as hex; "?" for an unreadable 16-byte line.
static std::string MemCommand(const std::string& args) {
    auto w = Words(args);
    if (w.size() != 2) return "FAIL usage: bridge.mem ADDR LEN";
    uintptr_t a = (uintptr_t)strtoull(w[0].c_str(), nullptr, 16);
    size_t n = (size_t)strtoul(w[1].c_str(), nullptr, 0);
    if (n == 0 || n > 0x1000) return "FAIL LEN must be 1..0x1000";
    std::string out = "OK ";
    uint8_t line[16];
    char h[3];
    for (size_t o = 0; o < n; o += 16) {
        size_t k = std::min<size_t>(16, n - o);
        if (!RawBytes((void*)(a + o), line, k)) { out += std::string(k * 2, '?'); continue; }
        for (size_t i = 0; i < k; i++) { snprintf(h, sizeof h, "%02X", line[i]); out += h; }
    }
    return out;
}

// ---- bridge.snap: chosen fields of every object of one handle type, appended to a file (research: daily snapshots)
// bridge.snap LABEL TYPE [class=CName] FIELD...   -> "#snap LABEL TYPE FIELD..." then "id<TAB>v1<TAB>v2..." lines
// bridge.snap reset [PATH] (default unit_snapshots.tsv in the HOI4 folder; truncates it)
// A FIELD is a kind letter and a chain of hex offsets: every offset but the last is followed as a pointer.
//   i int, f float, b byte, c country id -> tag, s MSVC std::string, x 64-bit value (hex)
//   e.g. c1c8 (owner), i1e0.a4 (the int at +0xa4 of the object +0x1e0 points to), f-10 (negative offsets work)
struct SnapField { char kind; int n; long long offs[6]; };
static std::string g_snapPath;

static bool ParseSnapField(const std::string& t, SnapField& f) {
    if (t.size() < 2 || !strchr("ifbcsx", t[0])) return false;
    f.kind = t[0]; f.n = 0;
    size_t i = 1;
    while (i < t.size() && f.n < 6) {
        size_t j = t.find('.', i);
        if (j == std::string::npos) j = t.size();
        std::string part = t.substr(i, j - i);
        char* end;
        f.offs[f.n++] = strtoll(part.c_str(), &end, 16);
        if (part.empty() || *end) return false;
        i = j + 1;
    }
    return f.n > 0;
}

// One field of one object, as text; "?" if unreadable. SEH only (no C++ objects).
static void RawSnapField(uint8_t* obj, const SnapField& f, char* out, size_t cap) {
    __try {
        uint8_t* p = obj;
        for (int k = 0; k + 1 < f.n; k++) { p = *(uint8_t**)(p + f.offs[k]); if (!p) { strcpy_s(out, cap, "0"); return; } }
        p += f.offs[f.n - 1];
        switch (f.kind) {
        case 'i': snprintf(out, cap, "%d", *(int*)p); break;
        case 'f': snprintf(out, cap, "%.3f", *(float*)p); break;
        case 'b': snprintf(out, cap, "%u", *(uint8_t*)p); break;
        case 'x': snprintf(out, cap, "%llx", *(unsigned long long*)p); break;
        case 'c': { char t[8]; if (RawTagOf(*(int*)p, t)) strcpy_s(out, cap, t); else snprintf(out, cap, "#%d", *(int*)p); break; }
        case 's': {
            const MsvcString* s = (const MsvcString*)p;
            if (s->size > 200) { strcpy_s(out, cap, "?"); break; }
            size_t n = std::min<size_t>(s->size, cap - 1);
            memcpy(out, StrData(s), n);
            out[n] = 0;
            for (size_t i = 0; i < n; i++) if (out[i] == '\t' || out[i] == '\n' || out[i] == '\r') out[i] = ' ';
            break;
        }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { strcpy_s(out, cap, "?"); }
}

static std::string SnapCommand(const std::string& args) {
    auto w = Words(args);
    if (g_snapPath.empty()) {
        g_snapPath = g_logPath;
        g_snapPath.resize(g_snapPath.find_last_of('\\') + 1);
        g_snapPath += "unit_snapshots.tsv";
    }
    if (!w.empty() && w[0] == "reset") {
        if (w.size() > 1) g_snapPath = args.substr(args.find(w[1]));
        FILE* f = nullptr;
        fopen_s(&f, g_snapPath.c_str(), "w");
        if (!f) return "FAIL can't write " + g_snapPath;
        fclose(f);
        return "OK " + g_snapPath;
    }
    if (w.size() < 3) return "FAIL usage: bridge.snap LABEL TYPE [class=CName] FIELD... | bridge.snap reset [PATH]";
    EnsureCommandsPatched();
    if (!g_resolve) return "FAIL no handle resolver";
    int type = (int)strtol(w[1].c_str(), nullptr, 0);
    std::string want;
    std::vector<SnapField> fields;
    for (size_t i = 2; i < w.size(); i++) {
        if (w[i].rfind("class=", 0) == 0) { want = w[i].substr(6); continue; }
        SnapField f;
        if (!ParseSnapField(w[i], f)) return "FAIL bad field " + w[i];
        fields.push_back(f);
    }
    FILE* out = nullptr;
    fopen_s(&out, g_snapPath.c_str(), "a");
    if (!out) return "FAIL can't write " + g_snapPath;
    setvbuf(out, nullptr, _IOFBF, 1 << 20);
    fprintf(out, "#snap\t%s\t%d", w[0].c_str(), type);
    for (size_t i = 2; i < w.size(); i++) fprintf(out, "\t%s", w[i].c_str());
    fprintf(out, "\n");
    // Ids are handed out in order and objects die, so scan until a long run of misses.
    int found = 0, miss = 0, last = 0;
    char cls[96], v[256];
    for (int id = 1; id < 2000000 && miss < 20000; id++) {
        uint8_t* obj = (uint8_t*)RawResolve(type, id);
        if (!obj) { miss++; continue; }
        miss = 0; last = id;
        if (!want.empty() && (!RawClassName(obj, cls) || want != cls)) continue;
        fprintf(out, "%d", id);
        for (auto& f : fields) { RawSnapField(obj, f, v, sizeof v); fprintf(out, "\t%s", v); }
        fprintf(out, "\n");
        found++;
    }
    fclose(out);
    return "OK " + std::to_string(found) + " objects (ids to " + std::to_string(last) + ")";
}

// bridge.cmdrec [on [PATH] | off | mark TEXT | skip CLASS.. | unskip CLASS.. | owner TYPE HEXOFF[.HEXOFF..]]
static std::string CmdRecCommand(const std::string& args) {
    auto w = Words(args);
    std::string a = w.empty() ? "" : w[0];
    if (a == "on") {
        if (!EnsureCommandsPatched()) return "FAIL could not find the command vtables (see console_bridge.log)";
        std::string path;
        if (w.size() > 1) path = args.substr(args.find(w[1]));
        else {
            path = g_logPath;
            path.resize(path.find_last_of('\\') + 1);
            path += "command_record.tsv";
        }
        AcquireSRWLockExclusive(&g_recLock);
        if (g_recFile) fclose(g_recFile);
        g_recFile = nullptr;
        fopen_s(&g_recFile, path.c_str(), "w");
        if (g_recFile) {
            setvbuf(g_recFile, nullptr, _IOFBF, 1 << 20);
            fprintf(g_recFile, "#seq\tms\tclass\towner\tvia\tmode\thandles\thex%#zx\textra\n", kRecBytes);
            g_recSeq = 0;
            g_recStart = GetTickCount64();
            g_recPath = path;
        }
        g_recOn = g_recFile != nullptr;
        ReleaseSRWLockExclusive(&g_recLock);
        return g_recOn ? "OK recording to " + path : "FAIL can't write " + path;
    }
    if (a == "off") {
        AcquireSRWLockExclusive(&g_recLock);
        g_recOn = false;
        if (g_recFile) fclose(g_recFile);
        g_recFile = nullptr;
        unsigned long long n = g_recSeq;
        ReleaseSRWLockExclusive(&g_recLock);
        return "OK recording off, " + std::to_string(n) + " commands in " + g_recPath;
    }
    if (a == "mark" && w.size() > 1) {
        std::string text = args.substr(args.find(w[1]));
        AcquireSRWLockExclusive(&g_recLock);
        if (g_recFile) {
            fprintf(g_recFile, "#mark\t%llu\t%s\n", GetTickCount64() - g_recStart, text.c_str());
            fflush(g_recFile);
        }
        unsigned long long n = g_recSeq;
        ReleaseSRWLockExclusive(&g_recLock);
        return g_recOn ? "OK " + std::to_string(n) : "FAIL not recording";
    }
    if ((a == "skip" || a == "unskip") && w.size() > 1) {
        AcquireSRWLockExclusive(&g_recLock);
        for (size_t i = 1; i < w.size(); i++) { if (a == "skip") g_recSkip.insert(w[i]); else g_recSkip.erase(w[i]); }
        ReleaseSRWLockExclusive(&g_recLock);
        return "OK";
    }
    if ((a == "list" && w.size() == 5) || (a == "deref" && w.size() == 4) || (a == "rules" && w.size() == 3 && w[2] == "off")) {
        AcquireSRWLockExclusive(&g_recLock);
        if (a == "rules") g_recRules.erase(w[1]);
        else {
            RecRule r{ a == "list" ? 'L' : 'D', (int)strtol(w[2].c_str(), nullptr, 0), (int)strtol(w[3].c_str(), nullptr, 0),
                       a == "list" ? (int)strtol(w[4].c_str(), nullptr, 0) : 0 };
            bool ok = r.off >= 0 && r.off + 8 <= (int)kRecBytes && (r.kind == 'D' || (r.b >= 0 && r.b + 4 <= (int)kRecBytes));
            if (ok) g_recRules[w[1]].push_back(r);
            ReleaseSRWLockExclusive(&g_recLock);
            return ok ? "OK" : "FAIL offsets must lie in the first 0xa0 bytes";
        }
        ReleaseSRWLockExclusive(&g_recLock);
        return "OK";
    }
    if (a == "owner" && w.size() == 3) {
        int type = (int)strtol(w[1].c_str(), nullptr, 0);
        int offs[4], n = 0;
        for (size_t pos = 0; pos <= w[2].size() && n < 4;) {   // "80.0.3c": hex offsets, pointers followed
            size_t dot = w[2].find('.', pos);
            if (dot == std::string::npos) dot = w[2].size();
            offs[n++] = (int)strtol(w[2].substr(pos, dot - pos).c_str(), nullptr, 16);
            pos = dot + 1;
        }
        int i = 0;
        while (i < g_recOwnerN && g_recOwnerType[i] != type) i++;
        if (i == 16) return "FAIL too many owner types";
        // set while recording may be read mid-change by the game thread; only done between runs in practice
        for (int j = 0; j < n; j++) g_recOwnerOff[i][j] = offs[j];
        g_recOwnerLen[i] = n;
        g_recOwnerType[i] = type;
        if (i == g_recOwnerN) g_recOwnerN++;
        return "OK";
    }
    if (a.empty()) {
        std::string out = std::string("OK recording ") + (g_recOn ? "on, " + std::to_string(g_recSeq) + " commands in " + g_recPath : "off");
        out += " owners:";
        for (int i = 0; i < g_recOwnerN; i++) {
            char b[16];
            snprintf(b, sizeof b, " %d@", g_recOwnerType[i]);
            out += b;
            for (int j = 0; j < g_recOwnerLen[i]; j++) { snprintf(b, sizeof b, j ? ".%x" : "%x", g_recOwnerOff[i][j]); out += b; }
        }
        out += " skip:";
        for (auto& s : g_recSkip) out += " " + s;
        return out;
    }
    return "FAIL usage: bridge.cmdrec [on [PATH] | off | mark TEXT | skip CLASS.. | unskip CLASS.. | owner TYPE OFF | list CLASS PTR COUNT STRIDE | deref CLASS PTR FIELD | rules CLASS off]";
}

// ---- bridge.move: order a division (any country's) to a province, the way the game's own move code does it:
// build a CMoveCommand on the stack, check it (vtable slot 9), execute it (slot 10), destroy it (slot 0).
// CMoveCommand(cmd, CArmy* unit, int province, bool, int, bool x5): the flags are those of a player's move
// (1, 2, 1, 0, 0, 0, 0). The unit pointer is the object a handle resolves to minus 0x10 (its handle is at +0x18).
using MoveCtorFn = void*(__fastcall*)(void* cmd, void* unit, int province, char b4, int i5, char b6, char b7, char b8,
                                      char b9, char b10);
using ValidFn = char(__fastcall*)(void* cmd, void* arg);
using DtorFn = void*(__fastcall*)(void* cmd, int flags);
static MoveCtorFn g_moveCtor;
static void** g_moveVt;

// The CMoveCommand constructor: a command constructor prologue whose vtable lea loads CMoveCommand's vtable.
static bool FindMoveCtor() {
    if (g_moveCtor) return true;
    for (auto& kv : g_cmdName) if (kv.second == "CMoveCommand") g_moveVt = (void**)kv.first;
    if (!g_moveVt) return false;
    const char* pat = "48 89 4C 24 08 53 48 83 EC 60 48 8B D9 C6 41 08 00 C7 41 0C FF FF FF FF 33 C0 48 89 41 10 "
                      "33 C9 48 89 4B 10 C7 43 18 FF FF 00 00 48 89 4B 1C 48 8D 05";
    for (uint8_t* c = g_textStart; (c = FindPattern(c, g_textEnd, pat)) != nullptr; c++) {
        uint8_t* lea = c + 0x2f;   // 48 8D 05 rel32
        if (Rel32(lea, 3, 7) == (uint8_t*)g_moveVt) { g_moveCtor = (MoveCtorFn)c; break; }
    }
    Log("move: CMoveCommand vtable %p ctor %p", g_moveVt, g_moveCtor);
    return g_moveCtor != nullptr;
}

// 1 executed, 0 the game's check refused it, -1 crashed. SEH only.
static int RawMove(void* unit, int province, const char f[7]) {
    alignas(16) uint8_t cmd[0x100] = {};
    bool built = false;
    __try {
        g_moveCtor(cmd, unit, province, f[0], f[1], f[2], f[3], f[4], f[5], f[6]);
        built = true;
        void** vt = *(void***)cmd;
        int r = 0;
        if (((ValidFn)vt[9])(cmd, nullptr)) {
            t_bridgeIssued = true;
            ((CmdExecFn)vt[10])(cmd, nullptr, nullptr, nullptr);   // through hk_cmdExec, so it is recorded
            t_bridgeIssued = false;
            r = 1;
        }
        ((DtorFn)vt[0])(cmd, 0);
        return r;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        t_bridgeIssued = false;
        return built ? -1 : -2;
    }
}

// ---- bridge.protect: keep the game from stopping divisions we move.
// A unit's path lives at +0x2c0 of the full division object. ClearPath(unit) empties it, and CancelMovement(unit,
// bool) empties it too (directly), e.g. for the AI's CCancelMovementCommand, whose divisions sit in a list so its
// owner isn't found. The hooks refuse both for a protected division unless the bridge itself is moving it, and
// count who tried (by return address).
using ClearPathFn = void(__fastcall*)(uint8_t* unit);
static ClearPathFn o_clearPath;
using CancelMoveFn = void(__fastcall*)(uint8_t* unit, char flag);
static CancelMoveFn o_cancelMove;
static bool g_protReady = false;
static SRWLOCK g_protLock = SRWLOCK_INIT;
static std::set<int> g_protIds;                        // division handle ids
static std::map<uintptr_t, int> g_protCallers;         // caller rva -> refused ClearPath calls
static volatile bool g_protOn = false;

// True if the game should leave this unit's path alone; counts the caller.
static bool Protected(uint8_t* unit, void* ret) {
    if (!g_protOn || t_bridgeIssued) return false;
    int h[2] = { 0, 0 };
    RawBytes(unit + 0x18, (uint8_t*)h, 8);
    if (h[0] != 51) return false;
    AcquireSRWLockExclusive(&g_protLock);
    bool mine = g_protIds.count(h[1]) > 0;
    if (mine) g_protCallers[(uintptr_t)((uint8_t*)ret - g_base)]++;
    ReleaseSRWLockExclusive(&g_protLock);
    return mine;
}

static void __fastcall hk_clearPath(uint8_t* unit) {
    if (!Protected(unit, _ReturnAddress())) o_clearPath(unit);
}

static void __fastcall hk_cancelMove(uint8_t* unit, char flag) {
    if (!Protected(unit, _ReturnAddress())) o_cancelMove(unit, flag);
}

static bool EnsureProtectHook() {
    if (g_protReady) return true;
    uint8_t* f = FindPattern(g_textStart, g_textEnd,
        "40 53 48 83 EC 20 48 8B D9 48 81 C1 C0 02 00 00 E8 ?? ?? ?? ?? C7 83 2C 02 00 00 00 00 00 00 48 83 C4 20 5B C3");
    if (!f) { Log("protect: ClearPath not found"); return false; }
    uint8_t* c = FindPattern(g_textStart, g_textEnd,
        "48 89 5C 24 10 48 89 74 24 20 55 57 41 54 41 56 41 57 48 8B EC 48 83 EC 60 44 0F B6 E2 48 8B D9 C6 81 AC 02 00 00 00");
    if (!c) { Log("protect: CancelMovement not found"); return false; }
    g_protReady = MH_CreateHook(f, &hk_clearPath, (void**)&o_clearPath) == MH_OK && MH_EnableHook(f) == MH_OK &&
                  MH_CreateHook(c, &hk_cancelMove, (void**)&o_cancelMove) == MH_OK && MH_EnableHook(c) == MH_OK;
    Log("protect: ClearPath hoi4+%#llx, CancelMovement hoi4+%#llx hooked: %d", (unsigned long long)(f - g_base),
        (unsigned long long)(c - g_base), g_protReady);
    return g_protReady;
}

// bridge.protect [add ID.. | remove ID.. | clear | callers]
static std::string ProtectCommand(const std::string& args) {
    auto w = Words(args);
    if (!EnsureProtectHook()) return "FAIL ClearPath hook not available (see console_bridge.log)";
    std::string out = "OK";
    AcquireSRWLockExclusive(&g_protLock);
    if (!w.empty() && (w[0] == "add" || w[0] == "remove"))
        for (size_t i = 1; i < w.size(); i++) { int id = atoi(w[i].c_str()); if (w[0] == "add") g_protIds.insert(id); else g_protIds.erase(id); }
    else if (w.size() == 1 && w[0] == "clear") g_protIds.clear();
    else if (w.size() == 1 && w[0] == "callers") {
        for (auto& kv : g_protCallers) { char b[48]; snprintf(b, sizeof b, " hoi4+%#llx=%d", (unsigned long long)kv.first, kv.second); out += b; }
        g_protCallers.clear();
    } else if (!w.empty()) out = "FAIL usage: bridge.protect [add ID.. | remove ID.. | clear | callers]";
    g_protOn = !g_protIds.empty();
    if (w.empty()) out += " " + std::to_string(g_protIds.size()) + " protected divisions";
    ReleaseSRWLockExclusive(&g_protLock);
    return out;
}

// ---- bridge.watch: a hardware write watchpoint (research): debug register 0 on every thread of the game, a
// vectored handler counts the writing instructions with a rough call stack (return addresses found on the stack).
struct WatchHit { uintptr_t rip; uintptr_t stack[6]; volatile LONG count; };
static WatchHit g_watchHits[64];
static volatile LONG g_watchN = 0;
static PVOID g_watchVeh = nullptr;
static uintptr_t g_watchAddr = 0;

static LONG CALLBACK WatchVeh(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT* c = ep->ContextRecord;
    if (!(c->Dr6 & 1)) return EXCEPTION_CONTINUE_SEARCH;
    c->Dr6 = 0;
    uintptr_t rip = c->Rip - (uintptr_t)g_base, st[6] = {};
    const uintptr_t* sp = (const uintptr_t*)c->Rsp;
    for (int i = 0, k = 0; i < 200 && k < 6; i++)
        if (sp[i] >= (uintptr_t)g_textStart && sp[i] < (uintptr_t)g_textEnd) st[k++] = sp[i] - (uintptr_t)g_base;
    LONG n = g_watchN < 64 ? g_watchN : 64;
    for (LONG i = 0; i < n; i++)
        if (g_watchHits[i].rip == rip && g_watchHits[i].stack[0] == st[0] && g_watchHits[i].stack[1] == st[1]) {
            InterlockedIncrement(&g_watchHits[i].count);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    LONG i = InterlockedIncrement(&g_watchN) - 1;
    if (i < 64) { g_watchHits[i].rip = rip; memcpy(g_watchHits[i].stack, st, sizeof st); g_watchHits[i].count = 1; }
    return EXCEPTION_CONTINUE_EXECUTION;
}

// Sets (addr != 0) or clears debug register 0 on every other thread of the process. Runs on its own thread so
// that it can suspend the game's threads, the caller included.
static DWORD WINAPI WatchSetAll(LPVOID addrp) {
    uintptr_t addr = (uintptr_t)addrp;
    DWORD self = GetCurrentThreadId(), pid = GetCurrentProcessId(), n = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te{ sizeof te };
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != pid || te.th32ThreadID == self) continue;
        HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
        if (!h) continue;
        if (SuspendThread(h) != (DWORD)-1) {
            CONTEXT c{};
            c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(h, &c)) {
                c.Dr7 &= ~0xF0003ull;                                   // DR0: local enable, RW, LEN
                if (addr) { c.Dr0 = addr; c.Dr7 |= 1 | (1ull << 16) | (3ull << 18); }   // write, 4 bytes
                if (SetThreadContext(h, &c)) n++;
            }
            ResumeThread(h);
        }
        CloseHandle(h);
    }
    CloseHandle(snap);
    return n;
}

// bridge.watch ADDR | div ID OFF | hits | off
static std::string WatchCommand(const std::string& args) {
    auto w = Words(args);
    if (w.size() == 1 && w[0] == "hits") {
        std::string out = "OK";
        LONG n = g_watchN < 64 ? g_watchN : 64;
        for (LONG i = 0; i < n; i++) {
            char b[200];
            int k = snprintf(b, sizeof b, " hoi4+%#llx x%ld <", (unsigned long long)g_watchHits[i].rip, g_watchHits[i].count);
            for (int j = 0; j < 6 && g_watchHits[i].stack[j]; j++)
                k += snprintf(b + k, sizeof b - k, "%s%llx", j ? "," : "", (unsigned long long)g_watchHits[i].stack[j]);
            snprintf(b + k, sizeof b - k, ">");
            out += b;
        }
        return out;
    }
    uintptr_t addr = 0;
    if (w.size() == 1 && w[0] == "off") addr = 0;
    else if (w.size() == 3 && w[0] == "div") {
        EnsureCommandsPatched();
        uint8_t* obj = (uint8_t*)RawResolve(51, atoi(w[1].c_str()));
        if (!obj) return "FAIL no division " + w[1];
        addr = (uintptr_t)(obj - 0x10 + strtol(w[2].c_str(), nullptr, 16));   // offset into the full object
    } else if (w.size() == 1) addr = (uintptr_t)strtoull(w[0].c_str(), nullptr, 16);
    else return "FAIL usage: bridge.watch ADDR | div ID HEXOFF | hits | off";
    if (addr & 3) return "FAIL address must be 4-aligned";
    if (addr && !g_watchVeh) g_watchVeh = AddVectoredExceptionHandler(1, WatchVeh);
    g_watchN = 0;
    g_watchAddr = addr;
    HANDLE t = CreateThread(nullptr, 0, WatchSetAll, (LPVOID)addr, 0, nullptr);
    DWORD n = 0;
    if (t) { WaitForSingleObject(t, 5000); GetExitCodeThread(t, &n); CloseHandle(t); }
    char b[96];
    snprintf(b, sizeof b, "OK watch %s %#llx on %lu threads", addr ? "on" : "off", (unsigned long long)addr, n);
    return b;
}

// ---- bridge.army: build armies and give them leaders, as the game's army UI does.
// COrderGroupCommand(cmd, vector<handle>* divisions, CTheatre* theatre, obj* extra): its Execute creates an army
// ("orders group") of the given divisions in the theatre (only divisions of the theatre's country are kept).
// CSetArmyLeaderCommand(cmd, unit leader*, army*, bool): Execute makes the leader the army's commander.
// Both are built on the stack, checked (slot 9), executed (slot 10) and destroyed (slot 0), like bridge.move.
// Their constructors are found by a prologue pattern plus a lea of the class's own vtable within it.
using OrderGroupCtorFn = void*(__fastcall*)(void* cmd, void* units, void* theatre, void* extra);
using SetLeaderCtorFn = void*(__fastcall*)(void* cmd, void* leader, void* army, char flag);
static OrderGroupCtorFn g_orderGroupCtor;
static SetLeaderCtorFn g_setLeaderCtor;

static uint8_t* FindCtorFor(const char* cls, const char* pat) {
    void** vt = nullptr;
    for (auto& kv : g_cmdName) if (kv.second == cls) vt = (void**)kv.first;
    if (!vt) return nullptr;
    for (uint8_t* c = g_textStart; (c = FindPattern(c, g_textEnd, pat)) != nullptr; c++)
        for (int i = 0; i < 0x80 && c + i + 7 < g_textEnd; i++)
            if (c[i] == 0x48 && c[i + 1] == 0x8D && c[i + 2] == 0x05 && Rel32(c + i, 3, 7) == (uint8_t*)vt) return c;
    return nullptr;
}

static bool FindArmyCtors() {
    if (!g_orderGroupCtor)
        g_orderGroupCtor = (OrderGroupCtorFn)FindCtorFor("COrderGroupCommand",
            "48 89 5C 24 10 48 89 4C 24 08 55 56 57 41 54 41 55 41 56 41 57 48 83 EC 30 49 8B D9 4D 8B E8 4C 8B FA "
            "4C 8B F1 C6 41 08 00 C7 41 0C FF FF FF FF 33 F6 48 89 71 10 C7 41 18 FF FF 00 00 48 89 71 1C 48 8D 05");
    if (!g_setLeaderCtor)
        g_setLeaderCtor = (SetLeaderCtorFn)FindCtorFor("CSetArmyLeaderCommand",
            "48 89 5C 24 10 48 89 74 24 18 48 89 4C 24 08 57 48 83 EC 30 41 0F B6 F1 49 8B F8 48 8B D9 C6 41 08 00 "
            "C7 41 0C FF FF FF FF 33 C0 48 89 41 10 33 C9 48 89 4B 10 C7 43 18 FF FF 00 00 48 89 4B 1C 48 8D 05");
    Log("army: COrderGroupCommand ctor %p, CSetArmyLeaderCommand ctor %p", g_orderGroupCtor, g_setLeaderCtor);
    return g_orderGroupCtor && g_setLeaderCtor;
}

// Check and execute a command built in CMD, then destroy it: 1 executed, 0 refused by the game's check, -1 crashed.
static int RunBuilt(uint8_t* cmd) {
    __try {
        void** vt = *(void***)cmd;
        int r = 0;
        if (((ValidFn)vt[9])(cmd, nullptr)) {
            t_bridgeIssued = true;
            ((CmdExecFn)vt[10])(cmd, nullptr, nullptr, nullptr);
            t_bridgeIssued = false;
            r = 1;
        }
        ((DtorFn)vt[0])(cmd, 0);
        return r;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        t_bridgeIssued = false;
        return -1;
    }
}

static int OrderIdOf(uint8_t* division) {   // the army / front a division is in (its COrdersGroup's id), 0 if none
    uint8_t* order = nullptr;
    int id = 0;
    if (!RawBytes(division + 0xb0, (uint8_t*)&order, 8) || !order) return 0;
    return RawBytes(order + 0xc, (uint8_t*)&id, 4) ? id : 0;
}

static int RawCreateArmy(uint64_t* handles, int n, void* theatre) {
    struct { uint64_t* data; int cap; int count; } vec = { handles, n, n };
    alignas(16) uint8_t cmd[0x100] = {};
    __try { g_orderGroupCtor(cmd, &vec, theatre, nullptr); } __except (EXCEPTION_EXECUTE_HANDLER) { return -2; }
    return RunBuilt(cmd);
}

static int RawSetLeader(void* leader, void* army) {
    alignas(16) uint8_t cmd[0x100] = {};
    __try { g_setLeaderCtor(cmd, leader, army, 0); } __except (EXCEPTION_EXECUTE_HANDLER) { return -2; }
    return RunBuilt(cmd);
}

// bridge.army create DIVISION_ID.. | leader ARMY_ID LEADER_ID
static std::string ArmyCommand(const std::string& args) {
    auto w = Words(args);
    const char* usage = "FAIL usage: bridge.army create DIVISION_ID.. | leader ARMY_ID LEADER_ID";
    if (w.empty()) return usage;
    if (!EnsureCommandsPatched() || !g_resolve) return "FAIL no command vtables / handle resolver";
    if (!FindArmyCtors()) return "FAIL army command constructors not found";
    char cls[96];
    if (w[0] == "create" && w.size() >= 2) {
        std::vector<uint64_t> h;
        uint8_t* first = nullptr;
        for (size_t i = 1; i < w.size(); i++) {
            int id = atoi(w[i].c_str());
            uint8_t* obj = (uint8_t*)RawResolve(51, id);
            if (!obj || !RawClassName(obj, cls) || strcmp(cls, "CArmy") != 0) return "FAIL no division with id " + w[i];
            if (!first) first = obj;
            h.push_back(((uint64_t)(uint32_t)id << 32) | 51u);
        }
        void* theatre = nullptr;
        if (!RawBytes(first + 0x290, (uint8_t*)&theatre, 8) || !theatre || !RawClassName((uint8_t*)theatre, cls) ||
            strcmp(cls, "CTheatre") != 0) return "FAIL the first division has no theatre";
        int r = RawCreateArmy(h.data(), (int)h.size(), theatre);
        if (r == 0) return "FAIL the game refused to create the army";
        if (r < 0) return r == -1 ? "ERROR crashed while creating the army" : "ERROR crashed while building the command";
        int army = OrderIdOf(first);
        int in = 0;
        for (size_t i = 1; i < w.size(); i++) {
            uint8_t* obj = (uint8_t*)RawResolve(51, atoi(w[i].c_str()));
            if (obj && army && OrderIdOf(obj) == army) in++;
        }
        char b[96];
        snprintf(b, sizeof b, "OK army %d with %d of %zu divisions", army, in, w.size() - 1);
        return b;
    }
    if (w[0] == "leader" && w.size() == 3) {
        void* army = RawResolve(53, atoi(w[1].c_str()));
        void* leader = RawResolve(4713, atoi(w[2].c_str()));
        if (!army) return "FAIL no army with id " + w[1];
        if (!leader) return "FAIL no unit leader with id " + w[2];
        int r = RawSetLeader(leader, army);
        if (r == 1) return "OK leader " + w[2] + " commands army " + w[1];
        if (r == 0) return "FAIL the game refused the leader";
        return r == -1 ? "ERROR crashed while setting the leader" : "ERROR crashed while building the command";
    }
    return usage;
}

// bridge.move DIVISION_ID PROVINCE [b4 i5 b6 b7 b8 b9 b10]
static std::string MoveCommand(const std::string& args) {
    auto w = Words(args);
    if (w.size() != 2 && w.size() != 9) return "FAIL usage: bridge.move DIVISION_ID PROVINCE [7 flags]";
    if (!EnsureCommandsPatched() || !g_resolve) return "FAIL no command vtables / handle resolver";
    if (!FindMoveCtor()) return "FAIL CMoveCommand constructor not found";
    int id = atoi(w[0].c_str()), prov = atoi(w[1].c_str());
    char f[7] = { 1, 2, 1, 0, 0, 0, 0 };
    if (w.size() == 9) for (int i = 0; i < 7; i++) f[i] = (char)atoi(w[2 + i].c_str());
    uint8_t* obj = (uint8_t*)RawResolve(51, id);
    char cls[96];
    if (!obj || !RawClassName(obj, cls) || strcmp(cls, "CArmy") != 0) return "FAIL no division with id " + w[0];
    char tag[8] = "?";
    int owner = 0;
    if (RawBytes(obj + 0x1c8, (uint8_t*)&owner, 4)) RawTagOf(owner, tag);
    int r = RawMove(obj - 0x10, prov, f);
    if (r == 1) return "OK " + std::string(tag) + " division " + w[0] + " ordered to province " + w[1];
    if (r == 0) return "FAIL the game refused the move (province unreachable or not allowed)";
    return r == -1 ? "ERROR crashed while executing the move" : "ERROR crashed while building the move";
}

static void __fastcall hk_execCmd(void* cmd, int depth) {
    int prev = t_cmdDepth;
    t_cmdDepth = depth;
    o_execCmd(cmd, depth);
    t_cmdDepth = prev;
}

static void __fastcall hk_execAct(uint8_t* action) {
    char a[16], b[16];
    if (g_warsOn && t_cmdDepth == 0 && RawWarPair(action, a, b)) {
        const char* player = RawPlayerTag();
        if (!player || strcmp(player, a) != 0) {
            std::string key = std::string(a) + ":" + b;
            AcquireSRWLockExclusive(&g_warLock);
            bool allowed = g_warAllowed.count(key) > 0;
            if (!allowed) g_warAttempts[key]++;
            ReleaseSRWLockExclusive(&g_warLock);
            if (!allowed) {
                Log("war: %s's declaration of war on %s dropped (not allowed)", a, b);
                return;
            }
            Log("war: %s declares war on %s (allowed)", a, b);
        }
    }
    o_execAct(action);
}

// bridge.wars [on | off | allow [A:B ...] | attempts]
static std::string WarsCommand(const std::string& args) {
    if (!g_warReady) return "ERROR war declarations not hooked (see console_bridge.log)";
    std::vector<std::string> words;
    size_t pos = 0;
    while (pos < args.size()) {
        size_t s = args.find_first_not_of(" \t", pos);
        if (s == std::string::npos) break;
        size_t e = args.find_first_of(" \t", s);
        if (e == std::string::npos) e = args.size();
        words.push_back(args.substr(s, e - s));
        pos = e;
    }
    if (words.empty()) {
        AcquireSRWLockShared(&g_warLock);
        std::string out = std::string("OK ") + (g_warsOn ? "on" : "off") + ", " + std::to_string(g_warAllowed.size())
                          + " pairs allowed, " + std::to_string(g_warAttempts.size()) + " pairs tried";
        ReleaseSRWLockShared(&g_warLock);
        return out;
    }
    if (words[0] == "on" || words[0] == "off") {
        g_warsOn = words[0] == "on";
        return std::string("OK ") + words[0];
    }
    if (words[0] == "allow") {
        std::set<std::string> pairs;
        for (size_t i = 1; i < words.size(); i++) {
            std::string p = words[i];
            for (auto& ch : p) ch = (char)toupper((unsigned char)ch);
            size_t c = p.find(':');
            if (c == std::string::npos || c == 0 || c + 1 >= p.size()) return "FAIL bad pair " + words[i];
            pairs.insert(p);
        }
        AcquireSRWLockExclusive(&g_warLock);
        g_warAllowed = pairs;
        ReleaseSRWLockExclusive(&g_warLock);
        return "OK " + std::to_string(pairs.size()) + " pairs allowed";
    }
    if (words[0] == "attempts") {
        AcquireSRWLockExclusive(&g_warLock);
        std::string out = "OK";
        for (auto& kv : g_warAttempts) out += " " + kv.first + "=" + std::to_string(kv.second);
        g_warAttempts.clear();
        ReleaseSRWLockExclusive(&g_warLock);
        return out;
    }
    return "FAIL usage: bridge.wars [on | off | allow [A:B ...] | attempts]";
}

static std::string HandleBridgeCommand(const std::string& cmd) {
    if (cmd == "bridge.wars" || cmd.rfind("bridge.wars ", 0) == 0) return WarsCommand(cmd.substr(11));
    if (cmd == "bridge.cmdlog" || cmd.rfind("bridge.cmdlog ", 0) == 0) return CmdLogCommand(cmd.substr(13));
    if (cmd == "bridge.cmdblock" || cmd.rfind("bridge.cmdblock ", 0) == 0) return CmdBlockCommand(cmd.substr(15));
    if (cmd == "bridge.cmdrec" || cmd.rfind("bridge.cmdrec ", 0) == 0) return CmdRecCommand(cmd.substr(13));
    if (cmd.rfind("bridge.object ", 0) == 0) return ObjectCommand(cmd.substr(14));
    if (cmd.rfind("bridge.mem ", 0) == 0) return MemCommand(cmd.substr(11));
    if (cmd.rfind("bridge.move ", 0) == 0) return MoveCommand(cmd.substr(12));
    if (cmd.rfind("bridge.army ", 0) == 0) return ArmyCommand(cmd.substr(12));
    if (cmd.rfind("bridge.watch ", 0) == 0) return WatchCommand(cmd.substr(13));
    if (cmd == "bridge.protect" || cmd.rfind("bridge.protect ", 0) == 0) return ProtectCommand(cmd.substr(14));
    if (cmd == "bridge.snap" || cmd.rfind("bridge.snap ", 0) == 0) return SnapCommand(cmd.substr(11));
    if (cmd.rfind("bridge.tag ", 0) == 0) {
        if (!g_dataReady) return "ERROR country data support not active";
        std::string out = "OK";
        const char* p = cmd.c_str() + 11;
        while (*p) {
            char* end;
            long id = strtol(p, &end, 0);
            if (end == p) break;
            char t[8];
            out += " " + std::to_string(id) + "=" + (RawTagOf((int)id, t) ? t : "?");
            p = end;
        }
        return out;
    }
    if (cmd == "bridge.treaties" || cmd.rfind("bridge.treaties ", 0) == 0) return SetTreatyPairs(cmd.substr(15));
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
        if (ScanRelations()) {
            g_relReady = MH_CreateHook((void*)g_createStrips, &hk_createStrips, (void**)&o_createStrips) == MH_OK &&
                         MH_EnableHook((void*)g_createStrips) == MH_OK;
            Log(g_relReady ? "treaty row hook on" : "treaty row hook FAILED");
        }
        if (ScanEditBox()) {
            g_ebReady = MH_CreateHook((void*)g_ebInsert, &hk_ebInsert, (void**)&o_ebInsert) == MH_OK &&
                        MH_CreateHook((void*)g_ebDtor, &hk_ebDtor, (void**)&o_ebDtor) == MH_OK &&
                        MH_EnableHook((void*)g_ebInsert) == MH_OK && MH_EnableHook((void*)g_ebDtor) == MH_OK;
            Log(g_ebReady ? "editbox hooks on" : "editbox hooks FAILED");
        }
        if (ScanWar()) {
            g_warReady = MH_CreateHook((void*)g_execCmd, &hk_execCmd, (void**)&o_execCmd) == MH_OK &&
                         MH_CreateHook((void*)g_execAct, &hk_execAct, (void**)&o_execAct) == MH_OK &&
                         MH_EnableHook((void*)g_execCmd) == MH_OK && MH_EnableHook((void*)g_execAct) == MH_OK;
            Log(g_warReady ? "war declaration hooks on" : "war declaration hooks FAILED");
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
        // A fresh log each launch; the last one is kept as console_bridge.old.log
        char old[MAX_PATH];
        strcpy_s(old, g_logPath);
        if (char* dot = strrchr(old, '.')) strcpy_s(dot, old + MAX_PATH - dot, ".old.log");
        MoveFileExA(g_logPath, old, MOVEFILE_REPLACE_EXISTING);
        if (HANDLE h = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr)) CloseHandle(h);
    }
    return TRUE;
}
