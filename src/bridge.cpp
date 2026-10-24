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

static std::string HandleBridgeCommand(const std::string& cmd) {
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
    return "FAIL unknown bridge command (bridge.locinfo, bridge.setloc KEY text, bridge.reloadloc <file>)";
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
    if (g_ready) RunQueued();
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
