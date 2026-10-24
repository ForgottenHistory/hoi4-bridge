// Probe build of the HOI4 console bridge: observes only, never executes commands.
// Loaded as version.dll from the HOI4 folder. Writes console_bridge.log next to itself.
//
// Checks:
//  1. the DLL loads and forwards version.dll correctly (game starts normally)
//  2. byte patterns find the console dispatcher, word splitter and console singleton
//  3. which thread calls IDXGISwapChain::Present (once per frame)
//  4. which thread runs console commands the player types

#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <cstdio>
#include <cstdint>
#include <cstdarg>
#include <cstring>
#include "MinHook.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "user32.lib")

// Forward every version.dll export to the real system DLL.
#define FWD(name) __pragma(comment(linker, "/export:" #name "=C:\\Windows\\System32\\version." #name))
FWD(GetFileVersionInfoA) FWD(GetFileVersionInfoByHandle) FWD(GetFileVersionInfoExA) FWD(GetFileVersionInfoExW)
FWD(GetFileVersionInfoSizeA) FWD(GetFileVersionInfoSizeExA) FWD(GetFileVersionInfoSizeExW) FWD(GetFileVersionInfoSizeW)
FWD(GetFileVersionInfoW) FWD(VerFindFileA) FWD(VerFindFileW) FWD(VerInstallFileA) FWD(VerInstallFileW)
FWD(VerLanguageNameA) FWD(VerLanguageNameW) FWD(VerQueryValueA) FWD(VerQueryValueW)

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

// What the scan finds (all inside hoi4.exe)
static uint8_t* g_base;
static void*    g_dispatch;   // CConsoleCmdManager::Execute wrapper (this, SResult* out, CPdxArray<CString>* words)
static void*    g_split;      // CString::Split(this, CPdxArray<CString>* out, char sep)
static void*    g_getInst;    // creates the console manager and stores it in the slot
static void**   g_slot;       // global CConsoleCmdManager*

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
    if (!split) { Log("scan: split pattern NOT found"); return false; }
    // A little later: mgr = slot ? slot : create(); mgr->Execute(&result, &words)
    uint8_t* disp = FindPattern(split, split + 0x100,
        "48 8B 0D ?? ?? ?? ?? 48 85 C9 75 ?? E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 4C 8D 44 24 ?? 48 8D 55 ?? E8 ?? ?? ?? ??");
    if (!disp) { Log("scan: dispatch pattern NOT found"); return false; }

    g_split    = Rel32(split + 13, 1, 5);
    g_slot     = (void**)Rel32(disp, 3, 7);
    g_getInst  = Rel32(disp + 12, 1, 5);
    g_dispatch = Rel32(disp + 33, 1, 5);
    Log("scan: split=hoi4+%#llx dispatch=hoi4+%#llx getInst=hoi4+%#llx slot=hoi4+%#llx",
        (unsigned long long)((uint8_t*)g_split - g_base), (unsigned long long)((uint8_t*)g_dispatch - g_base),
        (unsigned long long)((uint8_t*)g_getInst - g_base), (unsigned long long)((uint8_t*)g_slot - g_base));
    return true;
}

// ---------------------------------------------------------------- game data layouts (MSVC x64)
struct MsvcString { union { char buf[16]; char* ptr; }; size_t size; size_t cap; };
static const char* StrData(const MsvcString* s) { return s->cap > 15 ? s->ptr : s->buf; }
struct PdxArray { void* data; int capacity; int size; void* alloc; };

// ---------------------------------------------------------------- hooks
static volatile DWORD g_presentThread = 0;
static volatile DWORD g_consoleThread = 0;
static volatile LONG  g_frames = 0;

using DispatchFn = void*(__fastcall*)(void* mgr, void* out, PdxArray* words);
static DispatchFn o_dispatch;

static void DescribeWords(PdxArray* w, char* out, size_t cap) {
    out[0] = 0;
    __try {
        for (int i = 0; i < w->size && i < 6; i++) {
            auto s = (MsvcString*)w->data + i;
            if (s->size > 200) { strcat_s(out, cap, "<?> "); continue; }
            strncat_s(out, cap, StrData(s), _TRUNCATE);
            strncat_s(out, cap, " ", _TRUNCATE);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { strcpy_s(out, cap, "<unreadable>"); }
}

static void* __fastcall hk_dispatch(void* mgr, void* out, PdxArray* words) {
    DWORD tid = GetCurrentThreadId();
    char desc[300]; DescribeWords(words, desc, sizeof desc);
    Log("console command on thread %lu (frame thread %lu, same=%s): %s", tid, g_presentThread,
        tid == g_presentThread ? "YES" : "no", desc);
    g_consoleThread = tid;
    void* r = o_dispatch(mgr, out, words);
    __try {
        auto ok = *(uint8_t*)out;
        auto msg = (MsvcString*)((uint8_t*)out + 8);
        Log("  -> ok=%d message=\"%.200s\"", ok, msg->size < 4096 ? StrData(msg) : "<long>");
    } __except (EXCEPTION_EXECUTE_HANDLER) { Log("  -> result unreadable"); }
    return r;
}

using PresentFn = HRESULT(__stdcall*)(IDXGISwapChain*, UINT, UINT);
static PresentFn o_present;
static HRESULT __stdcall hk_present(IDXGISwapChain* sc, UINT sync, UINT flags) {
    DWORD tid = GetCurrentThreadId();
    if (g_presentThread != tid) {
        Log("Present now on thread %lu (was %lu); swapchain %p", tid, g_presentThread, sc);
        g_presentThread = tid;
    }
    LONG n = InterlockedIncrement(&g_frames);
    if (n % 3000 == 0) Log("heartbeat: %ld frames, console mgr=%p", n, g_slot ? *g_slot : nullptr);
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

static DWORD WINAPI InitThread(void*) {
    Log("---- probe loaded into pid %lu ----", GetCurrentProcessId());
    if (MH_Initialize() != MH_OK) { Log("MinHook init failed"); return 0; }

    if (ScanGame()) {
        if (MH_CreateHook(g_dispatch, &hk_dispatch, (void**)&o_dispatch) == MH_OK &&
            MH_EnableHook(g_dispatch) == MH_OK)
            Log("console dispatch hook on");
        else Log("console dispatch hook FAILED");
    } else {
        Log("patterns not found: this game version needs new patterns. Console hook disabled.");
    }

    if (void* present = PresentAddress()) {
        if (MH_CreateHook(present, &hk_present, (void**)&o_present) == MH_OK && MH_EnableHook(present) == MH_OK)
            Log("Present hook on (%p)", present);
        else Log("Present hook FAILED");
    }
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
