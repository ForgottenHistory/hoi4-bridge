"""Talk to a running HOI4 that has the console bridge (version.dll) installed.

    python hoi4bridge.py "event streamrewards.1"
    python hoi4bridge.py "pp 100" "manpower 1000"      # several commands, one reply line each

From Python:
    from hoi4bridge import send, setloc, reload_loc_file, player_tag, country_block
    replies = send("tdebug")                  # -> ["OK ..."]  (or "FAIL ...", "ERROR ...")
    text = country_block("GER")               # live save-format text of one country

No window focus or keyboard input is involved; the game does not even need to be in the foreground.
"""

import ctypes
import os
import sys
import time
from ctypes import wintypes

PIPE = r"\\.\pipe\hoi4_console_bridge"

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateFileW.restype = wintypes.HANDLE
_k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                             wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
_k32.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                          wintypes.LPVOID]
_k32.WriteFile.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                           wintypes.LPVOID]
_k32.SetNamedPipeHandleState.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
                                         wintypes.LPVOID]
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_INVALID = wintypes.HANDLE(-1).value
_ERROR_FILE_NOT_FOUND, _ERROR_PIPE_BUSY, _ERROR_MORE_DATA = 2, 231, 234


class BridgeUnavailable(Exception):
    """HOI4 isn't running, or the bridge DLL isn't installed."""


def _open(connect_timeout: float):
    deadline = time.monotonic() + connect_timeout
    while True:
        h = _k32.CreateFileW(PIPE, 0xC0000000, 0, None, 3, 0, None)   # GENERIC_READ|WRITE, OPEN_EXISTING
        if h != _INVALID:
            mode = wintypes.DWORD(2)                                     # PIPE_READMODE_MESSAGE
            _k32.SetNamedPipeHandleState(h, ctypes.byref(mode), None, None)
            return h
        err = ctypes.get_last_error()
        if time.monotonic() >= deadline:
            if err == _ERROR_FILE_NOT_FOUND:
                raise BridgeUnavailable("HOI4 is not running, or the console bridge is not installed")
            raise BridgeUnavailable(f"pipe error {err}")
        time.sleep(0.05)


def _request(payload: bytes, connect_timeout: float) -> str:
    h = _open(connect_timeout)
    try:
        n = wintypes.DWORD()
        if not _k32.WriteFile(h, payload, len(payload), ctypes.byref(n), None):
            raise BridgeUnavailable(f"write failed: {ctypes.get_last_error()}")
        out = bytearray()
        buf = ctypes.create_string_buffer(1 << 20)
        while True:
            ok = _k32.ReadFile(h, buf, len(buf), ctypes.byref(n), None)
            out += buf.raw[:n.value]
            if ok:
                break
            if ctypes.get_last_error() != _ERROR_MORE_DATA:
                raise BridgeUnavailable(f"read failed: {ctypes.get_last_error()}")
        return out.decode("utf-8", "replace")
    finally:
        _k32.CloseHandle(h)


def send(*commands: str, connect_timeout: float = 2.0) -> list[str]:
    """Run console (or bridge.*) commands; one reply line per command."""
    return _request("\n".join(commands).encode("utf-8"), connect_timeout).splitlines()


def setloc(key: str, text: str) -> str:
    """Change one localisation key right away (no reload). Use \\n in text for a line break."""
    return send(f"bridge.setloc {key} {text}".replace("\r", "").replace("\n", "\\n"))[0]


def reload_loc_file(path: str) -> str:
    """Re-read one .yml localisation file and apply its keys, without reloading all localisation."""
    return send(f"bridge.reloadloc {os.path.abspath(path)}")[0]


def player_tag() -> str:
    """Tag of the country the player is playing, e.g. 'GER'."""
    r = send("bridge.player")[0]
    if not r.startswith("OK "):
        raise RuntimeError(r)
    return r[3:].strip()


def country_block(tag: str) -> str:
    """Live save-format text for one country: '\\tTAG={ ... \\t}', as written by the game's own save code."""
    r = _request(f"bridge.country {tag}".encode(), 2.0)
    if not r.startswith("OK "):
        raise RuntimeError(r.strip())
    return r[3:].rstrip("\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    try:
        lines = send(*sys.argv[1:])
    except BridgeUnavailable as e:
        print("ERROR", e)
        sys.exit(1)
    for line in lines:
        print(line)
    sys.exit(0 if all(l.startswith("OK") for l in lines) else 1)
