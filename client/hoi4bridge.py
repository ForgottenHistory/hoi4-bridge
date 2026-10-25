"""Talk to a running HOI4 that has the console bridge (version.dll) installed.

    python hoi4bridge.py "event streamrewards.1"
    python hoi4bridge.py "pp 100" "manpower 1000"      # several commands, one reply line each

From Python:
    from hoi4bridge import send, setloc, reload_loc_file, player_tag, country_block
    replies = send("tdebug")                  # -> ["OK ..."]  (or "FAIL ...", "ERROR ...")
    text = country_block("GER")               # live save-format text of one country
    query('GER = { log = "[THIS.GetLeader]" }')   # -> ["Adolf Hitler"]   (bridge.query, parsed)
    loc("GER_der_fuhrer")                     # -> ["Der Führer"]
    trigger("GER = { has_war_with = POL }")   # -> True / False
    surrender("POL")                          # -> {"progress": 0.62, "occupation": 0.5, "limit": 0.8}
    editbox("my_box"), editbox_set("my_box", "text"), decode_country(value)
A failed bridge command raises BridgeError (BridgeUnavailable if the game isn't reachable).

No window focus or keyboard input is involved; the game does not even need to be in the foreground.
"""

import codecs
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


def _cp1252_fallback(err: UnicodeDecodeError):
    return err.object[err.start:err.end].decode("cp1252", "replace"), err.end


codecs.register_error("hoi4bridge_cp1252", _cp1252_fallback)


def _decode(data: bytes) -> str:
    """Replies are UTF-8, but the game mixes encodings inside its own text (localisation is
    Windows-1252, character names UTF-8) and older bridge builds passed that through unconverted.
    Valid UTF-8 sequences decode as UTF-8; any other byte is read as Windows-1252."""
    return data.decode("utf-8", "hoi4bridge_cp1252")


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
        return _decode(bytes(out))
    finally:
        _k32.CloseHandle(h)


def send(*commands: str, connect_timeout: float = 2.0) -> list[str]:
    """Run console (or bridge.*) commands; one reply line per command."""
    # Split on "\n" only: str.splitlines() would also split on characters replies may contain
    # (\x1c-\x1e separators, \x85,   in localised text).
    reply = _request("\n".join(commands).encode("utf-8"), connect_timeout)
    lines = reply.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line.rstrip("\r") for line in lines]


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


# ---------------------------------------------------------------- reading the bridge's replies

class BridgeError(RuntimeError):
    """A bridge command ran but failed (the reply wasn't OK)."""


SEP = "\x1e"   # separates the items of a bridge.query or bridge.loc reply


def unescape(s: str) -> str:
    """Bridge replies are one line: backslash-n is a line break, a doubled backslash is one backslash."""
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            out.append("\n" if s[i + 1] == "n" else s[i + 1])
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _ok(reply: str) -> str:
    if not reply.startswith("OK"):
        raise BridgeError(reply)
    return reply[3:]


def query(effect: str) -> list[str]:
    """Run an effect (`TAG = { ... }`) and return the lines its `log = "..."` statements printed.
    ROOT inside it is the country selected in the game's UI, so name countries explicitly."""
    body = _ok(send(f"bridge.query {' '.join(effect.split())}")[0])
    # Older bridge builds keep the log stream's trailing line break on each line.
    return [unescape(x).rstrip("\r\n") for x in body.split(SEP)] if body else []


def loc(*keys: str) -> list[str]:
    """Localised text of each key, as the game shows it (a missing key comes back unchanged)."""
    if not keys:
        return []
    vals = [unescape(x) for x in _ok(send("bridge.loc " + " ".join(keys))[0]).split(SEP)]
    return vals + [""] * (len(keys) - len(vals))


def trigger(script: str) -> bool:
    """Evaluate a trigger (`TAG = { ... }`) with the console's eval_trigger: True if it holds."""
    return send(f"eval_trigger {script}")[0].rstrip().endswith("yes")


def surrender(tag: str) -> dict[str, float]:
    """The game's own surrender numbers for a country (as in the war overview tooltip), each 0..1:
    progress (it capitulates at 1), occupation (share of its victory points others control) and limit
    (the occupation at which it capitulates)."""
    out = {}
    for kv in _ok(send(f"bridge.surrender {tag}")[0]).split():
        k, _, v = kv.partition("=")
        try:
            out[k] = float(v)
        except ValueError:
            pass
    return out


def editbox(name: str) -> str:
    """Text of the GUI text box with that .gui name."""
    return unescape(_ok(send(f"bridge.editbox {name}")[0])).strip()


def editbox_set(name: str, text: str = "") -> None:
    """Replace that text box's text (no text clears it)."""
    _ok(send(f"bridge.editbox.set {name} {text}".rstrip().replace("\r", "").replace("\n", "\\n"))[0])


def decode_country(value: float):
    """A country stored in a script variable shows in a save-format block as a packed number (0x40 marker +
    the tag's 3 bytes, divided by 100000). Returns the tag, or None if the value isn't a country."""
    raw = round(value * 100000) & 0xFFFFFFFF
    if raw >> 24 != 0x40:
        return None
    return bytes([raw & 0xFF, (raw >> 8) & 0xFF, (raw >> 16) & 0xFF]).decode("ascii", "replace")


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
