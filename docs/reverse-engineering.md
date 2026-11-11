# Reverse engineering

## How the bridge works

- The DLL is named `version.dll` and sits in the HOI4 folder, so the game loads it instead of the system one.
  It forwards every real `version.dll` export to the system DLL and starts its own init thread.
- Clients connect to the named pipe `\\.\pipe\hoi4_console_bridge`, send one message of one or more command
  lines, and get one reply line per command. Commands are queued and run at the next frame on the game's
  render/main thread (the thread the in-game console uses), through the game's own console dispatcher.
- It finds the game's functions by **byte patterns** rather than fixed addresses, and hooks them with
  [MinHook](https://github.com/TsudaKageyu/minhook) (in `deps/`). A patch that only moves code leaves the
  patterns working; a patch that changes the code needs them re-derived. `console_bridge.log` says which
  patterns were not found.
- The `bridge.*` unit orders build the same `CCommand` objects the game builds for a player's or the AI's
  orders and execute them, so the game's own validation applies.

## Helper scripts (`re/`)

Python helpers for working out patterns and structure from the game's exe. Each takes the exe path as its
first argument. Install the dependencies with `pip install -r re/requirements.txt` (pefile, capstone).

| script | does |
|---|---|
| `pe_info.py` | PE headers, sections, imports |
| `strings.py`, `allstrings.py` | find strings in the exe |
| `xrefs.py`, `xrefs_range.py` | find code that references an address (RIP-relative) |
| `callers.py`, `callargs.py`, `callcount.py` | who calls a function, the string literals near each call, call counts |
| `disasm.py` | disassemble at an address |
| `vtable.py` | find the vftables for an RTTI class name |
| `findpat.py`, `mkpattern.py` | search for a byte pattern; build a wildcarded one and check it matches once in `.text` |
| `decompile.py` | Ghidra decompilation of a function (needs Ghidra and `pyghidra`) |

## The RE workbench

Ghidra, x64dbg, the Ghidra project and the exe snapshot are not part of this repo (they hold the game's
binaries). `decompile.py` looks for them in the "RE workbench" folder: set `HOI4_RE_WORKBENCH`, default
`~/hoi4-console-bridge`. It expects Ghidra at `<workbench>/tools/ghidra_12.1.4_PUBLIC`; `HOI4_PROGRAM` picks
the exe snapshot.

Do not commit game binaries or dumps. `.gitignore` excludes `*.exe` and `re/bin/`.
