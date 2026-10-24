# hoi4-bridge

A `version.dll` proxy for Hearts of Iron IV that runs console commands sent over a named pipe
(`\\.\pipe\hoi4_console_bridge`). No keystrokes, no window focus. It also adds a few `bridge.*`
commands the console doesn't have (change localisation live, read live country data).

Singleplayer only. Targets the latest HOI4 version (1.19.3 as of 2026-10). It finds game functions
by byte patterns, so it can survive patches. If the log says "patterns not found", re-derive them.

## Build and install

    build.bat bridge     # -> build\version.dll   (MSVC 2022, MinHook in deps/)
    build.bat probe      # observe-only test build
    install.bat          # copy build\version.dll into the HOI4 folder
    uninstall.bat        # remove it

The DLL logs to `console_bridge.log` in the HOI4 folder.

## Client

`client/hoi4bridge.py` (stdlib only):

    python client/hoi4bridge.py "pp 100" "event my_mod.1"     # one reply line per command

    from hoi4bridge import send, setloc, reload_loc_file, player_tag, country_block
    send("tdebug")                 # -> ["OK ..."] / ["FAIL ..."] / ["ERROR ..."]
    setloc("my.key", "New text")   # localisation change, no reload
    country_block("GER")           # live save-format text of one country

### Commands added by the bridge

| command | does |
|---|---|
| `bridge.player` | player's tag |
| `bridge.country TAG` | live save-format block of one country |
| `bridge.setloc KEY text` | set one localisation key (`\n` = line break) |
| `bridge.reloadloc <abs path>` | re-read one `.yml` file |
| `bridge.locinfo` | localisation buffer usage |
| `bridge.editbox NAME` | text of the GUI text box with that .gui name (`\n` = line break, `\\` = backslash) |
| `bridge.editbox.set NAME [text]` | replace that text box's text (no text = clear it) |
| `bridge.editbox.list` | text boxes seen so far, open or closed |

Text boxes are found by hooking the game's text insert function, so a box is known once something has
been typed, pasted or set into it. Its last text is kept after it closes.

### Useful built-in console commands

`eval_effect <script>` compiles and runs any effect script; wrap it as `TAG = { ... }`, because it
otherwise runs on whatever is selected in the UI. Also `eval_trigger`, `effect <tag> <scripted_effect>`,
`set_var`, `set_country_flag`, `reload texture <substring>`.

## Reverse engineering

`re/` holds the helper scripts (pefile + capstone: `pip install -r re/requirements.txt`).
`decompile.py` needs Ghidra. Ghidra, x64dbg, the Ghidra project and the exe snapshot live outside the
repo in the RE workbench (`HOI4_RE_WORKBENCH`, default `C:\Users\Albin\hoi4-console-bridge`).
