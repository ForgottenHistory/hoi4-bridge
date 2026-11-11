# hoi4-bridge

A `version.dll` proxy for Hearts of Iron IV that runs console commands sent over a named pipe
(`\.\pipe\hoi4_console_bridge`). No keystrokes, no window focus. It also adds `bridge.*` commands the
console doesn't have: read live country data, run script as a query, change localisation live, and issue
unit orders (moves, armies, battle plans) for any country.

- **Singleplayer only.** Don't use it in multiplayer.
- Windows, Steam version, 64-bit. Targets the latest HOI4 (1.19.4 as of 2026-10).
- Game functions are found by byte patterns, so it can survive patches. If the log says
  "patterns not found", the patterns need re-deriving (see [docs/reverse-engineering.md](docs/reverse-engineering.md)).

Used by [hoi4-custom-ai](https://github.com/ForgottenHistory/hoi4-custom-ai), which drives the game's army from Python.

> This is an unofficial modding/research tool and is not affiliated with Paradox Interactive.
> It modifies a running game process; use it at your own risk and keep a backup of your saves.

## Quick start

Requirements: MSVC 2022 (to build), Python 3 (for the client; stdlib only). The first build downloads
[MinHook](https://github.com/TsudaKageyu/minhook) 1.3.4 into `deps/minhook/` (checked against a pinned SHA-256).

    build.bat bridge     # -> build\version.dll
    install.bat          # copies it into the HOI4 folder
    # start the game, then:
    python client\hoi4bridge.py "bridge.player" "pp 100"

`install.bat` and `uninstall.bat` use the default Steam path
(`C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV`); set `HOI4_DIR` to use another folder.
`build.bat probe` builds an observe-only test DLL instead.

The DLL writes `console_bridge.log` in the HOI4 folder, fresh each launch (the previous one is kept as
`console_bridge.old.log`). Check it first if something doesn't work.

## Client

`client/hoi4bridge.py` is a stdlib-only Python client.

    python client/hoi4bridge.py "pp 100" "event my_mod.1"     # one reply line per command

```python
from hoi4bridge import send, setloc, player_tag, country_block, query, trigger

send("tdebug")                          # -> ["OK ..."] / ["FAIL ..."] / ["ERROR ..."]
setloc("my.key", "New text")            # localisation change, no reload
country_block("GER")                    # live save-format text of one country
query('GER = { log = "[THIS.GetLeader]" }')   # -> ["Adolf Hitler"]
trigger("GER = { has_war_with = POL }")       # -> True / False
```

A failed command raises `BridgeError`; `BridgeUnavailable` if the game isn't reachable.
More helpers (`loc`, `surrender`, `editbox`, `editbox_set`, `decode_country`, `reload_loc_file`) are in the file.

## What it adds

| area | commands | docs |
|---|---|---|
| Game state | `bridge.player`, `bridge.country`, `bridge.surrender`, `bridge.tag`, `bridge.pause` | [commands](docs/commands.md#game-state) |
| Script as a query | `bridge.query` (run an effect, get its `log` lines back) | [commands](docs/commands.md#script-queries) |
| Localisation | `bridge.setloc`, `bridge.reloadloc`, `bridge.loc`, `bridge.locinfo` | [commands](docs/commands.md#localisation) |
| Text boxes | `bridge.editbox*` | [commands](docs/commands.md#text-boxes) |
| Unit orders | `bridge.move`, `bridge.rail`, `bridge.army`, `bridge.plan`, `bridge.stop`, `bridge.protect` | [commands](docs/commands.md#unit-orders) |
| AI and diplomacy control | `bridge.wars`, `bridge.treaties`, `bridge.cmdblock` | [commands](docs/commands.md#controlling-what-the-ai-does) |
| Research tools | `bridge.cmdlog`, `bridge.cmdrec`, `bridge.snap`, `bridge.object`, `bridge.mem`, `bridge.watch` | [commands](docs/commands.md#research-tools) |

Useful built-in console commands: `eval_effect <script>` compiles and runs any effect script (wrap it as
`TAG = { ... }`, otherwise it runs on whatever is selected in the UI), plus `eval_trigger`,
`effect <tag> <scripted_effect>`, `set_var`, `set_country_flag`, `reload texture <substring>`.

## Docs

- [docs/commands.md](docs/commands.md): every `bridge.*` command
- [docs/reverse-engineering.md](docs/reverse-engineering.md): how the bridge finds the game's code, and the `re/` helper scripts

## Layout

    src/        bridge.cpp (the DLL), probe.cpp (observe-only build)
    client/     hoi4bridge.py
    re/         reverse-engineering helper scripts
    deps/       fetch_minhook.ps1, and MinHook's license (the library itself is downloaded)
    build.bat, install.bat, uninstall.bat

## License

MIT, see [LICENSE](LICENSE). MinHook is BSD-2-Clause, see [deps/minhook/LICENSE.txt](deps/minhook/LICENSE.txt).
