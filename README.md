# hoi4-bridge

A `version.dll` proxy for Hearts of Iron IV that runs console commands sent over a named pipe
(`\\.\pipe\hoi4_console_bridge`). No keystrokes, no window focus. It also adds a few `bridge.*`
commands the console doesn't have (change localisation live, read live country data).

Singleplayer only. Targets the latest HOI4 version (1.19.4 as of 2026-10). It finds game functions
by byte patterns, so it can survive patches. If the log says "patterns not found", re-derive them.

## Build and install

    build.bat bridge     # -> build\version.dll   (MSVC 2022, MinHook in deps/)
    build.bat probe      # observe-only test build
    install.bat          # copy build\version.dll into the HOI4 folder
    uninstall.bat        # remove it

The DLL logs to `console_bridge.log` in the HOI4 folder, fresh each launch; the previous launch's log is kept as
`console_bridge.old.log`.

## Client

`client/hoi4bridge.py` (stdlib only):

    python client/hoi4bridge.py "pp 100" "event my_mod.1"     # one reply line per command

    from hoi4bridge import send, setloc, reload_loc_file, player_tag, country_block
    send("tdebug")                 # -> ["OK ..."] / ["FAIL ..."] / ["ERROR ..."]
    setloc("my.key", "New text")   # localisation change, no reload
    country_block("GER")           # live save-format text of one country
    query('GER = { log = "[THIS.GetLeader]" }')   # bridge.query, parsed -> ["Adolf Hitler"]
    loc("GER_der_fuhrer")          # bridge.loc, parsed -> ["Der Führer"]
    trigger("GER = { has_war_with = POL }")   # eval_trigger -> True / False
    surrender("POL")               # bridge.surrender -> {"progress": .., "occupation": .., "limit": ..}
    editbox("box"), editbox_set("box", "text")   # bridge.editbox / .set
    decode_country(value)          # a country stored in a variable, as a save-format block shows it -> tag

A failed command raises `BridgeError`; `BridgeUnavailable` if the game isn't reachable.

### Commands added by the bridge

| command | does |
|---|---|
| `bridge.player` | player's tag |
| `bridge.country TAG` | live save-format block of one country |
| `bridge.surrender TAG` | the game's own surrender numbers, as in the war overview tooltip: `progress=` (capitulation at 1), `occupation=` (share of victory points others control), `limit=` (occupation at which it capitulates) |
| `bridge.setloc KEY text` | set one localisation key (`\n` = line break) |
| `bridge.reloadloc <abs path>` | re-read one `.yml` file |
| `bridge.locinfo` | localisation buffer usage |
| `bridge.query <effect>` | run an effect (`TAG = { ... }`) and return the lines its `log = "..."` statements print, separated by `\x1e` |
| `bridge.loc KEY [KEY ...]` | localised text of each key, separated by `\x1e` (a missing key comes back unchanged) |
| `bridge.treaties [A:B ...]` | the country pairs our own row in the diplomacy view's relations list shows a flag for (replaces the set; none clears it). The row's icon is `GFX_relation_airp_treaty`, its tooltip `AIRP_TREATY_RELATION`, a flag's tooltip `airp_rel_<A>_<B>` (tags in alphabetical order); the mod defines these |
| `bridge.wars [on \| off \| allow [A:B ...] \| attempts]` | with `on`, a war declaration an AI country sends (the diplomacy action, as its AI or a Declare War button would) is dropped unless `A:B` (A may declare on B) is in the allowed set (`allow` replaces it; none clears it). Script declarations (`declare_war_on` in focuses, events, decisions), civil wars, a country joining a faction at war, and the declarations that follow from an allowed one (guarantors, allies) are never stopped, nor the player's own. `attempts`: the dropped declarations since last asked, `A:B=count`, then cleared. No argument: status. Off at game start |
| `bridge.cmdlog [on \| off \| dump \| sample CLASS [N]]` | research: with `on`, points the Execute slot (vtable slot 10) of every `CCommand` class at a counter, so every command the game runs (player and AI: fronts, battle plans, production...) is counted by class; `dump` returns `Class=count` and clears. The first of each class from each caller, and the next N of a class after `sample`, go to the log: caller, fields that read as country ids (`+0x30=ITA`), first 0x88 bytes. Queued commands (AI and player) all run from one caller |
| `bridge.tag ID [ID ...]` | tag of each country id (`16=ITA`; `?` if none). Ids follow the order of `common/country_tags/00_countries.txt`, from 1 |
| `bridge.object TYPE ID` | the game object a handle `{TYPE, ID}` names (commands refer to objects this way; type 53 is an order, i.e. a front or battle plan): its class and the fields that read as country ids |
| `bridge.cmdblock ...` | research: drop commands of a class whose owner is a blocked country. Commands hold no sender, so a rule says where the owner is: `rule CLASS - OFF` (country id at +OFF of the command) or `rule CLASS HOFF OFF` (handle at +HOFF, country id at +OFF of its object); `rule CLASS auto` finds the owner as `bridge.cmdrec` does (first handle with a known owner, in the command or in its `bridge.cmdrec list` lists); `rule CLASS off` removes it. `add TAG ...` / `remove TAG ...` / `clear` set the countries, `dropped` returns `Class:TAG=count` and clears, no argument shows the setup |

| `bridge.cmdrec [on [PATH] \| off \| mark TEXT \| skip CLASS.. \| unskip CLASS.. \| owner TYPE HEXOFF[.HEXOFF..] \| list CLASS PTR COUNT STRIDE \| deref CLASS PTR FIELD \| rules CLASS off]` | research: with `on`, writes every executed command to a file (default `command_record.tsv` in the HOI4 folder), one tab-separated line each: sequence, ms, class, owner tag, how the owner was found, header `+0xc` (1 queued, -1 direct), the handles that resolve, the first 0xa0 bytes as hex; the last column also says `DROPPED` (bridge.cmdblock dropped it) and `DEPTH=N` (it ran inside another command's Execute). The owner comes from a `cmdblock` rule for the class, else the first handle whose type has a known owner offset (`owner TYPE HEXOFF[.HEXOFF..]`, every offset but the last followed as a pointer; defaults 51 division at +0x1c8, 53 order at +0x3c, 67 theatre via its first army `80.0.3c`). `mark TEXT` writes a `#mark` line. A last column holds data behind pointers: the class of each pointer that leads to an object (`P+0x40=CX`), and per-class rules, `list CLASS PTR COUNT STRIDE` (a vector: `L+0x28=[51:3,51:9]`) and `deref CLASS PTR FIELD` (`D+0x40=CProvince.0xa4=6325`); `rules CLASS off` removes them. Built in: the move target (CMove), the division lists of order assign/unassign, the two lists of a new front. A client can stamp the game date with `mark` (e.g. from `bridge.query` with `[GetDateText]`) |

| `bridge.move DIVISION_ID PROVINCE [7 flags]` | orders a division of any country (player or AI) to a province, as the game's own move code does: builds a `CMoveCommand`, runs the game's check, executes it. DIVISION_ID is the id of its handle `{51, id}` (see `bridge.snap`). Flags default to a player's move, `1 2 1 0 0 0 0`. FAIL if the game refuses the move. In the record (`bridge.cmdrec`) such moves carry `SRC=bridge`, and `bridge.cmdblock` never drops them |
| `bridge.rail DIVISION_ID PROVINCE [b i]` | strategic redeployment (by rail) of a division to a province, as the game builds it (`CStrategicRedeploymentCommand`, flags default to the game AI's `1 2`): runs the game's check first, so FAIL when there is no rail route or the unit may not redeploy. `bridge.cmdblock` never drops it |
| `bridge.army create DIVISION_ID.. \| add ARMY_ID DIVISION_ID.. \| group ARMY_ID.. \| assign GROUP_ID ARMY_ID.. \| leader ARMY_ID LEADER_ID` | `add` moves divisions into an existing army (`COrderAssignCommand`, as the army UI sends it). `assign` puts armies into an army group (`CAssignToArmyGroupCommand`). `group` makes an army group of the armies (`CArmyGroupCommand`) and returns its id; give it a field marshal with `leader GROUP_ID LEADER_ID`. `create` builds an army from the given divisions in their theatre (the game's `COrderGroupCommand`, as the army UI sends it) and returns its order id; `leader` makes a unit leader (handle type 4713, as in save files: `id = { id = 390 type = 4713 }`) the army's commander (`CSetArmyLeaderCommand`). Both run the game's own check first; `bridge.cmdblock` never drops them |
| `bridge.plan front ARMY_ID FRONT_ID START END [s=N] [k=N] DIVISION_ID.. \| arrow ARMY_ID [#LINE_ID] PROVINCE[,PROVINCE..] DIVISION_ID.. \| execute ARMY_ID [0\|1] \| delete ARMY_ID LINE_ID.. \| cohesion ARMY_ID 0-3` | battle plans, as the army UI makes them. `front` draws a front line for the army on a stretch of a `CFront` (handle type 66: a border between one of our areas and an enemy area; its +0x58 lists its sections, connected stretches with our provinces in order at +0x30), START..END in thousandths of a percent along the sections in turn (`COrderNewRootCommand`). `arrow` draws an offensive line through the provinces, the last one its target, on the front line with that id (else the first one the game accepts) (`COrderNewFrontCommand`). `execute` starts (1) or stops (0) the plan (`COrderExecuteCommand`); `delete` removes the army's lines with those ids (`COrderDeleteCommand`); an army's lines are the `COrderInstance`s listed at its +0x98, id at +0x244. `cohesion` sets how the army keeps to its plan (`CSetOrderGroupCohesionTypeCommand`): 0 flexible, 1 balanced, 2 rigid, 3 immobile (planning builds, but the game doesn't move the divisions). Divisions are the army's. Built from recorded commands; the game's check runs first |
| `bridge.stop DIVISION_ID..` | calls off a division's movement or attack with the game's own CancelMovement (works on protected divisions) |
| `bridge.protect [add ID.. \| remove ID.. \| clear \| callers]` | keeps the game from stopping the given divisions (handle ids), so a `bridge.move` isn't undone by the AI (its `CCancelMovementCommand` lists the divisions, so `bridge.cmdblock` can't tell whose they are). Hooks the unit's ClearPath and CancelMovement; moves the bridge sends still use them. `callers`: the game code whose calls were refused (`hoi4+rva=count`), then cleared |
| `bridge.watch ADDR \| div ID HEXOFF \| hits \| off` | research: a hardware write watchpoint (debug register 0, 4 bytes) on every game thread; `div ID OFF` watches a field of a division's full object (handle object - 0x10). `hits`: each writing instruction `hoi4+rva xCOUNT <return addresses found on the stack>` |
| `bridge.mem ADDR LEN` | research: LEN (up to 0x1000) bytes at hex ADDR as hex, `?` for unreadable ones. `bridge.object` gives an object's address, and the fields of it that point to objects with their class (`P+0x1e0=CProvince`) |
| `bridge.snap LABEL TYPE [class=CName] FIELD...` | research: appends a `#snap` line and then one line per object of handle TYPE (of that class) to `unit_snapshots.tsv` in the HOI4 folder: its id and each FIELD. A FIELD is a kind (`i` int, `f` float, `b` byte, `c` country id as tag, `s` std::string, `x` 64-bit hex) and hex offsets, every one but the last followed as a pointer: `i1e0.a4` is the int at +0xa4 of what +0x1e0 points to. `bridge.snap reset [PATH]` empties the file (or picks another). Divisions (`51 class=CArmy`): owner `c1c8`, province `i1e0.a4`, order id `ib0.c`, organisation `i20`/`i28`/`i78`, strength `i30` (100000 = 100%), template name `s3a8.20`. |

Command samples (`bridge.cmdlog`) also list each handle a command holds, with its object's class and country fields.

`bridge.query` makes script a query language: `log` formats with the game's own localisation, so
`GER = { every_neighbor_country = { log = "[THIS.GetTag] [THIS.GetLeader]" } }` returns one line per neighbour.
It hooks the game's logger, so the lines also still reach game.log.
| `bridge.editbox NAME` | text of the GUI text box with that .gui name (`\n` = line break, `\\` = backslash) |
| `bridge.editbox.set NAME [text]` | replace that text box's text (no text = clear it) |
| `bridge.editbox.list` | text boxes seen so far, open or closed |
| `bridge.editbox.multiline NAME [off]` | Enter inserts a line break in that box (.gui can't set this) |
| `bridge.editbox.mirror NAME PAGE` | show the box's whole text in the instant text box PAGE, live (`off` to stop) |

A text box only ever draws the line with the cursor, so for multi-line input pair it with a page:
the bridge hooks `CInstantTextBox::SetText` to find PAGE by name and sets the box's text on it each
frame it changes (the page's own .gui text shows while the box is empty).

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
