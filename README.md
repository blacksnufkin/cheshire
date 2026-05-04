![Cheshire Logo](assets/Cheshire_logo.png)
# Cheshire

**Pre-flight payload QA for Adaptix, powered by LitterBox.**

Cheshire is an Adaptix C2 service plugin that bridges the Adaptix client to a
[LitterBox](https://github.com/BlackSnufkin/LitterBox) sandbox. From inside
the Adaptix UI, an operator can pick any binary, dispatch it through
LitterBox's full analyzer chain (static + dynamic + every reachable EDR
profile), and watch the verdict materialize without ever leaving Adaptix.

The name follows the project mascot lineage:

- Adaptix → chameleon
- LitterBox → grumpy cat
- The bridge between them → **Cheshire** (the cat that grins, fades in and
  out of view, and tells you whether the path ahead is safe).

---

## What it does

| Action            | LitterBox endpoint(s)                                | Result |
|-------------------|------------------------------------------------------|--------|
| Upload payload    | `POST /upload`                                       | md5 + file metadata |
| Run All           | `POST /analyze/static/<md5>` + `/analyze/dynamic/<md5>` + `/analyze/edr/<profile>/<md5>` (×N profiles) in parallel goroutines | Static, Dynamic, every EDR profile populated as each completes |
| Static only       | `/analyze/static/<md5>`                              | YARA / CheckPlz / Stringnalyzer findings |
| Dynamic only      | `/analyze/dynamic/<md5>`                             | YARA-mem / PE-Sieve / Moneta / Patriot / HSB / RedEdr findings |
| EDR (multi)       | `/analyze/edr/<profile>/<md5>` per profile + Phase 2 polling on `/api/results/edr/<profile>/<md5>` | Per-profile alerts table + comprehensive alert detail (reason, MITRE, API, memory region, call stack, final user module, process, parent, EDR responses) |
| Cleanup           | `DELETE /file/<md5>`                                 | Removes upload + result folders + per-sample analysis dirs from LitterBox |
| Fleet probe       | `GET /health`                                        | Sandbox status, scanner inventory, EDR agent reachability — drives the EDR Profiles checkboxes |

EDR Phase 2 polling uses LitterBox's adaptive cadence (2s base, ×1.5 backoff
up to 15s when the alert count is stable, snap back to 2s on movement).
Each poll tick streams a `progress` event to the client so the live progress
strip can show alert counts ticking up in real time.

---

## Layout

```
Cheshire/
├── README.md
├── setup_cheshire.sh                       deploy script
└── cheshire_service/
    ├── config.yaml                         service plugin manifest + litterbox_url
    ├── go.mod / go.sum
    ├── Makefile                            builds dist/service_cheshire.so
    ├── pl_main.go                          Go service plugin (HTTP client to LitterBox)
    └── ax_config.axs                       AXScript UI (the dashboard dialog)
```

The Go plugin is a stateless HTTP relay between Adaptix's
`TsServiceSendDataClient` and LitterBox's REST API. The AXScript file owns
all rendering — verdict banner, detection summary, per-scanner sub-tabs,
EDR alerts table with click-to-detail.

---

## Setup

### 1. Bring up LitterBox

Cheshire requires a running LitterBox instance (see the
[LitterBox repo](https://github.com/BlackSnufkin/LitterBox) for installation).
Confirm reachability:

```sh
curl http://<litterbox-host>:1337/health
```

### 2. Configure Cheshire

Edit `cheshire_service/config.yaml` and set `litterbox_url`:

```yaml
extender_type: "service"
extender_file: "service_cheshire.so"
ax_file: "ax_config.axs"

service_name: "cheshire"
service_config: |
  litterbox_url: "http://192.168.88.128:1337"
```

If `litterbox_url` is missing the plugin loads but every operator command
returns `"Cheshire is not configured: set litterbox_url in service_config"`.
There is no fallback default.

### 3. Deploy

```sh
bash setup_cheshire.sh --ax /path/to/AdaptixC2
```

This:

1. Copies the source to `AdaptixC2/AdaptixServer/extenders/cheshire_service/`.
2. Adds `./extenders/cheshire_service` to the Go workspace.
3. Builds `service_cheshire.so` via the Makefile.
4. Copies the built `.so` + `config.yaml` + `ax_config.axs` to
   `AdaptixC2/dist/extenders/cheshire_service/`.

### 4. Register with the Adaptix server

Add a line to `AdaptixC2/dist/profile.yaml` under
`Teamserver.extenders`:

```yaml
extenders:
  - "extenders/cheshire_service/config.yaml"
  ...
```

### 5. Restart the server

```sh
pkill -f adaptixserver
cd AdaptixC2/dist
./adaptixserver -profile profile.yaml
```

You should see `[cheshire] Initialized — LitterBox at http://...` in the
server log, followed by `[+] Service 'cheshire' loaded`.

In the Adaptix client menu bar, **Cheshire → Test with Cheshire** opens the
dashboard.

---

## Dashboard

```
┌─ Payload ───────────────────────────────────────────────────────────────┐
│  [Browse...]  /home/op/payloads/beacon.exe                              │
├─ EDR Profiles ──────────────────────────────────────────────────────────┤
│  ☑ Elastic Defend   ● reachable     elastic · WIN-VM01 · nightcity      │
│  ☐ Fibratus         ● not reachable fibratus                            │
├─ Dynamic Analysis Args ─────────────────────────────────────────────────┤
│  --quiet -p 4444                                                        │
├─────────────────────────────────────────────────────────────────────────┤
│  [Run All] | [Static] [Dynamic] [EDR] | [Cleanup]    Uploaded: ...      │
├─────────────────────────────────────────────────────────────────────────┤
│  🚫 DETECTED — 5 hit(s) across 2 Static, 1 Dynamic [CRITICAL]           │
│                                              ✓ Static  ✓ Dynamic  🔄 elastic (2) │
├─ Detection Summary ─────────────────────────────────────────────────────┤
│  Severity  | Scanner             | Detection         | Detail           │
│  CRITICAL  | Static · CheckPlz   | Trojan:Win64/...  | offset 0x20EF    │
│  CRITICAL  | Static · YARA       | mimikatz_strings  | matched $sek...  │
│  HIGH      | Dynamic · PE-Sieve  | 3 modifications   | 3 IAT hooks      │
│  ...                                                                    │
├─ Static | Dynamic | EDR ────────────────────────────────────────────────┤
│  per-scanner sub-tabs with stat strip + bordered finding cards          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Verdict + scope

- `⏳ RUNNING — N hit(s) so far` while any scheduled scanner is in flight.
- `🚫 DETECTED — N hit(s) across X Static, Y Dynamic, Z EDR [maxSev]` once
  every scheduled scanner reaches a terminal state.
- `✓ CLEAN — 0 critical/high/medium detections` only if no real hits at any
  scanner. Informational signals (LOW/INFO) are noted separately, not in
  the headline.
- `(Static only)` / `(Dynamic + EDR)` etc. is appended when the operator
  runs an individual scanner instead of Run All — the verdict honestly
  reflects what was actually executed.

### Detection Summary

Aggregates **every** detection across every scanner into one sortable table.
Rows are extracted from the actual JSON LitterBox returns (not generic
factor strings):

- YARA / YARA-mem rules with severity + threat name + first matched string identifier
- CheckPlz `initial_threat` + `scan_results.detection_offset`
- Stringnalyzer dangerous-category counts
- PE-Sieve `total_suspicious` + per-indicator counts
- Moneta non-zero `total_*` anomaly counts (Private RWX → CRITICAL, etc.)
- Patriot per-finding `level` + `type` + first 120 chars of `details`
- HSB per-finding severity + type + thread id
- RedEdr Defender events filtered to `category === 'threat'`
- EDR alerts: rule + severity + process + API summary

Sorted by severity descending, then scanner name.

### Auto-cleanup

When the dialog closes, the current sample's md5 is wiped from LitterBox
via `DELETE /file/<md5>`. No stale samples accumulate between engagements.

---

## Architecture

```
Adaptix Client (Qt) ──┐
                      │ AXScript service_command("cheshire", "run_all", {...})
                      ▼
Adaptix Server  ──→  service_cheshire.so  ──HTTP──→  LitterBox  ──→  EDR VM
  │                                                       │              │
  │                    streams progress events        Static / Dynamic   │
  │                    + results back via             scanners run on    │
  │                    TsServiceSendDataClient        the LitterBox host │
  ▼                                                       │              │
Adaptix Client renders verdict, detection summary,        │     EDR profile
progress strip, per-scanner detail panels.                ▼     dispatches
                                                  /analyze/edr/<P>/<md5>
                                                  Phase 1: exec on EDR VM
                                                  Phase 2: poll Elastic
                                                          for alerts
```

The Go service plugin runs each scanner dispatch in its own goroutine, so
Run All issues Static + Dynamic + (one POST per EDR profile) all in
parallel. The AXScript dashboard updates live as each goroutine streams
back `progress` and result events.

---

## License

Cheshire follows the LitterBox / Adaptix conventions. See the parent project
licenses for details.
