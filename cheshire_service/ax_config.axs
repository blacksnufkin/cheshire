// ════════════════════════════════════════════════════════════════════════════
//  Cheshire — Adaptix × LitterBox payload QA dashboard
// ════════════════════════════════════════════════════════════════════════════

// ── State ────────────────────────────────────────────────────────────────────

var W = {};            // namespaced widget refs
var S = { md5: null, fileName: null, fileInfo: null,
          // detections accumulated across scanners — array of objects
          // { sev, scanner, name, detail }. Cleared per-scope on standalone runs.
          detections: { static: [], dynamic: [], edr: {} },
          // EDR per-profile sub-tab refs
          edrTabs: {},
          // last run scope: tracks which scanners ran so verdict banner
          // can display "Static-only run", "Dynamic + EDR", etc.
          ranScope: { static: false, dynamic: false, edr: {} } };
var pendingAction = null;
var dialogOpen = false;

// ── Constants ────────────────────────────────────────────────────────────────

var COL_CRITICAL = "#FF4444";
var COL_HIGH     = "#FF8800";
var COL_MEDIUM   = "#FFD700";
var COL_LOW      = "#4CAF50";
var COL_INFO     = "#5DA8E8";
var COL_DIM      = "#888";
var COL_OK       = "#4CAF50";
var COL_BAD      = "#F44336";
var COL_WARN     = "#FF9800";

var SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

// ── Entry ────────────────────────────────────────────────────────────────────

function InitService() {
    let action = menu.create_action("Test with Cheshire", function() {
        showCheshireDialog();
    });
    let cheshireMenu = menu.create_menu("Cheshire");
    cheshireMenu.addItem(action);
    menu.add_main(cheshireMenu);
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function asArr(x) { return Array.isArray(x) ? x : []; }
function asStr(x) { return (x === null || x === undefined) ? "" : String(x); }

function sevColor(sev) {
    let s = String(sev || "").toUpperCase();
    if (s === "CRITICAL") return COL_CRITICAL;
    if (s === "HIGH")     return COL_HIGH;
    if (s === "MEDIUM" || s === "MID") return COL_MEDIUM;
    if (s === "LOW")      return COL_LOW;
    if (s === "INFO")     return COL_INFO;
    return COL_DIM;
}

// Normalize severity to {CRITICAL,HIGH,MEDIUM,LOW,INFO} across scanner conventions.
function normSev(scanner, raw) {
    if (scanner === "yara") {
        let n = parseInt(raw) || 0;
        return n >= 100 ? "CRITICAL" :
               n >= 80  ? "HIGH"     :
               n >= 50  ? "MEDIUM"   :
               n >= 20  ? "LOW"      : "INFO";
    }
    if (scanner === "checkplz") return raw ? "CRITICAL" : "INFO";
    if (scanner === "rededr_defender") return raw === "threat" ? "CRITICAL" : "INFO";
    let s = String(raw || "").toUpperCase();
    if (s === "MID") return "MEDIUM";
    if (SEV_RANK[s] === undefined) return "INFO";
    return s;
}

function setStatus(text, color) {
    if (W.status) W.status.setText("<b style='color:" + color + "'>" + text + "</b>");
}

function setBtnsEnabled(b) {
    if (W.runAll)     W.runAll.setEnabled(b);
    if (W.runStatic)  W.runStatic.setEnabled(b);
    if (W.runDynamic) W.runDynamic.setEnabled(b);
    if (W.runEdr)     W.runEdr.setEnabled(b);
}

function selectedProfiles() {
    let names = [];
    for (let n in W.profileChecks) if (W.profileChecks[n].isChecked()) names.push(n);
    return names;
}

function ensureUploaded(cb) {
    if (S.md5) { cb(); return; }
    let path = W.filePath.text();
    if (!path || path.indexOf("No file") >= 0) {
        ax.show_message("Cheshire", "Select a payload file first.");
        return;
    }
    setStatus("Uploading...", COL_WARN);
    setBtnsEnabled(false);
    pendingAction = cb;
    ax.service_command("cheshire", "submit", { file_path: path });
}

function parseArgs(s) {
    if (!s) return [];
    let p = s.split(/\s+/);
    let out = [];
    for (let i = 0; i < p.length; i++) if (p[i].length > 0) out.push(p[i]);
    return out;
}

function fmtJSON(o) { try { return JSON.stringify(o, null, 2); } catch(e) { return String(o); } }

// Render a LitterBox-style stat strip into a label widget.
// items: [{label, value, severity}] where severity is "clean" | "critical" | "medium" | "info"
function renderStatStrip(label, items) {
    if (!label) return;
    let html = "<table cellspacing='4' cellpadding='4' style='margin:2px 0;'><tr>";
    for (let i = 0; i < items.length; i++) {
        let it = items[i];
        let val = (it.value === null || it.value === undefined) ? "0" : String(it.value);
        let sev = it.severity || "info";
        let isHit = sev === "critical" ||
                    (typeof it.value === "number" && it.value > 0 && sev !== "info" && sev !== "clean");
        let valColor;
        if (sev === "clean")    valColor = COL_OK;
        else if (sev === "critical") valColor = COL_CRITICAL;
        else if (sev === "medium")   valColor = COL_MEDIUM;
        else                         valColor = "#D0D0D0";

        let bdr = isHit ? COL_CRITICAL : "#444";
        html += "<td style='border:1px solid " + bdr + ";padding:5px 10px;'>" +
                "<div style='color:#888;font-size:8pt;'>" + it.label + "</div>" +
                "<div style='color:" + valColor + ";font-size:11pt;font-weight:bold;'>" + val + "</div>" +
                "</td>";
    }
    html += "</tr></table>";
    label.setText(html);
}

// Render an indicator-breakdown grid (3xN) where each cell shows label+count;
// cells with count > 0 get a critical-colored border.
function renderBreakdown(label, items) {
    if (!label) return;
    let html = "<table cellspacing='4' cellpadding='4' style='margin:6px 0;'>";
    let perRow = 3;
    for (let i = 0; i < items.length; i += perRow) {
        html += "<tr>";
        for (let j = 0; j < perRow && (i + j) < items.length; j++) {
            let it = items[i + j];
            let v = parseInt(it.value) || 0;
            let bdr = v > 0 ? COL_CRITICAL : "#444";
            let valCol = v > 0 ? COL_CRITICAL : "#D0D0D0";
            html += "<td style='border:1px solid " + bdr + ";padding:6px 10px;width:30%;'>" +
                    "<div style='color:#888;font-size:9pt;'>" + it.label + "</div>" +
                    "<div style='color:" + valCol + ";font-family:monospace;font-size:13pt;font-weight:bold;'>" + v + "</div>" +
                    "</td>";
        }
        html += "</tr>";
    }
    html += "</table>";
    label.setText(html);
}

// ── Main dialog ──────────────────────────────────────────────────────────────

function showCheshireDialog() {
    W = {};
    S = { md5: null, fileName: null, fileInfo: null,
          detections: { static: [], dynamic: [], edr: {} },
          edrTabs: {},
          ranScope: { static: false, dynamic: false, edr: {} } };
    pendingAction = null;
    dialogOpen = true;

    // ── Payload ──────────────────────────────────────────────────────────────
    let fileGroup = form.create_groupbox("Payload", false);
    W.filePath = form.create_label("<i style='color:#888'>No file selected</i>");
    let browseBtn = form.create_button("Browse...");
    form.connect(browseBtn, "clicked", function() {
        let path = ax.prompt_open_file("Select payload", "All Files (*)");
        if (path && path.length > 0) {
            W.filePath.setText(path);
            S.md5 = null; S.fileName = null; S.fileInfo = null;
            resetEverything();
            setStatus("File selected", COL_DIM);
        }
    });
    let fl = form.create_hlayout();
    fl.addWidget(browseBtn);
    fl.addWidget(W.filePath);
    fl.addWidget(form.create_hspacer());
    let fp = form.create_panel(); fp.setLayout(fl);
    fileGroup.setPanel(fp);

    // ── EDR Profiles ─────────────────────────────────────────────────────────
    let profGroup = form.create_groupbox("EDR Profiles", false);
    W.fleetLabel = form.create_label("<i style='color:#888'>loading fleet...</i>");
    W.profilesPanel = form.create_panel();
    W.profileChecks = {};
    let pl = form.create_vlayout();
    pl.addWidget(W.fleetLabel);
    pl.addWidget(W.profilesPanel);
    let pp = form.create_panel(); pp.setLayout(pl);
    profGroup.setPanel(pp);

    // ── Dynamic args ─────────────────────────────────────────────────────────
    let dynGroup = form.create_groupbox("Dynamic Analysis Args", false);
    W.dynArgs = form.create_textline();
    W.dynArgs.setPlaceholder("Optional space-separated args passed to the binary at runtime");
    let dl = form.create_hlayout();
    dl.addWidget(W.dynArgs);
    let dp = form.create_panel(); dp.setLayout(dl);
    dynGroup.setPanel(dp);

    // ── Run bar ──────────────────────────────────────────────────────────────
    W.status     = form.create_label("<b style='color:#888'>Ready</b>");
    W.runAll     = form.create_button("Run All");
    W.runStatic  = form.create_button("Static");
    W.runDynamic = form.create_button("Dynamic");
    W.runEdr     = form.create_button("EDR");
    W.cleanup    = form.create_button("Cleanup");
    W.cleanup.setEnabled(false);

    form.connect(W.runAll,     "clicked", runAll);
    form.connect(W.runStatic,  "clicked", runStatic);
    form.connect(W.runDynamic, "clicked", runDynamic);
    form.connect(W.runEdr,     "clicked", runEdr);
    form.connect(W.cleanup,    "clicked", function() {
        if (!S.md5) return;
        setStatus("Cleaning up...", COL_DIM);
        ax.service_command("cheshire", "cleanup", { md5: S.md5 });
    });

    let bl = form.create_hlayout();
    bl.addWidget(W.runAll);
    bl.addWidget(form.create_label("<span style='color:#444'>|</span>"));
    bl.addWidget(W.runStatic);
    bl.addWidget(W.runDynamic);
    bl.addWidget(W.runEdr);
    bl.addWidget(form.create_label("<span style='color:#444'>|</span>"));
    bl.addWidget(W.cleanup);
    bl.addWidget(form.create_hspacer());
    bl.addWidget(W.status);
    let bp = form.create_panel(); bp.setLayout(bl);

    // ── Verdict (compact, inline label — no group wrapper) ───────────────────
    W.verdictBanner = form.create_label(
        "<span style='color:#888;'><i>Select a payload and click Run All to begin.</i></span>"
    );

    // ── Live progress (compact, no group wrapper) ────────────────────────────
    W.progressLabel = form.create_label("<span style='color:#666;font-size:9pt;'>(no scanners running)</span>");
    S.progress = {};

    // Verdict + progress live side-by-side in one strip to save vertical space.
    let stripLayout = form.create_hlayout();
    stripLayout.addWidget(W.verdictBanner);
    stripLayout.addWidget(form.create_hspacer());
    stripLayout.addWidget(W.progressLabel);
    let stripPanel = form.create_panel(); stripPanel.setLayout(stripLayout);

    // ── Detection summary (the hero) ─────────────────────────────────────────
    let summaryGroup = form.create_groupbox("Detection Summary", false);
    W.summaryTable = form.create_table(["Severity", "Scanner", "Detection", "Detail"]);
    W.summaryTable.setSortingEnabled(true);
    let sl = form.create_vlayout();
    sl.addWidget(W.summaryTable);
    let sp = form.create_panel(); sp.setLayout(sl);
    summaryGroup.setPanel(sp);

    // ── Deep-dive tabs (the rest) ────────────────────────────────────────────
    W.topTabs = form.create_tabs();
    W.topTabs.addTab(buildStaticPanel(),  "Static");
    W.topTabs.addTab(buildDynamicPanel(), "Dynamic");
    W.topTabs.addTab(buildEdrPanel(),     "EDR");

    // ── Final layout ─────────────────────────────────────────────────────────
    let main = form.create_vlayout();
    main.addWidget(fileGroup);
    main.addWidget(profGroup);
    main.addWidget(dynGroup);
    main.addWidget(bp);
    main.addWidget(stripPanel);
    main.addWidget(summaryGroup);
    main.addWidget(W.topTabs);

    let dialog = form.create_dialog("Cheshire — LitterBox QA");
    dialog.setSize(1400, 1050);
    dialog.setLayout(main);
    dialog.setButtonsText("", "Close");

    ax.service_command("cheshire", "get_health", {});
    dialog.exec();

    // Auto-cleanup on close: nuke the sample from LitterBox so we don't
    // leave stale files between runs.
    if (S.md5) {
        ax.service_command("cheshire", "cleanup", { md5: S.md5 });
    }

    W = {}; S = {}; pendingAction = null; dialogOpen = false;
}

// ── Tab builders ─────────────────────────────────────────────────────────────

function mkText(placeholder) {
    let t = form.create_textmulti();
    t.setReadOnly(true);
    if (placeholder) t.setPlaceholder(placeholder);
    return t;
}
function wrap(t) {
    let lay = form.create_vlayout();
    lay.addWidget(t);
    let p = form.create_panel(); p.setLayout(lay);
    return p;
}

// Build a scanner sub-tab: stat strip on top + scrollable HTML label for
// details below. We use a label-in-scrollarea (not textmulti) because Qt's
// QPlainTextEdit does NOT render HTML/colors/bold — labels do, and the
// scrollarea handles overflow when content gets long.
function buildScannerTab(placeholder) {
    let stats = form.create_label("");
    let body  = form.create_label(placeholder ?
        "<i style='color:#666;font-size:10pt;'>" + placeholder + "</i>" : "");

    let bodyInner = form.create_panel();
    let bil = form.create_vlayout();
    bil.addWidget(body);
    bil.addWidget(form.create_vspacer());
    bodyInner.setLayout(bil);

    let scroll = form.create_scrollarea();
    scroll.setPanel(bodyInner);
    scroll.setWidgetResizable(true);

    let outerLay = form.create_vlayout();
    outerLay.addWidget(stats);
    outerLay.addWidget(scroll);
    let outer = form.create_panel(); outer.setLayout(outerLay);
    return { panel: outer, stats: stats, body: body };
}

// HTML helpers
function htmlEsc(s) {
    if (s === null || s === undefined) return "";
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function tagSev(sev) {
    let col = sevColor(sev);
    return "<span style='color:" + col + ";font-weight:bold;font-size:9pt;'>[" + sev + "]</span>";
}

function sectionHeader(title) {
    return "<div style='font-size:10pt;font-weight:bold;color:#E0E0E0;margin-top:10px;margin-bottom:4px;border-bottom:1px solid #444;padding-bottom:2px;'>" +
           htmlEsc(title) + "</div>";
}

function kvRowHtml(k, v) {
    return "<tr><td style='color:#888;padding:2px 12px 2px 0;font-size:10pt;'>" + htmlEsc(k) +
           "</td><td style='color:#D0D0D0;font-family:monospace;font-size:10pt;'>" + htmlEsc(v) + "</td></tr>";
}

function buildStaticPanel() {
    let tabs = form.create_tabs();
    W.staticYara         = buildScannerTab("YARA rule matches.");
    W.staticCheckplz     = buildScannerTab("CheckPlz AV signature scan.");
    W.staticStringnalyzer= buildScannerTab("Stringnalyzer findings.");
    tabs.addTab(W.staticYara.panel,          "YARA");
    tabs.addTab(W.staticCheckplz.panel,      "CheckPlz");
    tabs.addTab(W.staticStringnalyzer.panel, "Stringnalyzer");
    let lay = form.create_vlayout();
    lay.addWidget(tabs);
    let p = form.create_panel(); p.setLayout(lay);
    return p;
}

function buildDynamicPanel() {
    let tabs = form.create_tabs();
    W.dynYara    = buildScannerTab("YARA-mem matches.");
    W.dynPesieve = buildScannerTab("PE-Sieve memory modifications.");
    W.dynMoneta  = buildScannerTab("Moneta memory anomalies.");
    W.dynPatriot = buildScannerTab("Patriot behavior indicators.");
    W.dynHsb     = buildScannerTab("Hunt Sleeping Beacons.");
    W.dynRedEdr  = buildScannerTab("RedEdr telemetry.");
    tabs.addTab(W.dynYara.panel,    "YARA-mem");
    tabs.addTab(W.dynPesieve.panel, "PE-Sieve");
    tabs.addTab(W.dynMoneta.panel,  "Moneta");
    tabs.addTab(W.dynPatriot.panel, "Patriot");
    tabs.addTab(W.dynHsb.panel,     "HSB");
    tabs.addTab(W.dynRedEdr.panel,  "RedEdr");
    let lay = form.create_vlayout();
    lay.addWidget(tabs);
    let p = form.create_panel(); p.setLayout(lay);
    return p;
}

function buildEdrPanel() {
    W.edrEmpty = form.create_label(
        "<i style='color:#888;padding:8px;'>" +
        "No EDR runs yet. Select profiles above and click <b>EDR</b> or <b>Run All</b>." +
        "</i>"
    );
    W.edrTabs = form.create_tabs();
    let lay = form.create_vlayout();
    lay.addWidget(W.edrEmpty);
    lay.addWidget(W.edrTabs);
    let p = form.create_panel(); p.setLayout(lay);
    return p;
}

// ── State management ─────────────────────────────────────────────────────────

function clearScannerTab(t) {
    if (!t) return;
    if (t.stats) t.stats.setText("");
    if (t.body)  t.body.setText("");
}

function resetEverything() {
    S.detections = { static: [], dynamic: [], edr: {} };
    S.ranScope = { static: false, dynamic: false, edr: {} };
    redrawSummary();
    updateVerdict();
    clearScannerTab(W.staticYara);
    clearScannerTab(W.staticCheckplz);
    clearScannerTab(W.staticStringnalyzer);
    clearScannerTab(W.dynYara);
    clearScannerTab(W.dynPesieve);
    clearScannerTab(W.dynMoneta);
    clearScannerTab(W.dynPatriot);
    clearScannerTab(W.dynHsb);
    clearScannerTab(W.dynRedEdr);
}

function clearScopeStatic() {
    S.detections.static = [];
    S.ranScope.static = false;
    clearScannerTab(W.staticYara);
    clearScannerTab(W.staticCheckplz);
    clearScannerTab(W.staticStringnalyzer);
}
function clearScopeDynamic() {
    S.detections.dynamic = [];
    S.ranScope.dynamic = false;
    clearScannerTab(W.dynYara);
    clearScannerTab(W.dynPesieve);
    clearScannerTab(W.dynMoneta);
    clearScannerTab(W.dynPatriot);
    clearScannerTab(W.dynHsb);
    clearScannerTab(W.dynRedEdr);
}
function clearScopeEdrProfile(profile) {
    S.detections.edr[profile] = [];
    delete S.ranScope.edr[profile];
}

// ── Run actions ──────────────────────────────────────────────────────────────

function runAll() {
    let profs = selectedProfiles();
    ensureUploaded(function() {
        resetEverything();
        S.ranScope.static = true;
        S.ranScope.dynamic = true;
        for (let i = 0; i < profs.length; i++) S.ranScope.edr[profs[i]] = true;
        seedProgressRows(true, true, profs);
        setStatus("Running All — Static + Dynamic + " + profs.length + " EDR...", COL_WARN);
        setBtnsEnabled(false);
        ax.service_command("cheshire", "run_all", {
            md5: S.md5, static: true, dynamic: true,
            dyn_args: parseArgs(W.dynArgs.text()), profiles: profs,
        });
    });
}

function runStatic() {
    ensureUploaded(function() {
        clearScopeStatic();
        S.ranScope.static = true;
        seedProgressRows(true, false, []);
        redrawSummary();
        updateVerdict();
        setStatus("Running static analysis...", COL_WARN);
        setBtnsEnabled(false);
        ax.service_command("cheshire", "run_static", { md5: S.md5 });
    });
}

function runDynamic() {
    ensureUploaded(function() {
        clearScopeDynamic();
        S.ranScope.dynamic = true;
        seedProgressRows(false, true, []);
        redrawSummary();
        updateVerdict();
        setStatus("Running dynamic analysis (executing on LitterBox host)...", COL_WARN);
        setBtnsEnabled(false);
        ax.service_command("cheshire", "run_dynamic", {
            md5: S.md5, args: parseArgs(W.dynArgs.text()),
        });
    });
}

function runEdr() {
    let profs = selectedProfiles();
    if (profs.length === 0) {
        ax.show_message("Cheshire", "Select at least one EDR profile.");
        return;
    }
    ensureUploaded(function() {
        for (let i = 0; i < profs.length; i++) {
            clearScopeEdrProfile(profs[i]);
            S.ranScope.edr[profs[i]] = true;
        }
        seedProgressRows(false, false, profs);
        redrawSummary();
        updateVerdict();
        setStatus("Dispatching to " + profs.length + " EDR profile(s)...", COL_WARN);
        setBtnsEnabled(false);
        ax.service_command("cheshire", "run_edr", { md5: S.md5, profiles: profs });
    });
}

// ── Progress rows ────────────────────────────────────────────────────────────

function seedProgressRows(includeStatic, includeDynamic, profiles) {
    S.progress = {};
    if (includeStatic)  S.progress["static"]  = { state: "pending", message: "queued", count: 0 };
    if (includeDynamic) S.progress["dynamic"] = { state: "pending", message: "queued", count: 0 };
    for (let i = 0; i < profiles.length; i++) {
        S.progress["edr:" + profiles[i]] = { state: "pending", message: "queued", count: 0 };
    }
    redrawProgress();
}

function updateProgress(scannerKey, state, msg, count) {
    if (!S.progress[scannerKey]) S.progress[scannerKey] = {};
    S.progress[scannerKey].state = state;
    S.progress[scannerKey].message = msg;
    S.progress[scannerKey].count = count || 0;
    redrawProgress();
}

function progressIcon(state) {
    if (state === "pending")        return ["⏸", COL_DIM];
    if (state === "uploading")      return ["⬆", COL_WARN];
    if (state === "running")        return ["⏳", COL_WARN];
    if (state === "phase1")         return ["⏳", COL_WARN];
    if (state === "polling")        return ["🔄", COL_WARN];
    if (state === "done")           return ["✓", COL_OK];
    if (state === "skipped")        return ["⏭", COL_DIM];
    if (state === "error")          return ["✗", COL_BAD];
    return ["•", COL_DIM];
}

function redrawProgress() {
    if (!W.progressLabel) return;

    let keys = [];
    if (S.progress["static"])  keys.push("static");
    if (S.progress["dynamic"]) keys.push("dynamic");
    let edr = [];
    for (let k in S.progress) {
        if (k.indexOf("edr:") === 0) edr.push(k);
    }
    edr.sort();
    for (let i = 0; i < edr.length; i++) keys.push(edr[i]);

    if (keys.length === 0) {
        W.progressLabel.setText("<span style='color:#666;font-size:9pt;'>(no scanners running)</span>");
        return;
    }

    // Single-line summary: "Static ✓  Dynamic ⏳  EDR·elastic 🔄 (3)"
    let parts = [];
    for (let i = 0; i < keys.length; i++) {
        let k = keys[i];
        let p = S.progress[k];
        let display;
        if (k === "static")       display = "Static";
        else if (k === "dynamic") display = "Dynamic";
        else                      display = k.substring(4);
        let ic = progressIcon(p.state);
        let countStr = (p.count > 0) ? " <b style='color:" + COL_CRITICAL + "'>(" + p.count + ")</b>" : "";
        parts.push("<span style='color:" + ic[1] + ";'>" + ic[0] + "</span> " +
                   "<span style='color:#D0D0D0;font-size:9pt;'>" + display + "</span>" + countStr);
    }
    W.progressLabel.setText(parts.join(" &nbsp; "));
}

// ── Verdict + Summary ────────────────────────────────────────────────────────

function allScheduledDone() {
    function isTerminal(key) {
        let p = S.progress[key];
        return p && (p.state === "done" || p.state === "error" || p.state === "skipped");
    }
    if (S.ranScope.static  && !isTerminal("static"))  return false;
    if (S.ranScope.dynamic && !isTerminal("dynamic")) return false;
    for (let p in S.ranScope.edr) {
        if (!isTerminal("edr:" + p)) return false;
    }
    return true;
}

function updateVerdict() {
    if (!W.verdictBanner) return;

    // Run scope
    let parts = [];
    if (S.ranScope.static)  parts.push("Static");
    if (S.ranScope.dynamic) parts.push("Dynamic");
    let edrProfs = [];
    for (let p in S.ranScope.edr) edrProfs.push(p);
    if (edrProfs.length > 0) parts.push("EDR (" + edrProfs.join(", ") + ")");

    if (parts.length === 0) {
        W.verdictBanner.setText(
            "<span style='color:#888;'>" +
            "<i>Select a payload and click <b>Run All</b> to begin.</i></span>"
        );
        return;
    }

    if (!allScheduledDone()) {
        let partial = collectAllDetections().filter(function(d) {
            return SEV_RANK[d.sev] >= SEV_RANK.MEDIUM;
        });
        let countText = partial.length > 0 ?
            partial.length + " hit(s) so far" : "no hits yet";
        W.verdictBanner.setText(
            "<span style='font-size:11pt;color:" + COL_WARN + ";font-weight:bold;'>⏳ RUNNING</span>" +
            " <span style='color:#D0D0D0;'>— " + countText + "</span>" +
            " <span style='color:#888;font-size:9pt;'>(" + parts.join(" + ") + ")</span>"
        );
        return;
    }

    // Terminal verdict
    let allDetections = collectAllDetections();
    let real = [];
    let info = [];
    for (let i = 0; i < allDetections.length; i++) {
        let d = allDetections[i];
        if (SEV_RANK[d.sev] >= SEV_RANK.MEDIUM) real.push(d);
        else info.push(d);
    }

    let scopeNote = "";
    if (parts.length < 3) {
        scopeNote = " <span style='color:#888;font-size:9pt;'>(" + parts.join(" + ") + " only)</span>";
    }

    let html;
    if (real.length > 0) {
        let byFamily = {};
        for (let i = 0; i < real.length; i++) {
            let fam = real[i].scanner.split(" ")[0];
            byFamily[fam] = (byFamily[fam] || 0) + 1;
        }
        let famParts = [];
        for (let f in byFamily) famParts.push(byFamily[f] + " " + f);
        let maxSev = "INFO";
        for (let i = 0; i < real.length; i++) {
            if (SEV_RANK[real[i].sev] > SEV_RANK[maxSev]) maxSev = real[i].sev;
        }
        let col = sevColor(maxSev);
        html = "<span style='font-size:11pt;color:" + col + ";font-weight:bold;'>🚫 DETECTED</span>" +
               " <span style='color:#E0E0E0;'>— " + real.length + " hit(s) across " +
               famParts.join(", ") + "</span>" +
               " <span style='color:" + col + ";font-weight:bold;'>[" + maxSev + "]</span>" +
               scopeNote;
    } else {
        let infoNote = info.length > 0 ?
            " <span style='color:#888;font-size:9pt;'>(" + info.length + " informational)</span>" : "";
        html = "<span style='font-size:11pt;color:" + COL_OK + ";font-weight:bold;'>✓ CLEAN</span>" +
               " <span style='color:#E0E0E0;'>— 0 critical/high/medium</span>" +
               infoNote + scopeNote;
    }
    W.verdictBanner.setText(html);
}

function collectAllDetections() {
    let all = [];
    for (let i = 0; i < S.detections.static.length;  i++) all.push(S.detections.static[i]);
    for (let i = 0; i < S.detections.dynamic.length; i++) all.push(S.detections.dynamic[i]);
    for (let p in S.detections.edr) {
        let arr = S.detections.edr[p];
        for (let i = 0; i < arr.length; i++) all.push(arr[i]);
    }
    return all;
}

function redrawSummary() {
    if (!W.summaryTable) return;
    W.summaryTable.clear();

    let all = collectAllDetections();
    // Sort: severity desc, then scanner name asc
    all.sort(function(a, b) {
        let d = (SEV_RANK[b.sev] || 0) - (SEV_RANK[a.sev] || 0);
        if (d !== 0) return d;
        return String(a.scanner).localeCompare(String(b.scanner));
    });

    for (let i = 0; i < all.length; i++) {
        let d = all[i];
        W.summaryTable.addItem([d.sev, d.scanner, d.name, d.detail || ""]);
    }
}

// ── Detection extractors ─────────────────────────────────────────────────────

// Static
function extractStaticDetections(results) {
    let out = [];
    let r = results || {};

    // YARA
    let yara = r.yara || {};
    let matches = asArr(yara.matches);
    for (let i = 0; i < matches.length; i++) {
        let m = matches[i];
        let meta = m.metadata || {};
        let detail = meta.threat_name || meta.description || "";
        let strs = asArr(m.strings);
        if (strs.length > 0 && strs[0].identifier) {
            detail = (detail ? detail + " — " : "") + "matched " + strs[0].identifier;
        }
        out.push({
            sev: normSev("yara", meta.severity),
            scanner: "Static · YARA",
            name: m.rule || "?",
            detail: detail,
        });
    }

    // CheckPlz
    let cp = (r.checkplz || {}).findings || {};
    let scan = cp.scan_results || {};
    if (cp.initial_threat || scan.detection_offset) {
        let detail = "";
        if (scan.detection_offset) detail = "offset " + scan.detection_offset;
        if (scan.relative_location) detail += (detail ? " — " : "") + scan.relative_location;
        out.push({
            sev: "CRITICAL",
            scanner: "Static · CheckPlz",
            name: cp.initial_threat || scan.final_threat_detection || "AV signature triggered",
            detail: detail,
        });
    }

    // Stringnalyzer — aggregate the dangerous categories
    let strn = (r.stringnalyzer || {}).findings || {};
    let suspicious = asArr(strn.found_suspicious_strings).length +
                     asArr(strn.found_suspicious_functions).length;
    let netInd = asArr(strn.found_network_indicators).length +
                 asArr(strn.found_url).length +
                 asArr(strn.found_ip).length +
                 asArr(strn.found_domains).length;
    if (suspicious > 0 || netInd > 0) {
        let parts = [];
        if (suspicious > 0) parts.push(suspicious + " suspicious string/function(s)");
        if (netInd > 0)     parts.push(netInd + " network indicator(s)");
        out.push({
            sev: suspicious > 0 ? "MEDIUM" : "LOW",
            scanner: "Static · Stringnalyzer",
            name: "Suspicious strings detected",
            detail: parts.join(", "),
        });
    }

    return out;
}

// Dynamic
function extractDynamicDetections(results) {
    let out = [];
    let r = results || {};

    // YARA-mem
    let yara = r.yara || {};
    let matches = asArr(yara.matches);
    for (let i = 0; i < matches.length; i++) {
        let m = matches[i];
        let meta = m.metadata || {};
        out.push({
            sev: normSev("yara", meta.severity),
            scanner: "Dynamic · YARA-mem",
            name: m.rule || "?",
            detail: meta.threat_name || meta.description || "",
        });
    }

    // PE-Sieve
    let ps = (r.pe_sieve || {}).findings || {};
    if ((ps.total_suspicious || 0) > 0) {
        let parts = [];
        if (ps.hooked)        parts.push(ps.hooked + " hooked");
        if (ps.replaced)      parts.push(ps.replaced + " replaced");
        if (ps.iat_hooks)     parts.push(ps.iat_hooks + " IAT hooks");
        if (ps.implanted_pe)  parts.push(ps.implanted_pe + " implanted PE");
        if (ps.implanted_shc) parts.push(ps.implanted_shc + " implanted shc");
        out.push({
            sev: "HIGH",
            scanner: "Dynamic · PE-Sieve",
            name: ps.total_suspicious + " modification(s)",
            detail: parts.join(", "),
        });
    }

    // Moneta — report each anomaly category that fired
    let mn = (r.moneta || {}).findings || {};
    let monetaIndicators = [
        ["total_private_rwx",       "private RWX",            "CRITICAL"],
        ["total_modified_code",     "modified code regions",  "CRITICAL"],
        ["total_heap_executable",   "executable heap",        "CRITICAL"],
        ["total_modified_pe_header", "modified PE header(s)", "HIGH"],
        ["total_threads_non_image", "threads in non-image",   "HIGH"],
        ["total_private_rx",        "private RX",             "MEDIUM"],
        ["total_inconsistent_x",    "inconsistent X",         "MEDIUM"],
    ];
    for (let i = 0; i < monetaIndicators.length; i++) {
        let key = monetaIndicators[i][0];
        let count = mn[key] || 0;
        if (count > 0) {
            out.push({
                sev: monetaIndicators[i][2],
                scanner: "Dynamic · Moneta",
                name: count + " " + monetaIndicators[i][1],
                detail: "",
            });
        }
    }

    // Patriot
    let pat = (r.patriot || {}).findings || {};
    let patFindings = asArr(pat.findings);
    for (let i = 0; i < patFindings.length; i++) {
        let f = patFindings[i];
        out.push({
            sev: normSev("patriot", f.level),
            scanner: "Dynamic · Patriot",
            name: f.type || "indicator",
            detail: (f.details || "").substring(0, 120),
        });
    }

    // HSB
    let hsb = (r.hsb || {}).findings || {};
    let detections = asArr(hsb.detections);
    let first = detections.length > 0 ? detections[0] : null;
    let hsbFindings = first ? asArr(first.findings) : [];
    for (let i = 0; i < hsbFindings.length; i++) {
        let f = hsbFindings[i];
        let detail = "";
        if (f.thread_id) detail = "TID " + f.thread_id;
        if (f.description) detail += (detail ? " — " : "") + f.description;
        out.push({
            sev: normSev(null, f.severity),
            scanner: "Dynamic · HSB",
            name: f.type || "sleep anomaly",
            detail: detail,
        });
    }

    // RedEdr · Defender threat verdicts
    let re = (r.rededr || {}).findings || {};
    let defs = asArr(re.defender_events);
    for (let i = 0; i < defs.length; i++) {
        let d = defs[i];
        if (d.category !== "threat") continue;
        out.push({
            sev: "CRITICAL",
            scanner: "Dynamic · Defender",
            name: d.verdict || d.event || "Defender threat",
            detail: d.scan_target || "",
        });
    }

    return out;
}

// EDR — one detection per alert
function extractEdrDetections(profile, data) {
    let out = [];
    let alerts = asArr((data || {}).alerts);
    for (let i = 0; i < alerts.length; i++) {
        let a = alerts[i];
        let det = a.details || {};
        let p = det.process || {};
        let detail = "";
        if (p.name) detail = p.name + (p.pid != null ? " (pid " + p.pid + ")" : "");
        if (det.api && det.api.name) {
            detail += (detail ? " — " : "") + (det.api.summary || det.api.name + "()");
        }
        out.push({
            sev: normSev("edr", a.severity),
            scanner: "EDR · " + profile,
            name: a.title || "alert",
            detail: detail,
        });
    }
    return out;
}

// ── Renderers (deep-dive tabs) ───────────────────────────────────────────────

function renderProfiles(profilesData, agentsData) {
    let profs = (profilesData && profilesData.profiles) ? profilesData.profiles : [];
    let agentsArr = (agentsData && agentsData.agents) ? agentsData.agents : [];
    let agentsMap = {};
    for (let i = 0; i < agentsArr.length; i++) {
        let a = agentsArr[i];
        if (a && a.name) agentsMap[a.name] = a;
    }

    W.profileChecks = {};
    let grid = form.create_gridlayout();
    let reachable = 0;

    if (profs.length === 0) {
        W.fleetLabel.setText("<span style='color:" + COL_BAD + ";font-size:10pt;'><i>No EDR profiles configured</i></span>");
        grid.addWidget(form.create_label(""), 0, 0);
    } else {
        for (let i = 0; i < profs.length; i++) {
            let p = profs[i];
            let name = p.name;
            let display = p.display_name || name;
            let kind = p.kind || "elastic";
            let a = agentsMap[name] || {};
            let ag = a.agent || {};
            let el = a.elastic || {};
            let agentOk   = !!ag.reachable;
            let backendOk = (kind === "elastic") ? !!el.reachable : agentOk;
            let healthy = agentOk && backendOk;

            let statusText, statusCol;
            if (healthy) { statusText = "reachable";     statusCol = COL_OK; }
            else         { statusText = "not reachable"; statusCol = COL_BAD; }

            let chk = form.create_check(display);
            chk.setChecked(healthy);
            chk.setEnabled(healthy);
            W.profileChecks[name] = chk;

            let statusLabel = form.create_label(
                "<span style='color:" + statusCol + ";font-size:10pt;font-weight:bold;'>● " +
                statusText + "</span>"
            );

            // Compact meta — kind + hostname + cluster only.
            let metaParts = [];
            metaParts.push("<span style='color:#888;'>" + htmlEsc(kind) + "</span>");
            if (ag.hostname) metaParts.push("<span style='color:#A0A0A0;'>" + htmlEsc(ag.hostname) + "</span>");
            if (kind === "elastic" && el.cluster_name) {
                metaParts.push("<span style='color:#A0A0A0;'>" + htmlEsc(el.cluster_name) + "</span>");
            }
            let metaLabel = form.create_label(
                "<span style='font-size:9pt;'>" +
                metaParts.join(" <span style='color:#444;'>·</span> ") +
                "</span>"
            );

            // Aligned columns:  [checkbox]  [status badge]  [meta]  [spacer]
            grid.addWidget(chk,         i, 0);
            grid.addWidget(statusLabel, i, 1);
            grid.addWidget(metaLabel,   i, 2);
            if (healthy) reachable++;
        }

        let healthCol = (reachable === profs.length) ? COL_OK :
                        (reachable > 0)              ? COL_MEDIUM : COL_BAD;
        W.fleetLabel.setText(
            "<span style='font-size:10pt;'>" +
            "<b style='color:" + healthCol + ";'>" + reachable + "</b>" +
            " <span style='color:#888;'>of " + profs.length + " profile(s) reachable</span></span>"
        );
    }
    W.profilesPanel.setLayout(grid);
}

function renderStatic(results) {
    let r = results || {};
    renderStaticYara(r.yara);
    renderStaticCheckplz(r.checkplz);
    renderStaticStringnalyzer(r.stringnalyzer);
}

function renderStaticYara(yara) {
    if (!W.staticYara) return;
    let r = yara || {};
    let matches = asArr(r.matches);
    let totalStrings = 0;
    let highSev = 0;
    for (let i = 0; i < matches.length; i++) {
        totalStrings += asArr(matches[i].strings).length;
        let s = parseInt((matches[i].metadata && matches[i].metadata.severity) || 0);
        if (s > highSev) highSev = s;
    }
    let isClean = matches.length === 0;
    renderStatStrip(W.staticYara.stats, [
        { label: "Status",        value: isClean ? "Clean" : "Detected", severity: isClean ? "clean" : "critical" },
        { label: "Rule Matches",  value: matches.length,                 severity: isClean ? "clean" : "critical" },
        { label: "Total Strings", value: totalStrings,                   severity: "info" },
        { label: "Max Severity",  value: isClean ? "—" : highSev,        severity: highSev > 50 ? "critical" : "info" },
    ]);

    let html = "";
    if (isClean) {
        html = "<div style='color:" + COL_OK + ";font-size:10pt;padding:6px;'>✓ No YARA rules matched.</div>";
    } else {
        let sorted = matches.slice().sort(function(a, b) {
            return (parseInt((b.metadata && b.metadata.severity) || 0)) -
                   (parseInt((a.metadata && a.metadata.severity) || 0));
        });
        for (let i = 0; i < sorted.length; i++) {
            let m = sorted[i];
            let meta = m.metadata || {};
            let sev = normSev("yara", meta.severity);
            let col = sevColor(sev);
            html += "<div style='border:1px solid " + col + "60;padding:8px;margin:6px 0;background:#1a1a1a;'>";
            html += "<div style='font-size:10pt;'><b style='color:" + col + ";'>#" + (i+1) + " " +
                    htmlEsc(m.rule || "?") + "</b> " + tagSev(sev) +
                    " <span style='color:#888;font-size:9pt;'>(score " + (parseInt(meta.severity)||0) + ")</span></div>";
            html += "<table style='margin-top:6px;'>";
            if (meta.threat_name)   html += kvRowHtml("Threat",      meta.threat_name);
            if (meta.description)   html += kvRowHtml("Description", meta.description);
            if (meta.author)        html += kvRowHtml("Author",      meta.author);
            if (meta.creation_date) html += kvRowHtml("Created",     meta.creation_date);
            html += "</table>";
            let strs = asArr(m.strings);
            if (strs.length > 0) {
                html += "<div style='color:#888;font-size:10pt;margin-top:6px;'>String matches (" + strs.length + "):</div>";
                html += "<div style='font-family:monospace;font-size:9pt;background:#0a0a0a;padding:6px;margin-top:4px;'>";
                for (let j = 0; j < strs.length && j < 15; j++) {
                    let s = strs[j];
                    html += "<div><span style='color:#888'>" + htmlEsc(s.offset || "") + "</span> ";
                    if (s.identifier) html += "<span style='color:" + COL_INFO + "'>" + htmlEsc(s.identifier) + "</span> ";
                    html += "<span style='color:#C0C0C0'>" + htmlEsc(String(s.data || "").substring(0, 200)) + "</span></div>";
                }
                if (strs.length > 15) html += "<div style='color:#666'>... +" + (strs.length - 15) + " more</div>";
                html += "</div>";
            }
            html += "</div>";
        }
    }
    W.staticYara.body.setText(html);
}

function renderStaticCheckplz(cp) {
    if (!W.staticCheckplz) return;
    let r = cp || {};
    let f = r.findings || {};
    let scan = f.scan_results || {};
    let isClean = !f.initial_threat && !scan.detection_offset;

    renderStatStrip(W.staticCheckplz.stats, [
        { label: "Status",      value: isClean ? "Clean" : "Triggered",
          severity: isClean ? "clean" : "critical" },
        { label: "Duration",    value: scan.scan_duration !== undefined ? scan.scan_duration.toFixed(2) + "s" : "—",
          severity: "info" },
        { label: "Iterations",  value: scan.search_iterations || "—",
          severity: "info" },
        { label: "Hex dump",    value: scan.hex_dump ? "yes" : "—",
          severity: "info" },
    ]);

    let html = "";
    if (isClean) {
        html = "<div style='color:" + COL_OK + ";font-size:10pt;padding:6px;'>✓ AV signature scan completed without matches.</div>";
    } else {
        html += sectionHeader("Trigger");
        html += "<table>";
        if (f.initial_threat)       html += kvRowHtml("Initial threat",     f.initial_threat);
        if (scan.detection_offset)  html += kvRowHtml("Detection offset",   scan.detection_offset);
        if (scan.relative_location) html += kvRowHtml("Relative location",  scan.relative_location);
        if (scan.final_threat_detection) html += kvRowHtml("Final detection", scan.final_threat_detection);
        if (scan.file_path) html += kvRowHtml("File path", scan.file_path);
        if (scan.file_size) html += kvRowHtml("File size", scan.file_size);
        html += "</table>";

        let inds = asArr(f.threat_indicators);
        if (inds.length > 0) {
            html += sectionHeader("Indicators (" + inds.length + ")");
            for (let i = 0; i < inds.length; i++) {
                html += "<div style='color:#C0C0C0;font-family:monospace;font-size:10pt;padding:2px 0;'>• " +
                        htmlEsc(inds[i].indicator || JSON.stringify(inds[i])) + "</div>";
            }
        }
        if (scan.hex_dump) {
            html += sectionHeader("Hex dump (around trigger)");
            html += "<pre style='background:#0a0a0a;padding:8px;color:#A0A0A0;font-size:9pt;'>" +
                    htmlEsc(scan.hex_dump) + "</pre>";
        }
    }
    W.staticCheckplz.body.setText(html);
}

function renderStaticStringnalyzer(strn) {
    if (!W.staticStringnalyzer) return;
    let r = strn || {};
    let f = r.findings || {};

    let cats = [
        ["Suspicious strings",     f.found_suspicious_strings,    "critical"],
        ["Suspicious functions",   f.found_suspicious_functions,  "critical"],
        ["Network indicators",     f.found_network_indicators,    "medium"],
        ["URLs",                   f.found_url,                   "medium"],
        ["IP addresses",           f.found_ip,                    "medium"],
        ["Domains",                f.found_domains,               "medium"],
        ["DLLs referenced",        f.found_dll,                   "info"],
        ["Functions",              f.found_functions,             "info"],
        ["Paths",                  f.found_path,                  "info"],
        ["Files referenced",       f.found_file,                  "info"],
        ["Commands",               f.found_commands,              "medium"],
        ["Registry keys",          f.found_registry_keys,         "medium"],
        ["File operations",        f.found_file_operations,       "info"],
        ["Email addresses",        f.found_emails,                "info"],
        ["Error messages",         f.found_error_messages,        "info"],
        ["Interesting strings",    f.found_interesting_strings,   "info"],
    ];
    let nonEmpty = 0;
    for (let i = 0; i < cats.length; i++) if (asArr(cats[i][1]).length > 0) nonEmpty++;

    renderStatStrip(W.staticStringnalyzer.stats, [
        { label: "Total Strings", value: f.total_strings || 0, severity: "info" },
        { label: "Categories",    value: nonEmpty,             severity: nonEmpty > 0 ? "medium" : "clean" },
    ]);

    let html = "";
    if (nonEmpty === 0) {
        html = "<div style='color:" + COL_OK + ";font-size:10pt;padding:6px;'>✓ No notable strings found.</div>";
    } else {
        for (let i = 0; i < cats.length; i++) {
            let arr = asArr(cats[i][1]);
            if (arr.length === 0) continue;
            let col = sevColor(cats[i][2] === "critical" ? "CRITICAL" :
                              cats[i][2] === "medium" ? "MEDIUM" : "INFO");
            html += "<div style='font-size:10pt;font-weight:bold;color:" + col + ";margin-top:14px;margin-bottom:6px;'>" +
                    htmlEsc(cats[i][0]) + " <span style='color:#888;font-weight:normal;font-size:9pt;'>(" + arr.length + ")</span></div>";
            html += "<div style='font-family:monospace;font-size:10pt;color:#C0C0C0;background:#0a0a0a;padding:6px;'>";
            for (let j = 0; j < arr.length && j < 30; j++) html += htmlEsc(arr[j]) + "<br>";
            if (arr.length > 30) html += "<span style='color:#666'>... +" + (arr.length - 30) + " more</span>";
            html += "</div>";
        }
    }
    W.staticStringnalyzer.body.setText(html);
}

function renderDynamic(results) {
    let r = results || {};
    renderDynYara(r.yara);
    renderDynPesieve(r.pe_sieve);
    renderDynMoneta(r.moneta);
    renderDynPatriot(r.patriot);
    renderDynHsb(r.hsb);
    renderDynRedEdr(r.rededr);
}

function renderDynYara(yara) {
    if (!W.dynYara) return;
    let r = yara || {};
    let matches = asArr(r.matches);
    let highSev = 0;
    for (let i = 0; i < matches.length; i++) {
        let s = parseInt((matches[i].metadata && matches[i].metadata.severity) || 0);
        if (s > highSev) highSev = s;
    }
    let isClean = matches.length === 0;
    renderStatStrip(W.dynYara.stats, [
        { label: "Status",        value: isClean ? "Clean" : "Detected", severity: isClean ? "clean" : "critical" },
        { label: "Memory Hits",   value: matches.length,                 severity: isClean ? "clean" : "critical" },
        { label: "Max Severity",  value: isClean ? "—" : highSev,        severity: highSev > 50 ? "critical" : "info" },
    ]);

    let html = "";
    if (isClean) {
        html = "<div style='color:" + COL_OK + ";font-size:10pt;padding:6px;'>✓ No YARA-mem rules matched.</div>";
    } else {
        for (let i = 0; i < matches.length; i++) {
            let m = matches[i];
            let meta = m.metadata || {};
            let sev = normSev("yara", meta.severity);
            let col = sevColor(sev);
            html += "<div style='border:1px solid " + col + "60;padding:8px;margin:6px 0;background:#1a1a1a;'>";
            html += "<div style='font-size:10pt;'><b style='color:" + col + ";'>#" + (i+1) + " " +
                    htmlEsc(m.rule || "?") + "</b> " + tagSev(sev) + "</div>";
            if (meta.threat_name || meta.description) {
                html += "<table style='margin-top:6px;'>";
                if (meta.threat_name) html += kvRowHtml("Threat",      meta.threat_name);
                if (meta.description) html += kvRowHtml("Description", meta.description);
                html += "</table>";
            }
            html += "</div>";
        }
    }
    W.dynYara.body.setText(html);
}

function renderDynPesieve(ps) {
    if (!W.dynPesieve) return;
    let f = (ps || {}).findings || {};
    let isClean = (f.total_suspicious || 0) === 0;
    renderStatStrip(W.dynPesieve.stats, [
        { label: "Status",        value: isClean ? "Clean" : "Detected", severity: isClean ? "clean" : "critical" },
        { label: "Modules",       value: f.total_scanned || 0,           severity: "info" },
        { label: "Modifications", value: f.total_suspicious || 0,        severity: isClean ? "clean" : "critical" },
    ]);

    let breakdown = [
        { label: "Hooked",           value: f.hooked },
        { label: "Replaced",         value: f.replaced },
        { label: "Headers Modified", value: f.hdrs_modified },
        { label: "IAT Hooks",        value: f.iat_hooks },
        { label: "Implanted",        value: f.implanted },
        { label: "Implanted PE",     value: f.implanted_pe },
        { label: "Implanted shc",    value: f.implanted_shc },
        { label: "Unreachable",      value: f.unreachable },
        { label: "Other",            value: f.other },
    ];
    let html = sectionHeader("Indicator breakdown");
    html += "<table cellspacing='6' cellpadding='6' style='margin:4px 0;'>";
    let perRow = 3;
    for (let i = 0; i < breakdown.length; i += perRow) {
        html += "<tr>";
        for (let j = 0; j < perRow && (i + j) < breakdown.length; j++) {
            let it = breakdown[i + j];
            let v = it.value || 0;
            let bdr = v > 0 ? COL_CRITICAL : "#444";
            let valCol = v > 0 ? COL_CRITICAL : "#D0D0D0";
            html += "<td style='border:1px solid " + bdr + ";padding:4px 8px;'>" +
                    "<div style='color:#888;font-size:9pt;'>" + htmlEsc(it.label) + "</div>" +
                    "<div style='color:" + valCol + ";font-family:monospace;font-size:11pt;font-weight:bold;'>" + v + "</div>" +
                    "</td>";
        }
        html += "</tr>";
    }
    html += "</table>";
    if (f.raw_output) {
        html += sectionHeader("Raw output");
        html += "<pre style='background:#0a0a0a;padding:8px;color:#A0A0A0;font-size:9pt;'>" + htmlEsc(f.raw_output) + "</pre>";
    }
    W.dynPesieve.body.setText(html);
}

function renderDynMoneta(mn) {
    if (!W.dynMoneta) return;
    let f = (mn || {}).findings || {};
    let pi = f.process_info || {};
    let metrics = [f.total_private_rwx, f.total_private_rx, f.total_modified_code,
                   f.total_inconsistent_x, f.total_heap_executable, f.total_modified_pe_header,
                   f.total_missing_peb, f.total_mismatching_peb, f.total_threads_non_image];
    let isClean = true;
    for (let i = 0; i < metrics.length; i++) if (metrics[i]) { isClean = false; break; }

    renderStatStrip(W.dynMoneta.stats, [
        { label: "Status",  value: isClean ? "Clean" : "Detected", severity: isClean ? "clean" : "critical" },
        { label: "Regions", value: f.total_regions || 0,           severity: "info" },
        { label: "Threads", value: asArr(f.threads).length,        severity: "info" },
        { label: "Private RWX", value: f.total_private_rwx || 0,
          severity: f.total_private_rwx > 0 ? "critical" : "info" },
        { label: "Modified Code", value: f.total_modified_code || 0,
          severity: f.total_modified_code > 0 ? "critical" : "info" },
        { label: "Heap Exec", value: f.total_heap_executable || 0,
          severity: f.total_heap_executable > 0 ? "critical" : "info" },
    ]);

    let html = "";
    if (pi.name) {
        html += sectionHeader("Process");
        html += "<table>";
        html += kvRowHtml("Name",      pi.name + " (PID " + pi.pid + ", " + (pi.arch || "?") + ")");
        if (pi.path)        html += kvRowHtml("Path",          pi.path);
        if (f.scan_duration) html += kvRowHtml("Scan duration", f.scan_duration.toFixed(2) + "s");
        html += "</table>";
    }

    html += sectionHeader("Memory anomalies");
    let cats = [
        ["Private RWX",          f.total_private_rwx,          true],
        ["Modified Code",        f.total_modified_code,        true],
        ["Heap Executable",      f.total_heap_executable,      true],
        ["Modified PE Header",   f.total_modified_pe_header,   true],
        ["Threads in non-image", f.total_threads_non_image,    true],
        ["Private RX",           f.total_private_rx,           false],
        ["Inconsistent X",       f.total_inconsistent_x,       false],
        ["Missing PEB",          f.total_missing_peb,          false],
        ["Mismatching PEB",      f.total_mismatching_peb,      false],
        ["Unsigned Modules",     f.total_unsigned_modules,     false],
    ];
    html += "<table cellspacing='6' cellpadding='6'>";
    let perRow = 3;
    for (let i = 0; i < cats.length; i += perRow) {
        html += "<tr>";
        for (let j = 0; j < perRow && (i + j) < cats.length; j++) {
            let it = cats[i + j];
            let v = it[1] || 0;
            let isCrit = it[2];
            let bdr = v > 0 ? (isCrit ? COL_CRITICAL : COL_MEDIUM) : "#444";
            let valCol = v > 0 ? (isCrit ? COL_CRITICAL : COL_MEDIUM) : "#D0D0D0";
            html += "<td style='border:1px solid " + bdr + ";padding:4px 8px;'>" +
                    "<div style='color:#888;font-size:9pt;'>" + htmlEsc(it[0]) + "</div>" +
                    "<div style='color:" + valCol + ";font-family:monospace;font-size:11pt;font-weight:bold;'>" + v + "</div>" +
                    "</td>";
        }
        html += "</tr>";
    }
    html += "</table>";
    W.dynMoneta.body.setText(html);
}

function renderDynPatriot(pt) {
    if (!W.dynPatriot) return;
    let d = (pt || {}).findings || {};
    let proc = d.process_info || {};
    let mem = d.memory_stats || {};
    let sum = d.scan_summary || {};
    let findings = asArr(d.findings);
    let isClean = findings.length === 0;

    renderStatStrip(W.dynPatriot.stats, [
        { label: "Status",   value: isClean ? "Clean" : "Detected", severity: isClean ? "clean" : "critical" },
        { label: "Findings", value: sum.total_findings || 0,        severity: isClean ? "clean" : "critical" },
        { label: "Regions",  value: mem.total_regions || 0,         severity: "info" },
        { label: "Duration", value: sum.duration ? sum.duration.toFixed(2) + "s" : "—", severity: "info" },
    ]);

    let html = "";
    if (proc.process_name) {
        html += sectionHeader("Process");
        html += "<table>";
        html += kvRowHtml("Name",      proc.process_name + " (PID " + proc.pid + ")");
        html += kvRowHtml("Elevation", proc.elevation_status || "?");
        html += kvRowHtml("Memory",    "Private " + (mem.private_memory != null ? mem.private_memory : "?") +
                                       " MB · Executable " + (mem.executable_memory != null ? mem.executable_memory : "?") + " MB");
        html += "</table>";
    }

    let byType = sum.findings_by_type || {};
    if (Object.keys(byType).length > 0) {
        html += sectionHeader("Findings by type");
        html += "<table cellspacing='4' cellpadding='4'>";
        for (let t in byType) {
            html += "<tr><td style='color:" + COL_HIGH + ";padding:2px 16px 2px 0;'>" + htmlEsc(t) +
                    "</td><td style='color:" + COL_HIGH + ";font-family:monospace;font-weight:bold;'>" + byType[t] + "</td></tr>";
        }
        html += "</table>";
    }

    if (isClean) {
        html += "<div style='color:" + COL_OK + ";font-size:10pt;padding:6px;'>✓ No behavioral indicators.</div>";
    } else {
        html += sectionHeader("Findings (" + findings.length + ")");
        for (let i = 0; i < findings.length; i++) {
            let f = findings[i];
            let lvl = (f.level || "INFO").toUpperCase();
            let col = sevColor(lvl);
            html += "<div style='border:1px solid " + col + "60;padding:8px;margin:6px 0;background:#1a1a1a;'>";
            html += "<div><b style='color:" + col + ";'>#" + (f.finding_number || (i+1)) + " " +
                    htmlEsc(f.type || "?") + "</b> " + tagSev(lvl) +
                    " <span style='color:#888;font-size:9pt;'>" + htmlEsc(f.timestamp || "") + "</span></div>";
            if (f.details) html += "<div style='color:#C0C0C0;font-family:monospace;font-size:10pt;margin-top:4px;'>" +
                                    htmlEsc(f.details) + "</div>";
            if (f.parsed_details) {
                html += "<table style='margin-top:6px;'>";
                for (let k in f.parsed_details) html += kvRowHtml(k, f.parsed_details[k]);
                html += "</table>";
            }
            html += "</div>";
        }
    }
    W.dynPatriot.body.setText(html);
}

function renderDynHsb(hsb) {
    if (!W.dynHsb) return;
    let d = (hsb || {}).findings || {};
    let summary = d.summary || {};
    let detections = asArr(d.detections);
    let first = detections.length > 0 ? detections[0] : null;
    let fnds = first ? asArr(first.findings) : [];
    let hasFindings = fnds.length > 0;

    renderStatStrip(W.dynHsb.stats, [
        { label: "Status",   value: hasFindings ? "Detected" : "Clean", severity: hasFindings ? "critical" : "clean" },
        { label: "Findings", value: summary.total_findings || 0,         severity: hasFindings ? "critical" : "info" },
        { label: "Threads",  value: summary.scanned_threads || 0,        severity: "info" },
        { label: "Duration", value: summary.duration ? summary.duration.toFixed(2) + "s" : "—", severity: "info" },
    ]);

    let html = "";
    if (first) {
        html += sectionHeader("Process");
        html += "<table>" + kvRowHtml("Name", first.process_name + " (PID " + first.pid + ")") + "</table>";
    }
    if (!hasFindings) {
        html += "<div style='color:" + COL_OK + ";font-size:10pt;padding:6px;'>✓ No sleep-pattern indicators.</div>";
    } else {
        let byThread = {};
        for (let i = 0; i < fnds.length; i++) {
            let tid = fnds[i].thread_id || "process";
            if (!byThread[tid]) byThread[tid] = [];
            byThread[tid].push(fnds[i]);
        }
        for (let tid in byThread) {
            html += sectionHeader(tid === "process" ? "Process-wide (" + byThread[tid].length + ")"
                                                    : "Thread " + tid + " (" + byThread[tid].length + ")");
            let arr = byThread[tid];
            for (let i = 0; i < arr.length; i++) {
                let f = arr[i];
                let sev = normSev(null, f.severity);
                let col = sevColor(sev);
                html += "<div style='border-left:3px solid " + col + ";padding:6px 10px;margin:4px 0;background:#1a1a1a;'>";
                html += "<div><b style='color:" + col + ";'>" + htmlEsc(f.type || "?") + "</b> " + tagSev(sev) + "</div>";
                if (f.description) html += "<div style='color:#C0C0C0;font-size:10pt;margin-top:3px;'>" +
                                            htmlEsc(f.description) + "</div>";
                html += "</div>";
            }
        }
    }
    W.dynHsb.body.setText(html);
}

function renderDynRedEdr(re) {
    if (!W.dynRedEdr) return;
    let f = (re || {}).findings || {};
    let summary = f.summary || {};
    let proc = f.process_info || {};
    let defs = asArr(f.defender_events);
    let threats = 0;
    for (let i = 0; i < defs.length; i++) if (defs[i].category === "threat") threats++;
    let nets = asArr(f.network_activity).length;
    let api  = asArr(f.audit_api_calls).length;
    let kids = asArr(f.child_processes).length;

    renderStatStrip(W.dynRedEdr.stats, [
        { label: "Defender Threats", value: threats, severity: threats > 0 ? "critical" : "clean" },
        { label: "Total Events",     value: summary.total_events || 0,             severity: "info" },
        { label: "DLLs",             value: summary.total_dlls || 0,               severity: "info" },
        { label: "Child Procs",      value: kids,                                   severity: kids > 0 ? "medium" : "info" },
        { label: "Network",          value: nets,                                   severity: nets > 0 ? "medium" : "info" },
        { label: "Audit API",        value: api,                                    severity: api > 0 ? "medium" : "info" },
    ]);

    let html = "";
    if (proc.pid) {
        html += sectionHeader("Process");
        html += "<table>";
        html += kvRowHtml("PID", proc.pid);
        if (proc.image_path)  html += kvRowHtml("Image",      proc.image_path);
        if (proc.commandline) html += kvRowHtml("Cmdline",    proc.commandline);
        if (proc.parent_pid)  html += kvRowHtml("Parent PID", proc.parent_pid);
        html += "</table>";
    }

    if (threats > 0) {
        html += sectionHeader("⚠ Defender threat verdicts (" + threats + ")");
        for (let i = 0; i < defs.length; i++) {
            if (defs[i].category !== "threat") continue;
            html += "<div style='border-left:3px solid " + COL_CRITICAL + ";padding:6px 10px;margin:4px 0;background:#1a1a1a;'>";
            html += "<div style='color:" + COL_CRITICAL + ";font-weight:bold;font-size:10pt;'>" +
                    htmlEsc(defs[i].verdict || defs[i].event || "threat") + "</div>";
            if (defs[i].scan_target) html += "<div style='color:#C0C0C0;font-family:monospace;font-size:10pt;margin-top:3px;'>" +
                                              htmlEsc(defs[i].scan_target) + "</div>";
            if (defs[i].time) html += "<div style='color:#888;font-size:9pt;'>" + htmlEsc(defs[i].time) + "</div>";
            html += "</div>";
        }
    }

    let auditArr = asArr(f.audit_api_calls);
    if (auditArr.length > 0) {
        html += sectionHeader("Audit API calls (" + auditArr.length + ")");
        html += "<div style='font-family:monospace;font-size:10pt;background:#0a0a0a;padding:6px;'>";
        for (let i = 0; i < auditArr.length && i < 30; i++) {
            let a = auditArr[i];
            html += "<div><span style='color:" + COL_MEDIUM + ";'>" + htmlEsc(a.api || "?") + "</span>";
            if (a.target_pid) html += " <span style='color:#C0C0C0'>→ pid " + a.target_pid + "</span>";
            if (a.return_code !== undefined) html += " <span style='color:#888'>(rc=" + a.return_code + ")</span>";
            html += "</div>";
        }
        if (auditArr.length > 30) html += "<span style='color:#666'>... +" + (auditArr.length - 30) + " more</span>";
        html += "</div>";
    }

    let netArr = asArr(f.network_activity);
    if (netArr.length > 0) {
        html += sectionHeader("Network activity (" + netArr.length + ")");
        html += "<div style='font-family:monospace;font-size:10pt;background:#0a0a0a;padding:6px;'>";
        for (let i = 0; i < netArr.length && i < 30; i++) {
            let n = netArr[i];
            html += "<div><span style='color:" + COL_INFO + ";'>" + htmlEsc((n.proto || "?").toUpperCase()) + "</span> " +
                    "<span style='color:#C0C0C0'>" + htmlEsc(n.operation || "") + "</span> " +
                    "<span style='color:#888'>" + htmlEsc((n.local_addr || "") + ":" + (n.local_port || "")) + " → " +
                    htmlEsc((n.remote_addr || "") + ":" + (n.remote_port || "")) + "</span></div>";
        }
        if (netArr.length > 30) html += "<span style='color:#666'>... +" + (netArr.length - 30) + " more</span>";
        html += "</div>";
    }

    let kidsArr = asArr(f.child_processes);
    if (kidsArr.length > 0) {
        html += sectionHeader("Child processes (" + kidsArr.length + ")");
        html += "<div style='font-family:monospace;font-size:10pt;background:#0a0a0a;padding:6px;'>";
        for (let i = 0; i < kidsArr.length; i++) {
            let k = kidsArr[i];
            html += "<div><span style='color:" + COL_MEDIUM + ";'>PID " + k.pid + "</span>: " +
                    "<span style='color:#C0C0C0'>" + htmlEsc(k.image_name || "?") + "</span></div>";
        }
        html += "</div>";
    }

    if (html === "") html = "<div style='color:" + COL_OK + ";font-size:10pt;padding:6px;'>✓ No notable runtime telemetry.</div>";
    W.dynRedEdr.body.setText(html);
}

function renderEdrProfile(profile, data) {
    let entry = S.edrTabs[profile];
    if (!entry) {
        if (W.edrEmpty && W.edrEmpty.setVisible) W.edrEmpty.setVisible(false);

        let alertsTable = form.create_table(["Severity", "Rule", "Process", "Trigger", "Detected"]);
        alertsTable.setSortingEnabled(true);
        let detailText = form.create_textmulti();
        detailText.setReadOnly(true);
        detailText.setPlaceholder("Click an alert to inspect details.");

        form.connect(alertsTable, "cellClicked", function(row, col) {
            let e = S.edrTabs[profile];
            if (!e || !e.stash || row < 0 || row >= e.stash.length) return;
            renderEdrAlertDetail(e.detail, e.stash[row]);
        });

        let lay = form.create_vlayout();
        lay.addWidget(form.create_label("<b>Alerts</b>"));
        lay.addWidget(alertsTable);
        lay.addWidget(form.create_label("<b>Alert detail</b>"));
        lay.addWidget(detailText);
        let panel = form.create_panel(); panel.setLayout(lay);

        W.edrTabs.addTab(panel, profile);
        entry = { table: alertsTable, detail: detailText, stash: [] };
        S.edrTabs[profile] = entry;
    }

    if (!data) return;

    let alerts = asArr(data.alerts).slice().sort(function(a, b) {
        let order = { critical:4, high:3, medium:2, low:1 };
        let da = order[String(a.severity || "").toLowerCase()] || 0;
        let db = order[String(b.severity || "").toLowerCase()] || 0;
        if (db !== da) return db - da;
        return String(b.detected_at || "").localeCompare(String(a.detected_at || ""));
    });

    entry.table.clear();
    entry.stash = alerts;
    for (let i = 0; i < alerts.length; i++) {
        let a = alerts[i];
        let det = a.details || {};
        let p = det.process || {};
        let procStr = p.name ? (p.name + (p.pid != null ? " (" + p.pid + ")" : "")) : "";
        let trigger = "";
        if (det.api && det.api.name) trigger = det.api.summary || (det.api.name + "()");
        entry.table.addItem([
            String(a.severity || "?").toUpperCase(),
            a.title || "",
            procStr,
            trigger,
            a.detected_at || "",
        ]);
    }

    let st = data.status || "?";
    let sm = data.summary || {};
    let ex = data.execution || {};
    let summaryText = "Status: " + st + "\n" +
                      "Total alerts: " + (sm.total_alerts || 0) + "\n" +
                      "Critical/High: " + (sm.high_severity_alerts || 0) + "\n" +
                      "Hostname: " + (data.hostname || "?") + "\n" +
                      "PID: " + (ex.pid || "?") + "\n" +
                      "Exit code: " + (ex.exit_code !== undefined ? ex.exit_code : "?") + "\n" +
                      "Killed by EDR: " + (ex.killed_by_edr ? "yes" : "no") + "\n";
    if (sm.blocked_by_av) summaryText += "AV blocked: yes\n";
    if (ex.stdout) summaryText += "\nstdout:\n" + ex.stdout + "\n";
    if (ex.stderr) summaryText += "\nstderr:\n" + ex.stderr + "\n";

    if (alerts.length === 0) {
        if (st === "polling_alerts") {
            entry.detail.setText(summaryText + "\n\n[ Phase 2: polling Elastic for alerts... ]");
        } else {
            entry.detail.setText(summaryText + "\n\n[ No alerts raised during the correlation window ]");
        }
    } else {
        entry.detail.setText(summaryText + "\n\nClick an alert above to inspect details.");
    }
}

function renderEdrAlertDetail(target, a) {
    let d = a.details || {};
    let txt = "";
    txt += "═══ " + (a.title || "?") + " ═══\n";
    txt += "Severity:   " + String(a.severity || "?").toUpperCase() + "\n";
    txt += "Detected:   " + (a.detected_at || "?") + "\n\n";

    if (d.reason) txt += "Reason:\n  " + d.reason + "\n\n";
    if (d.rule_description) txt += "Rule:\n  " + d.rule_description + "\n\n";

    let mitre = asArr(d.mitre);
    if (mitre.length > 0) {
        txt += "MITRE ATT&CK:\n";
        for (let i = 0; i < mitre.length; i++) {
            let m = mitre[i];
            txt += "  • " + (m.tactic_name || "?") + " › " + (m.technique_name || "?");
            if (m.subtechnique_name) txt += " › " + m.subtechnique_name;
            txt += "\n";
        }
        txt += "\n";
    }

    if (d.api && d.api.name) {
        txt += "Triggering API:\n  " + (d.api.summary || d.api.name + "()") + "\n";
        let bs = asArr(d.api.behaviors);
        if (bs.length) txt += "  Behaviors: " + bs.join(", ") + "\n";
        txt += "\n";
    }

    if (d.memory_region && (d.memory_region.region_protection || d.memory_region.mapped_path)) {
        let m = d.memory_region;
        txt += "Memory region:\n";
        if (m.allocation_protection) txt += "  Allocation prot: " + m.allocation_protection + "\n";
        if (m.region_protection)     txt += "  Region prot:     " + m.region_protection + "\n";
        if (m.region_size != null)   txt += "  Region size:     " + m.region_size + " bytes\n";
        if (m.mapped_path)           txt += "  Mapped path:     " + m.mapped_path + "\n";
        txt += "\n";
    }

    let cs = asArr(d.call_stack);
    if (cs.length > 0) {
        txt += "Call stack:\n";
        if (d.call_stack_summary) txt += "  " + d.call_stack_summary + "\n\n";
        for (let i = 0; i < cs.length && i < 30; i++) {
            let f = cs[i];
            txt += "  " + ((typeof f === "string") ? f : fmtJSON(f)) + "\n";
        }
        if (cs.length > 30) txt += "  ... +" + (cs.length - 30) + " more frames\n";
        txt += "\n";
    }

    if (d.call_stack_final_user_module) {
        let m = d.call_stack_final_user_module;
        txt += "Final user module:\n";
        if (m.name === "Unbacked") {
            txt += "  ⚠ Code is in private memory with no file backing — classic shellcode.\n";
        } else if (m.name === "Undetermined") {
            txt += "  ⚠ Elastic Defend couldn't resolve a user-mode module.\n";
        }
        if (m.name) txt += "  Module: " + m.name + "\n";
        if (m.path) txt += "  Path:   " + m.path + "\n";
        txt += "\n";
    }

    if (d.process) {
        let p = d.process;
        txt += "Process:\n";
        if (p.name)            txt += "  Name:        " + p.name + "\n";
        if (p.pid != null)     txt += "  PID:         " + p.pid + "\n";
        if (p.command_line)    txt += "  Cmdline:     " + p.command_line + "\n";
        if (p.integrity_level) txt += "  Integrity:   " + p.integrity_level + "\n";
        txt += "\n";
    }

    let resps = asArr(d.responses);
    if (resps.length > 0) {
        txt += "EDR responses:\n";
        for (let i = 0; i < resps.length; i++) {
            let r = resps[i];
            txt += "  • " + (r.action || "?");
            if (r.tree) txt += " (tree)";
            if (r.target_name) txt += " — " + r.target_name;
            if (r.result_message) txt += " : " + r.result_message;
            txt += "\n";
        }
    }

    target.setText(txt);
}

// ── data_handler ─────────────────────────────────────────────────────────────

function data_handler(data) {
    let r;
    try { r = JSON.parse(data); } catch(e) { return; }

    switch (r.action) {

        case "health":
            renderProfiles(r.profiles, r.agents);
            break;

        case "submitted":
            S.md5 = r.md5;
            S.fileName = r.file_name;
            S.fileInfo = r.file_info;
            setStatus("Uploaded: " + r.file_name + " (" + r.md5 + ")", COL_OK);
            W.cleanup && W.cleanup.setEnabled(true);
            if (pendingAction) {
                let a = pendingAction; pendingAction = null; a();
            } else {
                setBtnsEnabled(true);
            }
            break;

        case "progress":
            updateProgress(r.scanner, r.state, r.message || "", r.count || 0);
            break;

        case "static_results":
            renderStatic(r.results);
            S.detections.static = extractStaticDetections(r.results);
            redrawSummary();
            updateVerdict();
            setBtnsEnabled(true);
            break;

        case "dynamic_results":
            renderDynamic(r.results);
            S.detections.dynamic = extractDynamicDetections(r.results);
            if (r.early_term) setStatus("Dynamic: early termination", COL_MEDIUM);
            redrawSummary();
            updateVerdict();
            setBtnsEnabled(true);
            break;

        case "edr_phase1":
            renderEdrProfile(r.profile, r.data);
            // Phase 1 has execution info but no alerts yet — clear the
            // profile's detections row, will refill on polling.
            S.detections.edr[r.profile] = [];
            redrawSummary();
            updateVerdict();
            break;

        case "edr_polling":
            renderEdrProfile(r.profile, r.data);
            S.detections.edr[r.profile] = extractEdrDetections(r.profile, r.data);
            redrawSummary();
            updateVerdict();
            break;

        case "edr_results":
            renderEdrProfile(r.profile, r.data);
            S.detections.edr[r.profile] = extractEdrDetections(r.profile, r.data);
            redrawSummary();
            updateVerdict();
            setBtnsEnabled(true);
            break;

        case "edr_error":
            setStatus("EDR " + r.profile + ": " + r.message, COL_BAD);
            setBtnsEnabled(true);
            break;

        case "risk_results":
            // Score is captured but the verdict banner is the headline.
            // Surface it as a single info row so operators can still see it.
            S.lastScore = { score: r.risk_score, level: r.risk_level };
            updateVerdict();
            break;

        case "all_done":
            setStatus("All analyses complete.", COL_OK);
            setBtnsEnabled(true);
            break;

        case "cleaned":
            setStatus("Cleaned " + (r.md5 || "") + " from LitterBox", COL_DIM);
            S.md5 = null; S.fileName = null; S.fileInfo = null;
            W.cleanup && W.cleanup.setEnabled(false);
            resetEverything();
            break;

        case "error":
            setStatus("Error: " + (r.message || "?"), COL_BAD);
            setBtnsEnabled(true);
            ax.show_message("Cheshire Error", r.message || "Unknown error");
            break;
    }
}
