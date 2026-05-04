// ── State ────────────────────────────────────────────────────────────────────

var currentMD5      = null;
var currentFileName = null;

var statusLabel     = null;
var fleetLabel      = null;
var runAllBtn       = null;
var runStaticBtn    = null;
var runDynamicBtn   = null;
var runEdrBtn       = null;
var cleanupBtn      = null;
var filePathLabel   = null;
var dynArgsLine     = null;

var profileChecks   = {};
var profilesPanel   = null;

var scoreText       = null;
var staticText      = null;
var dynYaraText     = null;
var dynPesieveText  = null;
var dynMonetaText   = null;
var dynPatriotText  = null;
var dynHsbText      = null;
var dynRedEdrText   = null;
var edrTabsByProfile = {};
var edrOuterTabs    = null;
var topTabs         = null;

var pendingAction = null;

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

function setStatus(text, color) {
    if (statusLabel) statusLabel.setText("<b style='color:" + color + "'>" + text + "</b>");
}

function setBtnsEnabled(b) {
    if (runAllBtn)     runAllBtn.setEnabled(b);
    if (runStaticBtn)  runStaticBtn.setEnabled(b);
    if (runDynamicBtn) runDynamicBtn.setEnabled(b);
    if (runEdrBtn)     runEdrBtn.setEnabled(b);
}

function selectedProfiles() {
    let names = [];
    for (let n in profileChecks) if (profileChecks[n].isChecked()) names.push(n);
    return names;
}

function ensureUploaded(cb) {
    if (currentMD5) { cb(); return; }
    let path = filePathLabel.text();
    if (!path || path.indexOf("No file") >= 0) {
        ax.show_message("Cheshire", "Select a payload file first.");
        return;
    }
    setStatus("Uploading...", "#FF9800");
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
function asArr(x) { return Array.isArray(x) ? x : []; }

function levelColor(level) {
    let l = String(level || "").toLowerCase();
    if (l === "critical") return "#FF4444";
    if (l === "high")     return "#FF8800";
    if (l === "medium" || l === "mid") return "#FFD700";
    if (l === "low")      return "#4CAF50";
    return "#888";
}

// ── Main dialog ──────────────────────────────────────────────────────────────

function showCheshireDialog() {
    currentMD5 = null;
    currentFileName = null;
    profileChecks = {};
    edrTabsByProfile = {};
    pendingAction = null;

    // Payload group
    let fileGroup = form.create_groupbox("Payload", false);
    filePathLabel = form.create_label("<i style='color:#888'>No file selected</i>");
    let browseBtn = form.create_button("Browse...");
    form.connect(browseBtn, "clicked", function() {
        let path = ax.prompt_open_file("Select payload", "All Files (*)");
        if (path && path.length > 0) {
            filePathLabel.setText(path);
            currentMD5 = null; currentFileName = null;
            clearResults();
            setStatus("File selected", "#888");
        }
    });
    let fl = form.create_hlayout();
    fl.addWidget(browseBtn);
    fl.addWidget(filePathLabel);
    fl.addWidget(form.create_hspacer());
    let fp = form.create_panel(); fp.setLayout(fl);
    fileGroup.setPanel(fp);

    // EDR profiles group
    let profGroup = form.create_groupbox("EDR Profiles", false);
    fleetLabel = form.create_label("<i style='color:#888'>loading fleet...</i>");
    profilesPanel = form.create_panel();
    profilesPanel.setLayout(form.create_hlayout());
    let pl = form.create_vlayout();
    pl.addWidget(fleetLabel);
    pl.addWidget(profilesPanel);
    let pp = form.create_panel(); pp.setLayout(pl);
    profGroup.setPanel(pp);

    // Dynamic args
    let dynGroup = form.create_groupbox("Dynamic Analysis Args", false);
    dynArgsLine = form.create_textline();
    dynArgsLine.setPlaceholder("Optional space-separated args passed to the binary at runtime");
    let dl = form.create_hlayout();
    dl.addWidget(dynArgsLine);
    let dp = form.create_panel(); dp.setLayout(dl);
    dynGroup.setPanel(dp);

    // Run bar
    statusLabel   = form.create_label("<b style='color:#888'>Ready</b>");
    runAllBtn     = form.create_button("Run All");
    runStaticBtn  = form.create_button("Static");
    runDynamicBtn = form.create_button("Dynamic");
    runEdrBtn     = form.create_button("EDR");
    cleanupBtn    = form.create_button("Cleanup");
    cleanupBtn.setEnabled(false);

    form.connect(runAllBtn,     "clicked", runAll);
    form.connect(runStaticBtn,  "clicked", runStatic);
    form.connect(runDynamicBtn, "clicked", runDynamic);
    form.connect(runEdrBtn,     "clicked", runEdr);
    form.connect(cleanupBtn,    "clicked", function() {
        if (!currentMD5) return;
        setStatus("Cleaning up...", "#888");
        ax.service_command("cheshire", "cleanup", { md5: currentMD5 });
    });

    let bl = form.create_hlayout();
    bl.addWidget(statusLabel);
    bl.addWidget(form.create_hspacer());
    bl.addWidget(runAllBtn);
    bl.addWidget(runStaticBtn);
    bl.addWidget(runDynamicBtn);
    bl.addWidget(runEdrBtn);
    bl.addWidget(cleanupBtn);
    let bp = form.create_panel(); bp.setLayout(bl);

    // Result tabs
    topTabs = form.create_tabs();
    topTabs.addTab(buildScorePanel(),   "Score");
    topTabs.addTab(buildStaticPanel(),  "Static");
    topTabs.addTab(buildDynamicPanel(), "Dynamic");
    topTabs.addTab(buildEdrPanel(),     "EDR");

    let main = form.create_vlayout();
    main.addWidget(fileGroup);
    main.addWidget(profGroup);
    main.addWidget(dynGroup);
    main.addWidget(bp);
    main.addWidget(topTabs);

    let dialog = form.create_dialog("Cheshire — LitterBox QA");
    dialog.setSize(1100, 800);
    dialog.setLayout(main);
    dialog.setButtonsText("", "Close");

    ax.service_command("cheshire", "get_profiles", {});
    dialog.exec();

    currentMD5 = null; currentFileName = null;
    statusLabel = null; fleetLabel = null;
    runAllBtn = null; runStaticBtn = null; runDynamicBtn = null; runEdrBtn = null;
    cleanupBtn = null; filePathLabel = null; dynArgsLine = null;
    profileChecks = {}; profilesPanel = null;
    scoreText = null; staticText = null;
    dynYaraText = null; dynPesieveText = null; dynMonetaText = null;
    dynPatriotText = null; dynHsbText = null; dynRedEdrText = null;
    edrTabsByProfile = {}; edrOuterTabs = null; topTabs = null;
    pendingAction = null;
}

function mkText(placeholder) {
    let t = form.create_textmulti();
    t.setReadOnly(true);
    if (placeholder) t.setPlaceholder(placeholder);
    return t;
}

function wrapText(t) {
    let lay = form.create_vlayout();
    lay.addWidget(t);
    let p = form.create_panel(); p.setLayout(lay);
    return p;
}

function buildScorePanel() {
    scoreText = mkText("Risk score and triggering indicators will appear here.");
    return wrapText(scoreText);
}

function buildStaticPanel() {
    staticText = mkText("Static analysis results (YARA / CheckPlz / Stringnalyzer).");
    return wrapText(staticText);
}

function buildDynamicPanel() {
    let tabs = form.create_tabs();
    dynYaraText    = mkText("YARA-mem matches.");
    dynPesieveText = mkText("PE-Sieve memory modifications.");
    dynMonetaText  = mkText("Moneta memory anomalies.");
    dynPatriotText = mkText("Patriot behavior indicators.");
    dynHsbText     = mkText("Hunt Sleeping Beacons — sleep mask detection.");
    dynRedEdrText  = mkText("RedEdr — Defender / network / API telemetry.");
    tabs.addTab(wrapText(dynYaraText),    "YARA-mem");
    tabs.addTab(wrapText(dynPesieveText), "PE-Sieve");
    tabs.addTab(wrapText(dynMonetaText),  "Moneta");
    tabs.addTab(wrapText(dynPatriotText), "Patriot");
    tabs.addTab(wrapText(dynHsbText),     "HSB");
    tabs.addTab(wrapText(dynRedEdrText),  "RedEdr");
    let lay = form.create_vlayout();
    lay.addWidget(tabs);
    let p = form.create_panel(); p.setLayout(lay);
    return p;
}

function buildEdrPanel() {
    edrOuterTabs = form.create_tabs();
    let placeholder = mkText("Run an EDR analysis to populate this panel.");
    edrOuterTabs.addTab(wrapText(placeholder), "(no runs)");
    let lay = form.create_vlayout();
    lay.addWidget(edrOuterTabs);
    let p = form.create_panel(); p.setLayout(lay);
    return p;
}

function clearResults() {
    if (scoreText)       scoreText.setText("");
    if (staticText)      staticText.setText("");
    if (dynYaraText)     dynYaraText.setText("");
    if (dynPesieveText)  dynPesieveText.setText("");
    if (dynMonetaText)   dynMonetaText.setText("");
    if (dynPatriotText)  dynPatriotText.setText("");
    if (dynHsbText)      dynHsbText.setText("");
    if (dynRedEdrText)   dynRedEdrText.setText("");
    edrTabsByProfile = {};
}

// ── Run actions ──────────────────────────────────────────────────────────────

function runAll() {
    ensureUploaded(function() {
        let profs = selectedProfiles();
        setStatus("Running All — Static + Dynamic + " + profs.length + " EDR...", "#FF9800");
        setBtnsEnabled(false);
        ax.service_command("cheshire", "run_all", {
            md5: currentMD5, static: true, dynamic: true,
            dyn_args: parseArgs(dynArgsLine.text()), profiles: profs,
        });
    });
}

function runStatic() {
    ensureUploaded(function() {
        setStatus("Running static analysis...", "#FF9800");
        setBtnsEnabled(false);
        ax.service_command("cheshire", "run_static", { md5: currentMD5 });
    });
}

function runDynamic() {
    ensureUploaded(function() {
        setStatus("Running dynamic analysis (executing on LitterBox host)...", "#FF9800");
        setBtnsEnabled(false);
        ax.service_command("cheshire", "run_dynamic", {
            md5: currentMD5, args: parseArgs(dynArgsLine.text()),
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
        setStatus("Dispatching to " + profs.length + " EDR profile(s)...", "#FF9800");
        setBtnsEnabled(false);
        ax.service_command("cheshire", "run_edr", { md5: currentMD5, profiles: profs });
    });
}

// ── Renderers ────────────────────────────────────────────────────────────────

function renderProfiles(profilesData, agentsData) {
    let profs = (profilesData && profilesData.profiles) ? profilesData.profiles : [];
    let agentsArr = (agentsData && agentsData.agents) ? agentsData.agents : [];
    let agentsMap = {};
    for (let i = 0; i < agentsArr.length; i++) {
        let a = agentsArr[i];
        if (a && a.name) agentsMap[a.name] = a;
    }

    profileChecks = {};
    let layout = form.create_hlayout();
    let reachable = 0;

    if (profs.length === 0) {
        fleetLabel.setText("<i style='color:#F44336'>No EDR profiles configured</i>");
    } else {
        for (let i = 0; i < profs.length; i++) {
            let p = profs[i];
            let name = p.name;
            let display = p.display_name || name;
            let kind = p.kind || "elastic";
            let a = agentsMap[name] || {};
            let ag = a.agent || {};
            let el = a.elastic || {};
            let agentOk = !!ag.reachable;
            let backendOk = (kind === "elastic") ? !!el.reachable : agentOk;
            let healthy = agentOk && backendOk;

            let badge = healthy ? "●" : (agentOk ? "◐" : "○");
            let bcol  = healthy ? "#4CAF50" : (agentOk ? "#FFD700" : "#F44336");
            let suffix = "";
            if (ag.hostname) suffix += " — " + ag.hostname;
            if (kind === "elastic" && el.cluster_name) suffix += " / " + el.cluster_name;

            let label = "<span style='color:" + bcol + "'>" + badge + "</span> " + display + " (" + kind + ")" + suffix;
            let chk = form.create_check(label);
            chk.setChecked(healthy);
            chk.setEnabled(healthy);
            profileChecks[name] = chk;
            layout.addWidget(chk);
            if (healthy) reachable++;
        }
        layout.addWidget(form.create_hspacer());
        fleetLabel.setText("<b>" + reachable + "</b> of " + profs.length + " healthy");
    }
    profilesPanel.setLayout(layout);
}

function renderRisk(score, level, factors) {
    if (!scoreText) return;
    let col = levelColor(level);
    let html = "<div style='font-size:18pt;'><b>Score:</b> <span style='color:" + col + ";font-size:28pt;'>" +
               score + "</span> / 100</div>\n";
    html += "<div style='font-size:14pt;'><b>Level:</b> <span style='color:" + col + ";'>" + (level || "Unknown") + "</span></div>\n\n";
    html += "<b>Triggering indicators:</b>\n";
    let f = asArr(factors);
    if (f.length === 0) {
        html += "  (none)\n";
    } else {
        for (let i = 0; i < f.length; i++) {
            html += "  • " + f[i] + "\n";
        }
    }
    scoreText.setText(html);
}

function renderStatic(results) {
    if (!staticText) return;
    let r = results || {};
    let out = "";

    let yara = r.yara || {};
    let yMatches = asArr(yara.matches);
    out += "═══ YARA (" + yMatches.length + " matches) ═══\n";
    if (yMatches.length === 0) {
        out += "  (none)\n";
    } else {
        for (let i = 0; i < yMatches.length; i++) {
            let m = yMatches[i];
            let meta = m.metadata || {};
            out += "  • [" + (meta.severity || "?") + "] " + (m.rule || "?");
            if (meta.description) out += " — " + meta.description;
            out += "\n";
        }
    }
    out += "\n";

    let cp = r.checkplz || {};
    let f = cp.findings || {};
    let scan = f.scan_results || {};
    out += "═══ CheckPlz ═══\n";
    if (f.initial_threat) {
        out += "  ⚠ Initial threat: " + f.initial_threat + "\n";
    }
    if (scan.detection_offset) {
        out += "  Detection offset: " + scan.detection_offset + "\n";
    }
    if (!f.initial_threat && !scan.detection_offset) {
        out += "  (clean)\n";
    }
    out += "\n";

    let strn = r.stringnalyzer || {};
    let strnFindings = strn.findings || {};
    out += "═══ Stringnalyzer ═══\n";
    out += "  Total strings: " + (strnFindings.total_strings || 0) + "\n";
    let cats = [
        ["Suspicious strings",     strnFindings.found_suspicious_strings],
        ["Suspicious functions",   strnFindings.found_suspicious_functions],
        ["URLs",                   strnFindings.found_url],
        ["IP addresses",           strnFindings.found_ip],
        ["Domains",                strnFindings.found_domains],
    ];
    for (let i = 0; i < cats.length; i++) {
        let arr = asArr(cats[i][1]);
        if (arr.length === 0) continue;
        out += "  " + cats[i][0] + " (" + arr.length + "):\n";
        for (let j = 0; j < arr.length && j < 10; j++) out += "    - " + arr[j] + "\n";
        if (arr.length > 10) out += "    ... +" + (arr.length - 10) + " more\n";
    }

    staticText.setText(out);
}

function renderDynamic(results) {
    let r = results || {};

    if (dynYaraText) {
        let y = r.yara || {};
        let matches = asArr(y.matches);
        let out = "═══ YARA-mem (" + matches.length + " matches) ═══\n";
        if (matches.length === 0) out += "  (none)\n";
        for (let i = 0; i < matches.length; i++) {
            let m = matches[i];
            let meta = m.metadata || {};
            out += "  • [" + (meta.severity || "?") + "] " + (m.rule || "?") + "\n";
        }
        dynYaraText.setText(out);
    }

    if (dynPesieveText) {
        let ps = (r.pe_sieve || {}).findings || {};
        let out = "═══ PE-Sieve ═══\n";
        out += "  Total scanned:    " + (ps.total_scanned || 0) + "\n";
        out += "  Total suspicious: " + (ps.total_suspicious || 0) + "\n";
        out += "  Hooked:           " + (ps.hooked || 0) + "\n";
        out += "  Replaced:         " + (ps.replaced || 0) + "\n";
        out += "  IAT hooks:        " + (ps.iat_hooks || 0) + "\n";
        out += "  Implanted:        " + (ps.implanted || 0) + "\n";
        out += "  Implanted PE:     " + (ps.implanted_pe || 0) + "\n";
        out += "  Implanted shc:    " + (ps.implanted_shc || 0) + "\n";
        if (ps.raw_output) out += "\n" + ps.raw_output + "\n";
        dynPesieveText.setText(out);
    }

    if (dynMonetaText) {
        let m = (r.moneta || {}).findings || {};
        let pi = m.process_info || {};
        let out = "═══ Moneta ═══\n";
        if (pi.name) out += "  Process: " + pi.name + " (PID " + pi.pid + ", " + pi.arch + ")\n";
        out += "  Total regions:        " + (m.total_regions || 0) + "\n";
        out += "  Private RWX:          " + (m.total_private_rwx || 0) + "\n";
        out += "  Private RX:           " + (m.total_private_rx || 0) + "\n";
        out += "  Modified Code:        " + (m.total_modified_code || 0) + "\n";
        out += "  Heap Executable:      " + (m.total_heap_executable || 0) + "\n";
        out += "  Modified PE Header:   " + (m.total_modified_pe_header || 0) + "\n";
        out += "  Inconsistent X:       " + (m.total_inconsistent_x || 0) + "\n";
        out += "  Missing PEB:          " + (m.total_missing_peb || 0) + "\n";
        out += "  Mismatching PEB:      " + (m.total_mismatching_peb || 0) + "\n";
        out += "  Threads in non-image: " + (m.total_threads_non_image || 0) + "\n";
        dynMonetaText.setText(out);
    }

    if (dynPatriotText) {
        let p = (r.patriot || {}).findings || {};
        let proc = p.process_info || {};
        let sum = p.scan_summary || {};
        let findings = asArr(p.findings);
        let out = "═══ Patriot ═══\n";
        if (proc.process_name) out += "  Process: " + proc.process_name + " (PID " + proc.pid + ")\n";
        out += "  Total findings: " + (sum.total_findings || 0) + "\n\n";
        for (let i = 0; i < findings.length; i++) {
            let fnd = findings[i];
            out += "  • [" + (fnd.level || "?") + "] " + (fnd.type || "?") + "\n";
            if (fnd.details) out += "    " + fnd.details + "\n";
        }
        dynPatriotText.setText(out);
    }

    if (dynHsbText) {
        let h = (r.hsb || {}).findings || {};
        let summary = h.summary || {};
        let detections = asArr(h.detections);
        let first = detections.length > 0 ? detections[0] : null;
        let out = "═══ HSB — Hunt Sleeping Beacons ═══\n";
        out += "  Findings:        " + (summary.total_findings || 0) + "\n";
        out += "  Threads scanned: " + (summary.scanned_threads || 0) + "\n";
        if (first) {
            out += "  Process:         " + first.process_name + " (PID " + first.pid + ")\n\n";
            let fnds = asArr(first.findings);
            for (let i = 0; i < fnds.length; i++) {
                let fnd = fnds[i];
                out += "  • [" + (fnd.severity || "?") + "] " + (fnd.type || "?");
                if (fnd.thread_id) out += " (thread " + fnd.thread_id + ")";
                out += "\n";
                if (fnd.description) out += "    " + fnd.description + "\n";
            }
        }
        dynHsbText.setText(out);
    }

    if (dynRedEdrText) {
        let re = (r.rededr || {}).findings || {};
        let summary = re.summary || {};
        let defs = asArr(re.defender_events);
        let threats = 0;
        for (let i = 0; i < defs.length; i++) if (defs[i].category === "threat") threats++;

        let out = "═══ RedEdr ═══\n";
        out += "  Defender threats: " + threats + "\n";
        out += "  Total events:     " + (summary.total_events || 0) + "\n";
        out += "  DLLs loaded:      " + (summary.total_dlls || 0) + "\n";
        out += "  Child processes:  " + (summary.total_child_processes || 0) + "\n";
        out += "  Network events:   " + (summary.total_network_activity || 0) + "\n";
        out += "  Audit API calls:  " + (summary.total_audit_api_calls || 0) + "\n";

        if (threats > 0) {
            out += "\n  ⚠ Defender threat verdicts:\n";
            for (let i = 0; i < defs.length; i++) {
                if (defs[i].category !== "threat") continue;
                out += "    • " + (defs[i].verdict || defs[i].event || "threat");
                if (defs[i].scan_target) out += " — " + defs[i].scan_target;
                out += "\n";
            }
        }
        dynRedEdrText.setText(out);
    }
}

function renderEdrProfile(profile, data) {
    let entry = edrTabsByProfile[profile];
    if (!entry) {
        if (Object.keys(edrTabsByProfile).length === 0 && edrOuterTabs) {
            // Can't remove — leave the placeholder
        }
        let alertsTable = form.create_table(["Severity", "Rule", "Process", "Trigger", "Detected"]);
        alertsTable.setSortingEnabled(true);
        let detailText = form.create_textmulti();
        detailText.setReadOnly(true);
        detailText.setPlaceholder("Click an alert to inspect details.");

        let stash = [];

        form.connect(alertsTable, "cellClicked", function(row, col) {
            if (!entry || !entry.stash || row < 0 || row >= entry.stash.length) return;
            renderEdrAlertDetail(entry.detail, entry.stash[row]);
        });

        let lay = form.create_vlayout();
        lay.addWidget(form.create_label("<b>Alerts</b>"));
        lay.addWidget(alertsTable);
        lay.addWidget(form.create_label("<b>Alert detail</b>"));
        lay.addWidget(detailText);
        let panel = form.create_panel(); panel.setLayout(lay);

        edrOuterTabs.addTab(panel, profile);
        entry = { table: alertsTable, detail: detailText, stash: stash };
        edrTabsByProfile[profile] = entry;
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
        if (p.name)          txt += "  Name:        " + p.name + "\n";
        if (p.pid != null)   txt += "  PID:         " + p.pid + "\n";
        if (p.command_line)  txt += "  Cmdline:     " + p.command_line + "\n";
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

        case "profiles":
            renderProfiles(r.profiles, r.agents);
            break;

        case "submitted":
            currentMD5 = r.md5;
            currentFileName = r.file_name;
            setStatus("Uploaded: " + r.file_name + " (" + r.md5 + ")", "#4CAF50");
            cleanupBtn && cleanupBtn.setEnabled(true);
            if (pendingAction) {
                let a = pendingAction; pendingAction = null; a();
            } else {
                setBtnsEnabled(true);
            }
            break;

        case "static_results":
            renderStatic(r.results);
            setBtnsEnabled(true);
            break;

        case "dynamic_results":
            renderDynamic(r.results);
            if (r.early_term) setStatus("Dynamic: early termination", "#FFD700");
            setBtnsEnabled(true);
            break;

        case "edr_phase1":
            renderEdrProfile(r.profile, r.data);
            break;

        case "edr_polling":
            renderEdrProfile(r.profile, r.data);
            break;

        case "edr_results":
            renderEdrProfile(r.profile, r.data);
            setBtnsEnabled(true);
            break;

        case "edr_error":
            setStatus("EDR " + r.profile + ": " + r.message, "#F44336");
            setBtnsEnabled(true);
            break;

        case "risk_results":
            renderRisk(r.risk_score, r.risk_level, r.risk_factors);
            break;

        case "all_done":
            setStatus("All analyses complete.", "#4CAF50");
            setBtnsEnabled(true);
            break;

        case "cleaned":
            setStatus("Cleaned " + (r.md5 || "") + " from LitterBox", "#888");
            currentMD5 = null;
            currentFileName = null;
            cleanupBtn && cleanupBtn.setEnabled(false);
            clearResults();
            break;

        case "error":
            setStatus("Error: " + (r.message || "?"), "#F44336");
            setBtnsEnabled(true);
            ax.show_message("Cheshire Error", r.message || "Unknown error");
            break;
    }
}
