// ── State ────────────────────────────────────────────────────────────────────

var currentMD5        = null;
var currentFileName   = null;
var statusLabel       = null;
var runBtn            = null;
var cleanupBtn        = null;
var profileCombo      = null;
var staticCheck       = null;
var edrCheck          = null;
var filePathLabel     = null;

// Result widgets
var scoreText         = null;
var staticText        = null;
var edrAlertsTable    = null;
var edrExecText       = null;
var tabWidget         = null;

// ── Entry ─────────────────────────────────────────────────────────────────────

function InitService() {
    let action = menu.create_action("Test with Cheshire", function() {
        showCheshireDialog();
    });
    menu.add_session_main(action);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function setStatus(text, color) {
    if (statusLabel) {
        statusLabel.setText("<b style='color:" + color + "'>" + text + "</b>");
    }
}

function setRunEnabled(enabled) {
    if (runBtn) runBtn.setEnabled(enabled);
}

function setCleanupEnabled(enabled) {
    if (cleanupBtn) cleanupBtn.setEnabled(enabled);
}

function fmtJSON(obj) {
    try { return JSON.stringify(obj, null, 2); } catch(e) { return String(obj); }
}

function severityColor(sev) {
    if (!sev) return "#aaa";
    let s = sev.toLowerCase();
    if (s === "critical") return "#FF4444";
    if (s === "high")     return "#FF8800";
    if (s === "medium")   return "#FFD700";
    if (s === "low")      return "#4CAF50";
    return "#aaa";
}

// ── Main dialog ───────────────────────────────────────────────────────────────

function showCheshireDialog() {
    currentMD5      = null;
    currentFileName = null;

    // ── File group ────────────────────────────────────────────────────────────

    let fileGroup  = form.create_groupbox("Payload", false);
    filePathLabel  = form.create_label("<i style='color:#888'>No file selected</i>");
    let browseBtn  = form.create_button("Browse...");

    form.connect(browseBtn, "clicked", function() {
        let path = ax.prompt_open_file("Select payload", "All Files (*)");
        if (path && path.length > 0) {
            filePathLabel.setText(path);
            currentMD5      = null;
            currentFileName = null;
            setCleanupEnabled(false);
            setStatus("File selected — click Run to upload & analyze", "#888");
            scoreText && scoreText.setText("");
            staticText && staticText.setText("");
            edrAlertsTable && edrAlertsTable.clear();
            edrExecText && edrExecText.setText("");
        }
    });

    let fileLayout = form.create_hlayout();
    fileLayout.addWidget(browseBtn);
    fileLayout.addWidget(filePathLabel);
    fileLayout.addWidget(form.create_hspacer());
    let filePanel = form.create_panel();
    filePanel.setLayout(fileLayout);
    fileGroup.setPanel(filePanel);

    // ── Analysis options group ────────────────────────────────────────────────

    let optGroup  = form.create_groupbox("Analysis Options", false);
    staticCheck   = form.create_check("Static (YARA / CheckPlz / Stringnalyzer)");
    staticCheck.setChecked(true);
    edrCheck      = form.create_check("EDR");
    edrCheck.setChecked(true);
    profileCombo  = form.create_combo();
    profileCombo.addItems(["loading..."]);

    let optLayout = form.create_gridlayout();
    optLayout.addWidget(staticCheck,  0, 0, 1, 1);
    optLayout.addWidget(edrCheck,     1, 0, 1, 1);
    optLayout.addWidget(form.create_label("Profile:"), 1, 1, 1, 1);
    optLayout.addWidget(profileCombo, 1, 2, 1, 1);
    optLayout.addWidget(form.create_hspacer(), 1, 3, 1, 1);
    let optPanel = form.create_panel();
    optPanel.setLayout(optLayout);
    optGroup.setPanel(optPanel);

    // ── Control bar ───────────────────────────────────────────────────────────

    statusLabel = form.create_label("<b style='color:#888'>Ready</b>");
    runBtn      = form.create_button("Run");
    cleanupBtn  = form.create_button("Cleanup");
    cleanupBtn.setEnabled(false);

    form.connect(runBtn, "clicked", function() {
        let path = filePathLabel.text();
        if (!path || path.indexOf("No file") >= 0) {
            ax.show_message("Cheshire", "Select a payload file first.");
            return;
        }
        setRunEnabled(false);
        setCleanupEnabled(false);
        scoreText && scoreText.setText("");
        staticText && staticText.setText("");
        edrAlertsTable && edrAlertsTable.clear();
        edrExecText && edrExecText.setText("");
        setStatus("Uploading...", "#FF9800");
        ax.service_command("cheshire", "submit", { file_path: path });
    });

    form.connect(cleanupBtn, "clicked", function() {
        if (!currentMD5) return;
        setStatus("Cleaning up...", "#888");
        ax.service_command("cheshire", "cleanup", { md5: currentMD5 });
    });

    let barLayout = form.create_hlayout();
    barLayout.addWidget(statusLabel);
    barLayout.addWidget(form.create_hspacer());
    barLayout.addWidget(cleanupBtn);
    barLayout.addWidget(runBtn);
    let barPanel = form.create_panel();
    barPanel.setLayout(barLayout);

    // ── Score tab ────────────────────────────────────────────────────────────

    scoreText = form.create_textmulti();
    scoreText.setReadOnly(true);
    scoreText.setPlaceholder("Risk assessment will appear here after analysis.");
    let scorePanel = form.create_panel();
    let scoreLayout = form.create_vlayout();
    scoreLayout.addWidget(scoreText);
    scorePanel.setLayout(scoreLayout);

    // ── Static tab ───────────────────────────────────────────────────────────

    staticText = form.create_textmulti();
    staticText.setReadOnly(true);
    staticText.setPlaceholder("Static analysis results will appear here.");
    let staticPanel = form.create_panel();
    let staticLayout = form.create_vlayout();
    staticLayout.addWidget(staticText);
    staticPanel.setLayout(staticLayout);

    // ── EDR tab ──────────────────────────────────────────────────────────────

    edrAlertsTable = form.create_table(["Severity", "Rule", "Event", "Process", "Call Stack"]);
    edrAlertsTable.setSortingEnabled(true);

    edrExecText = form.create_textmulti();
    edrExecText.setReadOnly(true);
    edrExecText.setPlaceholder("Execution log will appear here.");

    let edrSplitLayout = form.create_vlayout();
    edrSplitLayout.addWidget(edrAlertsTable);
    edrSplitLayout.addWidget(form.create_label("<b>Execution Log</b>"));
    edrSplitLayout.addWidget(edrExecText);
    let edrPanel = form.create_panel();
    edrPanel.setLayout(edrSplitLayout);

    // ── Tabs ──────────────────────────────────────────────────────────────────

    tabWidget = form.create_tabs();
    tabWidget.addTab(scorePanel,  "Score");
    tabWidget.addTab(staticPanel, "Static");
    tabWidget.addTab(edrPanel,    "EDR");

    // ── Main layout ───────────────────────────────────────────────────────────

    let mainLayout = form.create_vlayout();
    mainLayout.addWidget(fileGroup);
    mainLayout.addWidget(optGroup);
    mainLayout.addWidget(barPanel);
    mainLayout.addWidget(tabWidget);

    let dialog = form.create_dialog("Cheshire — Payload Analysis");
    dialog.setSize(950, 700);
    dialog.setLayout(mainLayout);
    dialog.setButtonsText("", "Close");

    // Fetch EDR profiles on open
    ax.service_command("cheshire", "get_profiles", {});

    dialog.exec();

    // Cleanup state
    currentMD5        = null;
    currentFileName   = null;
    statusLabel       = null;
    runBtn            = null;
    cleanupBtn        = null;
    profileCombo      = null;
    staticCheck       = null;
    edrCheck          = null;
    filePathLabel     = null;
    scoreText         = null;
    staticText        = null;
    edrAlertsTable    = null;
    edrExecText       = null;
    tabWidget         = null;
}

// ── data_handler ──────────────────────────────────────────────────────────────

function data_handler(data) {
    let r = JSON.parse(data);

    switch (r.action) {

        case "profiles":
            if (!profileCombo) break;
            profileCombo.clear();
            let profs = (r.profiles && r.profiles.profiles) ? r.profiles.profiles : [];
            if (profs.length === 0) {
                profileCombo.addItems(["(no profiles)"]);
            } else {
                let names = [];
                for (let i = 0; i < profs.length; i++) names.push(profs[i].name || profs[i].display_name || "profile");
                profileCombo.addItems(names);
            }
            break;

        case "submitted":
            currentMD5      = r.md5;
            currentFileName = r.file_name;
            setStatus("Uploaded: " + r.file_name + " (" + r.md5 + ")", "#4CAF50");

            // Fire requested analyses
            let doStatic = staticCheck && staticCheck.isChecked();
            let doEdr    = edrCheck && edrCheck.isChecked();

            if (doStatic) {
                setStatus("Running static analysis...", "#FF9800");
                ax.service_command("cheshire", "run_static", { md5: r.md5 });
            }
            if (doEdr && profileCombo) {
                let prof = profileCombo.currentText();
                if (prof && prof !== "(no profiles)" && prof !== "loading...") {
                    if (!doStatic) setStatus("Running EDR analysis...", "#FF9800");
                    ax.service_command("cheshire", "run_edr", { md5: r.md5, profile: prof });
                }
            }
            if (!doStatic && !doEdr) {
                setRunEnabled(true);
                setCleanupEnabled(true);
                setStatus("Uploaded. No analyses selected.", "#888");
            }
            break;

        case "static_results":
            if (!staticText) break;
            try {
                let res    = r.results || {};
                let out    = "";
                let yara   = res.yara_results;
                let checkp = res.checkplz_results;
                let strn   = res.stringnalyzer_results;

                if (yara) {
                    out += "=== YARA ===\n";
                    let matches = yara.matches || [];
                    out += matches.length > 0 ? matches.join("\n") : "No matches";
                    out += "\n\n";
                }
                if (checkp) {
                    out += "=== CheckPlz ===\n";
                    out += fmtJSON(checkp) + "\n\n";
                }
                if (strn) {
                    out += "=== Stringnalyzer ===\n";
                    out += fmtJSON(strn) + "\n\n";
                }
                staticText.setText(out || fmtJSON(res));
            } catch(e) {
                staticText.setText(fmtJSON(r.results));
            }
            if (tabWidget) tabWidget.setCurrentIndex(1);

            // Now fetch risk
            if (currentMD5) {
                ax.service_command("cheshire", "get_risk", { md5: currentMD5 });
            }
            setCleanupEnabled(true);
            // Re-enable run only if EDR is not pending
            let edrPending = edrCheck && edrCheck.isChecked() && profileCombo &&
                             profileCombo.currentText() !== "(no profiles)" &&
                             profileCombo.currentText() !== "loading...";
            if (!edrPending) {
                setRunEnabled(true);
                setStatus("Static analysis complete.", "#4CAF50");
            }
            break;

        case "edr_phase1":
            setStatus("Payload executing on EDR VM — waiting for alerts...", "#FF9800");
            if (r.data && r.data.execution) {
                let exec = r.data.execution;
                let log  = "PID: " + (exec.pid || "?") + "\n" +
                           "Exit code: " + (exec.exit_code !== undefined ? exec.exit_code : "?") + "\n" +
                           "Killed by EDR: " + (exec.killed_by_edr ? "yes" : "no") + "\n\n";
                if (exec.stdout) log += "stdout:\n" + exec.stdout + "\n";
                if (exec.stderr) log += "stderr:\n" + exec.stderr + "\n";
                if (edrExecText) edrExecText.setText(log);
            }
            if (tabWidget) tabWidget.setCurrentIndex(2);
            break;

        case "edr_polling":
            if (!r.data) break;
            let total = (r.data.summary && r.data.summary.total_alerts) ? r.data.summary.total_alerts : 0;
            setStatus("EDR: polling alerts... (" + total + " so far)", "#FF9800");
            renderEdrAlerts(r.data);
            break;

        case "edr_results":
            renderEdrAlerts(r.data);
            let edrStatus = (r.data && r.data.status) ? r.data.status : "completed";
            let alertCount = (r.data && r.data.summary && r.data.summary.total_alerts) ? r.data.summary.total_alerts : 0;
            setStatus("EDR done — " + alertCount + " alert(s) [" + edrStatus + "]", alertCount > 0 ? "#F44336" : "#4CAF50");
            setRunEnabled(true);
            setCleanupEnabled(true);

            if (currentMD5) {
                ax.service_command("cheshire", "get_risk", { md5: currentMD5 });
            }
            if (tabWidget) tabWidget.setCurrentIndex(2);
            break;

        case "risk_results":
            if (!scoreText) break;
            let score  = r.risk_score !== undefined ? r.risk_score : "?";
            let level  = r.risk_level || "unknown";
            let factors = r.risk_factors || [];
            let col = "#4CAF50";
            if (level === "Critical") col = "#FF4444";
            else if (level === "High") col = "#FF8800";
            else if (level === "Medium") col = "#FFD700";

            let txt = "Score: " + score + " / 100   Level: " + level + "\n\n";
            txt += "Risk Factors:\n";
            for (let i = 0; i < factors.length; i++) {
                let f = factors[i];
                txt += "  • [" + (f.severity || "?").toUpperCase() + "] " + (f.message || fmtJSON(f)) + "\n";
            }
            scoreText.setText(txt);
            if (tabWidget) tabWidget.setCurrentIndex(0);
            break;

        case "cleaned":
            setStatus("Cleaned up " + (r.md5 || ""), "#888");
            currentMD5      = null;
            currentFileName = null;
            setCleanupEnabled(false);
            break;

        case "error":
            setStatus("Error: " + (r.message || "unknown"), "#F44336");
            setRunEnabled(true);
            ax.show_message("Cheshire Error", r.message || "Unknown error");
            break;
    }
}

function renderEdrAlerts(data) {
    if (!data || !edrAlertsTable) return;

    let alerts = (data.alerts) ? data.alerts : [];
    edrAlertsTable.clear();

    for (let i = 0; i < alerts.length; i++) {
        let a   = alerts[i];
        let sev = a.severity || "";
        let rule = a.title || "";
        let event = (a.details && a.details.api && a.details.api.name) ? a.details.api.name : "";
        let proc = "";
        if (a.details && a.details.process) {
            proc = a.details.process.name || a.details.process.executable || "";
        }
        let cs = "";
        if (a.details && a.details.call_stack_summary) {
            cs = a.details.call_stack_summary;
        } else if (a.details && a.details.call_stack_final_user_module) {
            cs = a.details.call_stack_final_user_module;
        }
        edrAlertsTable.addItem([sev, rule, event, proc, cs]);
    }

    // Update exec log if we have execution data
    if (data.execution && edrExecText) {
        let exec = data.execution;
        let log  = "PID: " + (exec.pid || "?") + "\n" +
                   "Exit code: " + (exec.exit_code !== undefined ? exec.exit_code : "?") + "\n" +
                   "Killed by EDR: " + (exec.killed_by_edr ? "yes" : "no") + "\n\n";
        if (exec.stdout) log += "stdout:\n" + exec.stdout + "\n";
        if (exec.stderr) log += "stderr:\n" + exec.stderr + "\n";
        edrExecText.setText(log);
    }
}
