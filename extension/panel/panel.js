// panel.js — PixelSpy DevTools Panel v2.0
// Tabbed UI: Dashboard · Issues · Attack Surface · Events

// ── State ─────────────────────────────────────────────────────────────────────

let allIssues      = [];
let allEvents      = [];
let lastSurface    = null;
let lastScore      = null;
let activeTab      = "dashboard";
let activeTypeFilter = "ALL";
let activeSevFilter  = "ALL";
let selectedIssueId  = null;
let pollInterval     = null;

// ── Boot ──────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    initTabs();
    bindToolbar();
    bindFilters();
    startEventPoll();
});

// ── Theme Management ──────────────────────────────────────────────────────────

function initTheme() {
    const savedTheme = localStorage.getItem('pixelspy-theme') || 'dark';
    document.body.setAttribute('data-theme', savedTheme);
    updateThemeBtn(savedTheme);

    document.getElementById('theme-toggle').addEventListener('click', () => {
        const current = document.body.getAttribute('data-theme');
        const target = current === 'dark' ? 'light' : 'dark';
        document.body.setAttribute('data-theme', target);
        localStorage.setItem('pixelspy-theme', target);
        updateThemeBtn(target);
    });
}

function updateThemeBtn(theme) {
    const btn = document.getElementById('theme-toggle');
    btn.textContent = theme === 'dark' ? '☀️' : '🌙';
}

// ── Tab System ────────────────────────────────────────────────────────────────

function initTabs() {
    document.getElementById("tab-nav").addEventListener("click", e => {
        const btn = e.target.closest(".tab-btn");
        if (!btn || !btn.dataset.tab) return;
        switchTab(btn.dataset.tab);
    });
}

function switchTab(tabName) {
    activeTab = tabName;

    document.querySelectorAll(".tab-btn").forEach(b => {
        b.classList.toggle("active", b.dataset.tab === tabName);
    });
    document.querySelectorAll(".tab-pane").forEach(p => {
        p.classList.toggle("active", p.id === `tab-${tabName}`);
    });
}

// ── Toolbar ───────────────────────────────────────────────────────────────────

function bindToolbar() {
    document.getElementById("btn-scan").addEventListener("click", runScan);
    document.getElementById("btn-clear").addEventListener("click", clearAll);
    document.getElementById("btn-export").addEventListener("click", exportReport);
}

function runScan() {
    setStatus("Scanning…", true);
    document.getElementById("btn-scan").disabled = true;

    sendToContent("RUN_SCAN", response => {
        document.getElementById("btn-scan").disabled = false;

        if (!response || !response.success) {
            setStatus("Scan failed — is the page fully loaded?", false);
            return;
        }

        const report = response.report;
        allIssues  = report.issues  || [];
        allEvents  = report.events  || [];
        lastSurface = report.attackSurface  || null;
        lastScore   = report.securityScore  || null;

        renderDashboard();
        renderIssueList();
        renderAttackSurface();
        renderEventStream();
        updateBadges();

        const count = allIssues.length;
        setStatus(
            `Scan complete — ${count} issue${count !== 1 ? "s" : ""} found.`,
            false, count
        );

        // Auto-switch to dashboard to show results
        switchTab("dashboard");
    });
}

function clearAll() {
    allIssues     = [];
    allEvents     = [];
    lastSurface   = null;
    lastScore     = null;
    selectedIssueId = null;

    renderDashboard();
    renderIssueList();
    renderAttackSurface();
    renderEventStream();
    updateBadges();

    setStatus("Cleared.", false, 0);
    document.getElementById("issue-count").classList.add("hidden");
}

function exportReport() {
    const data = {
        exportedAt: new Date().toISOString(),
        url: location.href,
        securityScore: lastScore,
        issues: allIssues,
        attackSurface: lastSurface,
        events: allEvents
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = `pixelspy-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

// ── Badge Updates ─────────────────────────────────────────────────────────────

function updateBadges() {
    const issueBadge = document.getElementById("tab-badge-issues");
    const eventBadge = document.getElementById("tab-badge-events");

    if (allIssues.length > 0) {
        issueBadge.textContent = allIssues.length;
        issueBadge.classList.remove("hidden");
    } else {
        issueBadge.classList.add("hidden");
    }

    eventBadge.textContent = allEvents.length;
}

// ── DASHBOARD ─────────────────────────────────────────────────────────────────

function renderDashboard() {
    renderScoreRing();
    renderStatCards();
    renderCategoryScores();
    renderOwaspGrid();
    renderSurfaceFindings();
}

function renderScoreRing() {
    const scoreEl  = document.getElementById("score-number");
    const gradeEl  = document.getElementById("score-grade");
    const subEl    = document.getElementById("score-meta-sub");
    const chipVal  = document.getElementById("score-chip-value");
    const ringFill = document.getElementById("score-ring-fill");

    if (!lastScore) {
        scoreEl.textContent  = "—";
        gradeEl.textContent  = "–";
        subEl.textContent    = "Run a scan to evaluate";
        chipVal.textContent  = "—";
        ringFill.style.strokeDashoffset = "201";
        return;
    }

    const s = lastScore.overall;
    const circumference = 201; // 2 * PI * 32
    const offset = circumference - (s / 100) * circumference;

    scoreEl.textContent = s;
    gradeEl.textContent = lastScore.grade;
    gradeEl.style.color = lastScore.gradeColor;
    scoreEl.style.color = lastScore.gradeColor;
    ringFill.style.stroke = lastScore.gradeColor;
    ringFill.style.strokeDashoffset = offset.toFixed(1);
    subEl.textContent = `${lastScore.gradeLabel} · ${lastScore.issueCount} issue${lastScore.issueCount !== 1 ? "s" : ""}`;
    chipVal.textContent = `${s}/100`;
    chipVal.style.color = lastScore.gradeColor;
    document.getElementById("score-chip").style.borderColor =
        lastScore.gradeColor + "55";
}

function renderStatCards() {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    allIssues.forEach(i => {
        const sev = (i.severity || "LOW").toUpperCase();
        if (counts[sev] !== undefined) counts[sev]++;
    });
    document.getElementById("stat-val-critical").textContent = counts.CRITICAL;
    document.getElementById("stat-val-high").textContent     = counts.HIGH;
    document.getElementById("stat-val-medium").textContent   = counts.MEDIUM;
}

function renderCategoryScores() {
    const el = document.getElementById("category-list");
    if (!lastScore) {
        el.innerHTML = `<div class="category-empty">Run a scan to see scores.</div>`;
        return;
    }

    el.innerHTML = Object.entries(lastScore.categories).map(([key, cat]) => {
        const barColor = cat.score >= 80 ? "var(--score-a)"
                       : cat.score >= 60 ? "var(--score-b)"
                       : cat.score >= 40 ? "var(--score-c)"
                       : "var(--score-f)";
        return `
          <div class="category-row">
            <div class="category-label">${escHtml(cat.label)}</div>
            <div class="category-bar-wrap">
              <div class="category-bar" style="width:${cat.score}%; background:${barColor}"></div>
            </div>
            <div class="category-score-val" style="color:${barColor}">${cat.score}</div>
          </div>`;
    }).join("");
}

function renderOwaspGrid() {
    const el = document.getElementById("owasp-grid");
    if (!lastScore || !lastScore.owaspTop10) {
        el.innerHTML = `<div class="category-empty">Run a scan to see OWASP status.</div>`;
        return;
    }

    el.innerHTML = lastScore.owaspTop10.map(item => `
      <div class="owasp-item ${item.affected ? "affected" : ""}">
        <div class="owasp-item-id">${escHtml(item.id)}</div>
        <div class="owasp-item-name">${escHtml(item.name)}</div>
      </div>`
    ).join("");
}

function renderSurfaceFindings() {
    const el = document.getElementById("findings-list");
    if (!lastSurface || !lastSurface.metadata.findings.length) {
        el.innerHTML = `<div class="category-empty">${lastSurface ? "No surface findings." : "Run a scan to see findings."}</div>`;
        return;
    }

    el.innerHTML = lastSurface.metadata.findings.map(f => `
      <div class="finding-row">
        <span class="finding-sev ${escHtml(f.severity)}">${escHtml(f.severity)}</span>
        <span class="finding-text">${escHtml(f.text)}</span>
      </div>`
    ).join("");
}

// ── FILTER BINDINGS ───────────────────────────────────────────────────────────

function bindFilters() {
    document.getElementById("filter-type").addEventListener("click", e => {
        const btn = e.target.closest(".filter-btn");
        if (!btn) return;
        document.querySelectorAll("#filter-type .filter-btn")
            .forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        activeTypeFilter = btn.dataset.filter;
        renderIssueList();
    });

    document.getElementById("filter-severity").addEventListener("click", e => {
        const btn = e.target.closest(".filter-btn");
        if (!btn) return;
        document.querySelectorAll("#filter-severity .filter-btn")
            .forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        activeSevFilter = btn.dataset.sev;
        renderIssueList();
    });
}

function getFilteredIssues() {
    return allIssues.filter(issue => {
        const typeOk = activeTypeFilter === "ALL" || issue.type === activeTypeFilter;
        const sevOk  = activeSevFilter  === "ALL" || issue.severity === activeSevFilter;
        return typeOk && sevOk;
    });
}

// ── ISSUE LIST ────────────────────────────────────────────────────────────────

function renderIssueList() {
    const list     = document.getElementById("issue-list");
    const filtered = getFilteredIssues();

    list.innerHTML = "";

    if (filtered.length === 0) {
        const em = document.createElement("div");
        em.className   = "empty-state";
        em.textContent = allIssues.length === 0
            ? "No issues found. Run a scan."
            : "No issues match the current filters.";
        list.appendChild(em);
        return;
    }

    filtered.forEach(issue => {
        const row = document.createElement("div");
        row.className = "issue-row slide-in" +
            (issue.id === selectedIssueId ? " selected" : "");
        row.dataset.id = issue.id;

        const typeClass = (issue.type || "").toLowerCase();
        const sevClass  = (issue.severity || "LOW").toLowerCase();

        row.innerHTML = `
          <div class="issue-left">
            <div class="type-dot ${typeClass}"></div>
            <div class="sev-badge ${sevClass}">${escHtml(issue.severity || "LOW")}</div>
          </div>
          <div class="issue-body">
            <div class="issue-title">${escHtml(buildIssueTitle(issue))}</div>
            <div class="issue-sub">${escHtml(buildIssueSub(issue))}</div>
          </div>`;

        row.addEventListener("click", () => {
            document.querySelectorAll(".issue-row")
                .forEach(r => r.classList.remove("selected"));
            row.classList.add("selected");
            selectedIssueId = issue.id;
            renderDetail(issue);
            // Switch to issues tab if on dashboard
            if (activeTab !== "issues") switchTab("issues");
        });

        list.appendChild(row);
    });
}

function buildIssueTitle(issue) {
    if (issue.type === "XSS")  return `${issue.context || ""} XSS — ${issue.sink || ""}`;
    if (issue.type === "SQLi") return `SQLi — ${issue.confidence || ""} confidence`;
    return issue.type || "Unknown";
}

function buildIssueSub(issue) {
    if (issue.type === "XSS") {
        return issue.source
            ? `${issue.source} → ${issue.variable || "?"} → ${issue.sink || "?"}`
            : issue.detail || "";
    }
    if (issue.type === "SQLi") {
        const url = issue.url || "";
        return url.length > 55 ? "…" + url.slice(-52) : url;
    }
    return issue.detail || "";
}

// ── DETAIL PANEL ──────────────────────────────────────────────────────────────

function renderDetail(issue) {
    const container = document.getElementById("detail-content");
    if (!issue) {
        container.innerHTML = `<div class="empty-state">Select an issue to view details.</div>`;
        return;
    }
    if (issue.type === "XSS")  container.innerHTML = buildXSSDetail(issue);
    else if (issue.type === "SQLi") container.innerHTML = buildSQLiDetail(issue);
    else container.innerHTML = `<div class="empty-state">${escHtml(issue.detail || "No details.")}</div>`;
}

function buildXSSDetail(issue) {
    const sev = (issue.severity || "").toLowerCase();

    const hasFlow = issue.source && issue.variable;
    const flowHTML = hasFlow ? (() => {
        const nodes = [
            { icon: "SRC", cls: "source", label: issue.source || "unknown",    meta: `line ${issue.sourceLine || "?"}` },
            { icon: "VAR", cls: "var",    label: issue.variable || "?",         meta: "tainted" },
            { icon: "SNK", cls: "sink",   label: issue.sink || "unknown sink",  meta: `line ${issue.sinkLine || "?"}` }
        ];
        return `<div class="flow-trace">
          <div class="flow-trace-title">Data Flow Trace</div>
          <div class="flow-chain">
            ${nodes.map((n, i) => `
              ${i > 0 ? '<div class="flow-connector"></div>' : ""}
              <div class="flow-node">
                <div class="flow-node-icon ${n.cls}">${n.icon}</div>
                <div class="flow-node-label">${escHtml(n.label)}</div>
                <div class="flow-node-meta">${escHtml(n.meta)}</div>
              </div>`).join("")}
          </div>
        </div>`;
    })() : "";

    const recommendation = issue.recommendation || "";

    return `
      <div class="detail-summary">
        <div class="detail-stat">
          <div class="detail-stat-label">Type</div>
          <div class="detail-stat-value" style="color:var(--type-xss)">XSS</div>
        </div>
        <div class="detail-stat">
          <div class="detail-stat-label">Severity</div>
          <div class="detail-stat-value" style="color:var(--sev-${sev})">${escHtml(issue.severity || "?")}</div>
        </div>
        <div class="detail-stat">
          <div class="detail-stat-label">Confidence</div>
          <div class="detail-stat-value">${escHtml(issue.confidence || "HIGH")}</div>
        </div>
      </div>

      ${flowHTML}

      <div class="context-block">
        <div class="context-block-title">Context</div>
        <div class="context-row">
          <span class="context-key">Injection point</span>
          <span class="context-value">${escHtml(issue.context || "HTML")}</span>
        </div>
        <div class="context-row">
          <span class="context-key">Sink</span>
          <span class="context-value" style="font-family:var(--font-mono);color:var(--text-code)">${escHtml(issue.sink || "—")}</span>
        </div>
        <div class="context-row">
          <span class="context-key">Sanitized</span>
          <span class="context-value" style="color:${issue.sanitized ? "var(--type-sqli)" : "var(--sev-critical)"}">
            ${issue.sanitized ? "Yes" : "None detected"}
          </span>
        </div>
        <div class="context-row">
          <span class="context-key">Engine</span>
          <span class="context-value">${escHtml(issue.engine || "AST")}</span>
        </div>
        ${issue.owaspId ? `<div class="context-row">
          <span class="context-key">OWASP</span>
          <span class="context-value">${escHtml(issue.owaspId)}: Injection</span>
        </div>` : ""}
        ${issue.detail ? `<div class="context-row">
          <span class="context-key">Detail</span>
          <span class="context-value">${escHtml(issue.detail)}</span>
        </div>` : ""}
      </div>

      ${recommendation ? `
      <div class="fix-block">
        <div class="fix-block-title">🔧 Fix Recommendation</div>
        <div class="fix-block-text">${escHtml(recommendation)}</div>
      </div>` : ""}`;
}

function buildSQLiDetail(issue) {
    const sev = (issue.severity || "").toLowerCase();
    const evidenceHTML = (issue.evidence || []).map(e => `
      <div class="evidence-item">
        <span class="evidence-bullet">›</span>
        <span>${escHtml(e)}</span>
      </div>`).join("") || `<div class="evidence-item"><span>No evidence recorded.</span></div>`;

    const recommendation = issue.recommendation || "";

    return `
      <div class="detail-summary">
        <div class="detail-stat">
          <div class="detail-stat-label">Type</div>
          <div class="detail-stat-value" style="color:var(--type-sqli)">SQLi</div>
        </div>
        <div class="detail-stat">
          <div class="detail-stat-label">Severity</div>
          <div class="detail-stat-value" style="color:var(--sev-${sev})">${escHtml(issue.severity || "?")}</div>
        </div>
        <div class="detail-stat">
          <div class="detail-stat-label">Score</div>
          <div class="detail-stat-value">${issue.score || 0} pts</div>
        </div>
      </div>

      <div class="context-block">
        <div class="context-block-title">Request Info</div>
        <div class="context-row">
          <span class="context-key">Method</span>
          <span class="context-value">${escHtml(issue.method || "GET")}</span>
        </div>
        <div class="context-row">
          <span class="context-key">Confidence</span>
          <span class="context-value">${escHtml(issue.confidence || "MEDIUM")}</span>
        </div>
        <div class="context-row">
          <span class="context-key">Engine</span>
          <span class="context-value">${escHtml(issue.engine || "RUNTIME")}</span>
        </div>
        ${issue.owaspId ? `<div class="context-row">
          <span class="context-key">OWASP</span>
          <span class="context-value">${escHtml(issue.owaspId)}: Injection</span>
        </div>` : ""}
        <div class="context-row">
          <span class="context-key">URL</span>
          <span class="context-value" style="font-family:var(--font-mono);font-size:10px;word-break:break-all">
            ${escHtml((issue.url || "").substring(0, 120))}
          </span>
        </div>
      </div>

      <div class="evidence-block">
        <div class="context-block-title">Evidence Signals</div>
        ${evidenceHTML}
      </div>

      ${recommendation ? `
      <div class="fix-block">
        <div class="fix-block-title">🔧 Fix Recommendation</div>
        <div class="fix-block-text">${escHtml(recommendation)}</div>
      </div>` : ""}`;
}

// ── ATTACK SURFACE ────────────────────────────────────────────────────────────

function renderAttackSurface() {
    const layout = document.getElementById("surface-layout");
    if (!lastSurface) {
        layout.innerHTML = `<div class="empty-state surface-empty">Run a scan to map the attack surface.</div>`;
        return;
    }

    const s = lastSurface;
    layout.innerHTML = `
      ${buildSurfaceOverviewCard(s)}
      ${buildFormsCard(s)}
      ${buildScriptsCard(s)}
      ${buildCookiesLsCard(s)}
      ${buildUrlParamsCard(s)}
      ${buildIframesCard(s)}
    `;
}

function buildSurfaceOverviewCard(s) {
    const rp = s.metadata.riskPoints || 0;
    const rpColor = rp < 20 ? "var(--score-a)" : rp < 50 ? "var(--score-b)" : rp < 80 ? "var(--score-c)" : "var(--score-f)";
    return `
      <div class="surface-card surface-card-full">
        <div class="surface-card-title">
          Surface Overview
          <span class="surface-count" style="color:${rpColor}">Risk: ${rp} pts</span>
        </div>
        <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:6px;">
          ${[
            ["Forms",       s.forms.length],
            ["Inputs",      s.metadata.totalInputVectors],
            ["Ext Scripts", s.externalScripts.filter(x => x.isExternal).length],
            ["iFrames",     s.iframes.length],
            ["URL Params",  s.urlParams.length]
          ].map(([label, val]) => `
            <div style="text-align:center;padding:8px;background:var(--bg-surface);border:1px solid var(--border);border-radius:var(--radius-md)">
              <div style="font-size:16px;font-weight:800;color:var(--text-primary)">${val}</div>
              <div style="font-size:10px;color:var(--text-muted);margin-top:2px">${label}</div>
            </div>`).join("")}
        </div>
      </div>`;
}

function buildFormsCard(s) {
    if (s.forms.length === 0) return `<div class="surface-card"><div class="surface-card-title">Forms <span class="surface-count">0</span></div><div class="empty-state" style="padding:10px">No forms found.</div></div>`;
    return `
      <div class="surface-card">
        <div class="surface-card-title">Forms <span class="surface-count">${s.forms.length}</span></div>
        <table class="surface-table">
          <thead><tr><th>ID/Action</th><th>Method</th><th>Inputs</th><th>CSRF</th><th>HTTPS</th></tr></thead>
          <tbody>
            ${s.forms.map(f => `<tr>
              <td title="${escHtml(f.action)}">${escHtml(f.id)}</td>
              <td>${escHtml(f.method)}</td>
              <td>${f.inputCount}</td>
              <td>${f.hasCsrfToken
                    ? '<span class="surface-tag ok">✓</span>'
                    : (f.method === "POST" ? '<span class="surface-tag danger">✗</span>' : '<span class="surface-tag neutral">N/A</span>')}</td>
              <td>${f.isHTTPS
                    ? '<span class="surface-tag ok">✓</span>'
                    : (f.hasPasswordField ? '<span class="surface-tag danger">✗</span>' : '<span class="surface-tag warn">No</span>')}</td>
            </tr>`).join("")}
          </tbody>
        </table>
      </div>`;
}

function buildScriptsCard(s) {
    const ext = s.externalScripts.filter(x => x.isExternal);
    if (ext.length === 0) return `<div class="surface-card"><div class="surface-card-title">External Scripts <span class="surface-count">0</span></div><div class="empty-state" style="padding:10px">No external scripts.</div></div>`;
    return `
      <div class="surface-card">
        <div class="surface-card-title">External Scripts <span class="surface-count">${ext.length}</span></div>
        <table class="surface-table">
          <thead><tr><th>Domain</th><th>SRI</th><th>Async</th></tr></thead>
          <tbody>
            ${ext.map(sc => {
                let domain = sc.src;
                try { domain = new URL(sc.src).hostname; } catch(e) {}
                return `<tr>
                  <td title="${escHtml(sc.src)}">${escHtml(domain)}</td>
                  <td>${sc.hasSRI ? '<span class="surface-tag ok">✓</span>' : '<span class="surface-tag danger">✗</span>'}</td>
                  <td>${sc.isAsync ? '<span class="surface-tag ok">async</span>' : '<span class="surface-tag neutral">sync</span>'}</td>
                </tr>`;
            }).join("")}
          </tbody>
        </table>
      </div>`;
}

function buildCookiesLsCard(s) {
    return `
      <div class="surface-card">
        <div class="surface-card-title">Cookies &amp; localStorage</div>
        ${s.cookies.length > 0 ? `
          <div style="font-size:10px;color:var(--text-muted);margin-bottom:6px;font-weight:600">JS-Readable Cookies (no HttpOnly)</div>
          ${s.cookies.map(c => `
            <div class="surface-meta-row">
              <span class="surface-meta-key">${escHtml(c.name)}</span>
              <span class="surface-tag warn">no HttpOnly</span>
            </div>`).join("")}` : `<div style="font-size:11px;color:var(--text-muted);margin-bottom:8px">No JS-readable cookies.</div>`}
        ${s.localStorage.length > 0 ? `
          <div style="font-size:10px;color:var(--text-muted);margin:8px 0 6px;font-weight:600">localStorage (${s.localStorage.length} keys)</div>
          ${s.localStorage.slice(0, 5).map(i => `
            <div class="surface-meta-row">
              <span class="surface-meta-key">${escHtml(i.key)}</span>
              ${i.looksLikeSensitive
                ? '<span class="surface-tag danger">sensitive</span>'
                : `<span class="surface-tag neutral">${i.valueLength}B</span>`}
            </div>`).join("")}
          ${s.localStorage.length > 5 ? `<div style="font-size:10px;color:var(--text-muted);margin-top:4px">…and ${s.localStorage.length - 5} more</div>` : ""}
        ` : ""}
      </div>`;
}

function buildUrlParamsCard(s) {
    return `
      <div class="surface-card">
        <div class="surface-card-title">URL Parameters <span class="surface-count">${s.urlParams.length}</span></div>
        ${s.urlParams.length === 0
            ? `<div class="empty-state" style="padding:10px">No URL parameters.</div>`
            : `<table class="surface-table">
                <thead><tr><th>Param</th><th>Value</th><th>Type</th></tr></thead>
                <tbody>
                  ${s.urlParams.map(p => `<tr>
                    <td style="color:var(--text-code)">${escHtml(p.key)}</td>
                    <td>${escHtml(p.value)}</td>
                    <td>${p.looksNumeric
                        ? '<span class="surface-tag warn">numeric</span>'
                        : '<span class="surface-tag neutral">string</span>'}</td>
                  </tr>`).join("")}
                </tbody>
              </table>`}
      </div>`;
}

function buildIframesCard(s) {
    return `
      <div class="surface-card">
        <div class="surface-card-title">iFrames <span class="surface-count">${s.iframes.length}</span></div>
        ${s.iframes.length === 0
            ? `<div class="empty-state" style="padding:10px">No iframes found.</div>`
            : `<table class="surface-table">
                <thead><tr><th>Source</th><th>External</th><th>Sandbox</th></tr></thead>
                <tbody>
                  ${s.iframes.map(f => {
                    let domain = f.src || "—";
                    try { domain = f.src ? new URL(f.src).hostname : "—"; } catch(e){}
                    return `<tr>
                      <td>${escHtml(domain)}</td>
                      <td>${f.isExternal ? '<span class="surface-tag warn">yes</span>' : '<span class="surface-tag neutral">no</span>'}</td>
                      <td>${f.hasSandbox ? '<span class="surface-tag ok">✓</span>' : (f.isExternal ? '<span class="surface-tag danger">✗</span>' : '<span class="surface-tag neutral">—</span>')}</td>
                    </tr>`;
                  }).join("")}
                </tbody>
              </table>`}
      </div>`;
}

// ── EVENT STREAM ──────────────────────────────────────────────────────────────

function renderEventStream() {
    const tbody    = document.getElementById("event-tbody");
    const countEl  = document.getElementById("event-count");
    const badge    = document.getElementById("tab-badge-events");

    tbody.innerHTML = "";
    countEl.textContent = allEvents.length;
    badge.textContent   = allEvents.length;

    const recent = allEvents.slice(-150).reverse();
    recent.forEach(ev => {
        const tr     = document.createElement("tr");
        const time   = new Date(ev.timestamp).toLocaleTimeString("en-US", { hour12: false });
        const detail = ev.url || ev.detail || "—";
        const flagEl = ev.flag
            ? `<span class="event-flag ${ev.flag.toLowerCase()}">${ev.flag}</span>`
            : `<span style="color:var(--text-muted)">—</span>`;

        tr.innerHTML = `
          <td>${escHtml(time)}</td>
          <td>${escHtml(ev.type || "?")}</td>
          <td title="${escHtml(detail)}">${escHtml(detail.substring(0, 90))}</td>
          <td>${escHtml(ev.method || "—")}</td>
          <td>${flagEl}</td>`;

        tbody.appendChild(tr);
    });
}

// ── LIVE POLLING ──────────────────────────────────────────────────────────────

function startEventPoll() {
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(() => {
        sendToContent("GET_REPORT", response => {
            if (!response || !response.success) return;
            const report = response.report;

            let needsDashboardRefresh = false;

            // Update score globally if it changed
            if (report.securityScore && (!lastScore || report.securityScore.overall !== lastScore.overall)) {
                lastScore = report.securityScore;
                needsDashboardRefresh = true;
            }

            // Sync Surface if it changed
            if (report.attackSurface) {
                lastSurface = report.attackSurface;
            }

            // Merge new runtime issues (may appear between scans)
            if (report.issues && report.issues.length !== allIssues.length) {
                const existingIds = new Set(allIssues.map(i => i.id));
                const newIssues = (report.issues || []).filter(i => !existingIds.has(i.id));
                if (newIssues.length > 0) {
                    allIssues.push(...newIssues);
                    renderIssueList();
                    needsDashboardRefresh = true;
                    updateBadges();
                }
            }

            if (needsDashboardRefresh) {
                renderDashboard();
            }

            allEvents = report.events || [];
            renderEventStream();
        });
    }, 3000);
}

// ── MESSAGING ─────────────────────────────────────────────────────────────────

function sendToContent(action, callback) {
    // Guard: extension context may be invalidated after a reload.
    if (!chrome.runtime?.id) {
        console.warn("PixelSpy: Extension context gone — stopping poll.");
        if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
        setStatus("⚠️ Extension reloaded — reopen DevTools", false, null);
        callback && callback(null);
        return;
    }
    try {
        const tabId = chrome.devtools.inspectedWindow.tabId;
        chrome.runtime.sendMessage({ action, tabId }, response => {
            if (chrome.runtime.lastError) {
                const msg = chrome.runtime.lastError.message || "";
                // Context invalidated = extension was reloaded; stop polling.
                if (msg.includes("invalidated") || msg.includes("context")) {
                    if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
                    setStatus("⚠️ Extension reloaded — reopen DevTools", false, null);
                } else {
                    console.warn("PixelSpy:", msg);
                }
                callback && callback(null);
                return;
            }
            callback && callback(response);
        });
    } catch (e) {
        if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
        console.warn("PixelSpy: sendMessage failed:", e.message);
        callback && callback(null);
    }
}

// ── UTILITIES ─────────────────────────────────────────────────────────────────

function setStatus(text, scanning, issueCount) {
    const el       = document.getElementById("status-text");
    const countEl  = document.getElementById("issue-count");

    el.textContent = text;
    el.classList.toggle("scanning", !!scanning);

    if (typeof issueCount === "number" && issueCount > 0) {
        countEl.textContent = `${issueCount} issue${issueCount !== 1 ? "s" : ""}`;
        countEl.classList.remove("hidden");
    }
}

function escHtml(str) {
    return String(str || "")
        .replace(/&/g,  "&amp;")
        .replace(/</g,  "&lt;")
        .replace(/>/g,  "&gt;")
        .replace(/"/g,  "&quot;")
        .replace(/'/g,  "&#39;");
}
