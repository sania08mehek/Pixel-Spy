// securityScorer.js — PixelSpy OWASP-weighted Security Scoring Engine
// Calculates a 0–100 score from detected issues + attack surface data.
// Exports: window.calculateSecurityScore(issues, attackSurface)

window.calculateSecurityScore = function (issues, attackSurface) {
    let score = 100;

    // Category trackers (each starts at 100)
    const categories = {
        xss:    { score: 100, issues: 0, label: "XSS Protection",     owaspId: "A03" },
        sqli:   { score: 100, issues: 0, label: "Injection",          owaspId: "A03" },
        csrf:   { score: 100, issues: 0, label: "Auth & Session",     owaspId: "A07" },
        config: { score: 100, issues: 0, label: "Security Config",    owaspId: "A05" },
        deps:   { score: 100, issues: 0, label: "Vulnerable Deps",    owaspId: "A06" }
    };

    const owaspHits = new Set(); // which OWASP categories are affected

    // ── Process detected issues ────────────────────────────────────────────────
    (issues || []).forEach(issue => {
        const type = (issue.type || "").toUpperCase();
        const sev  = (issue.severity || "LOW").toUpperCase();

        const deduction = sev === "CRITICAL" ? 22 :
                          sev === "HIGH"     ? 14 :
                          sev === "MEDIUM"   ?  7 : 3;

        score -= deduction;

        if (type === "XSS") {
            categories.xss.score = Math.max(0, categories.xss.score - deduction * 1.5);
            categories.xss.issues++;
            owaspHits.add("A03");
        } else if (type === "SQLI") {
            categories.sqli.score = Math.max(0, categories.sqli.score - deduction * 1.5);
            categories.sqli.issues++;
            owaspHits.add("A03");
        } else if (type === "CSRF") {
            categories.csrf.score = Math.max(0, categories.csrf.score - deduction * 1.2);
            categories.csrf.issues++;
            owaspHits.add("A07");
        } else {
            categories.config.score = Math.max(0, categories.config.score - deduction);
            categories.config.issues++;
            owaspHits.add("A05");
        }
    });

    // ── Process attack surface data ────────────────────────────────────────────
    let surfaceRiskPoints = 0;

    if (attackSurface) {
        surfaceRiskPoints = attackSurface.metadata.riskPoints || 0;
        score -= Math.min(Math.floor(surfaceRiskPoints / 4), 25); // cap at -25

        // External scripts without SRI
        const noSriScripts = (attackSurface.externalScripts || [])
            .filter(s => s.isExternal && !s.hasSRI);
        if (noSriScripts.length > 0) {
            categories.deps.score = Math.max(0, categories.deps.score - noSriScripts.length * 12);
            categories.deps.issues += noSriScripts.length;
            owaspHits.add("A06");
        }

        // Insecure forms
        const insecureForms = (attackSurface.forms || [])
            .filter(f => f.hasPasswordField && !f.isHTTPS);
        if (insecureForms.length > 0) {
            categories.csrf.score = Math.max(0, categories.csrf.score - 35);
            categories.csrf.issues += insecureForms.length;
            owaspHits.add("A07");
        }

        // CSRF-vulnerable POST forms
        const csrfForms = (attackSurface.forms || [])
            .filter(f => f.method === "POST" && !f.hasCsrfToken);
        if (csrfForms.length > 0) {
            categories.csrf.score = Math.max(0, categories.csrf.score - csrfForms.length * 10);
            owaspHits.add("A07");
        }

        // Sensitive localStorage
        const sensitiveLs = (attackSurface.localStorage || [])
            .filter(i => i.looksLikeSensitive);
        if (sensitiveLs.length > 0) {
            categories.config.score = Math.max(0, categories.config.score - sensitiveLs.length * 8);
            categories.config.issues += sensitiveLs.length;
            owaspHits.add("A05");
        }

        // JS-readable cookies (no HttpOnly)
        const jsCookies = (attackSurface.cookies || []);
        if (jsCookies.length > 0) {
            categories.config.score = Math.max(0, categories.config.score - jsCookies.length * 3);
            owaspHits.add("A05");
        }
    }

    score = Math.max(0, Math.min(100, Math.round(score)));

    // Apply category floor from issue-derived scores
    Object.values(categories).forEach(cat => {
        cat.score = Math.max(0, Math.min(100, Math.round(cat.score)));
    });

    const grade      = score >= 80 ? "A" : score >= 60 ? "B" : score >= 40 ? "C" : "F";
    const gradeLabel = grade === "A" ? "Good" : grade === "B" ? "Fair" : grade === "C" ? "Poor" : "Critical";
    const gradeColor = grade === "A" ? "#34d399" : grade === "B" ? "#fbbf24" : grade === "C" ? "#fb923c" : "#f87171";

    // OWASP Top 10 compliance summary
    const owaspTop10 = [
        { id: "A01", name: "Broken Access Control" },
        { id: "A02", name: "Cryptographic Failures" },
        { id: "A03", name: "Injection / XSS" },
        { id: "A04", name: "Insecure Design" },
        { id: "A05", name: "Security Misconfiguration" },
        { id: "A06", name: "Vulnerable Components" },
        { id: "A07", name: "Auth Failures" },
        { id: "A08", name: "Data Integrity Failures" },
        { id: "A09", name: "Logging Failures" },
        { id: "A10", name: "SSRF" }
    ].map(item => ({
        ...item,
        affected: owaspHits.has(item.id)
    }));

    return {
        overall: score,
        grade,
        gradeLabel,
        gradeColor,
        categories,
        owaspTop10,
        issueCount: (issues || []).length,
        surfaceRiskPoints,
        affectedOwaspCount: owaspHits.size,
        scannedAt: Date.now()
    };
};
