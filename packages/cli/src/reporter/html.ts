import { ScanResult, FileScanResult, Finding, Severity } from '../scanner/rules/types.js';
import { getScoreLabel, getScoreEmoji } from '../scanner/rules/ai-smells/ai-confidence-scorer.js';

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

const SEVERITY_COLORS: Record<Severity, string> = {
  error: '#ef4444',
  warn: '#f59e0b',
  info: '#3b82f6',
};

const SEVERITY_BG: Record<Severity, string> = {
  error: 'rgba(239,68,68,0.1)',
  warn: 'rgba(245,158,11,0.1)',
  info: 'rgba(59,130,246,0.1)',
};

function renderFindingCard(finding: Finding): string {
  const color = SEVERITY_COLORS[finding.severity];
  const bg = SEVERITY_BG[finding.severity];
  const fix = finding.fix ? `<div class="fix"><span class="fix-label">FIX:</span> ${escapeHtml(finding.fix)}</div>` : '';
  return `
    <div class="finding" style="border-left: 3px solid ${color}; background: ${bg}">
      <div class="finding-header">
        <span class="severity-badge" style="color:${color}">${finding.severity.toUpperCase()}</span>
        <span class="rule-id">${escapeHtml(finding.ruleId)}</span>
        <span class="location">line ${finding.line}</span>
      </div>
      <div class="message">${escapeHtml(finding.message)}</div>
      <pre class="snippet"><code>${escapeHtml(finding.snippet)}</code></pre>
      ${fix}
    </div>`;
}

function renderFileSection(file: FileScanResult): string {
  if (file.findings.length === 0) return '';
  const scoreEmoji = getScoreEmoji(file.aiScore);
  const scoreLabel = getScoreLabel(file.aiScore);
  const errorCount = file.findings.filter((f) => f.severity === 'error').length;
  const warnCount = file.findings.filter((f) => f.severity === 'warn').length;
  return `
    <section class="file-section" id="file-${encodeURIComponent(file.relativePath)}">
      <div class="file-header">
        <h3>${escapeHtml(file.relativePath)}</h3>
        <div class="file-meta">
          <span class="ai-score">${scoreEmoji} AI Score: ${file.aiScore}/100 (${scoreLabel})</span>
          <span class="counts">
            ${errorCount > 0 ? `<span style="color:#ef4444">${errorCount} errors</span>` : ''}
            ${warnCount > 0 ? `<span style="color:#f59e0b">${warnCount} warnings</span>` : ''}
          </span>
        </div>
      </div>
      <div class="findings-list">
        ${file.findings.map(renderFindingCard).join('')}
      </div>
    </section>`;
}

function renderSidebarItems(files: FileScanResult[]): string {
  return files
    .filter((f) => f.findings.length > 0)
    .map((f) => {
      const errCount = f.findings.filter((x) => x.severity === 'error').length;
      const dot = errCount > 0 ? '🔴' : '🟡';
      return `<li><a href="#file-${encodeURIComponent(f.relativePath)}" class="sidebar-link">${dot} ${escapeHtml(f.relativePath)} <span class="count">${f.findings.length}</span></a></li>`;
    })
    .join('');
}

function getInlineCss(): string {
  return `
    :root { --bg:#0a0a0a; --surface:#111; --border:#1e1e1e; --text:#e2e8f0; --muted:#64748b; --accent:#7c3aed; --cyan:#06b6d4; }
    * { box-sizing:border-box; margin:0; padding:0; }
    body { background:var(--bg); color:var(--text); font-family:'Geist Mono',monospace; font-size:14px; }
    a { color:var(--cyan); text-decoration:none; }
    .layout { display:flex; min-height:100vh; }
    .sidebar { width:280px; min-height:100vh; background:var(--surface); border-right:1px solid var(--border); padding:1rem; position:sticky; top:0; max-height:100vh; overflow-y:auto; }
    .sidebar h2 { color:var(--accent); margin-bottom:1rem; font-size:1rem; }
    .sidebar ul { list-style:none; }
    .sidebar-link { display:flex; justify-content:space-between; padding:0.35rem 0.5rem; border-radius:4px; color:var(--text); font-size:0.8rem; }
    .sidebar-link:hover { background:var(--border); }
    .count { background:var(--border); padding:0 6px; border-radius:3px; font-size:0.75rem; }
    .main { flex:1; padding:2rem; max-width:900px; }
    .topbar { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:1.5rem; margin-bottom:2rem; }
    .topbar h1 { font-size:1.5rem; color:var(--accent); margin-bottom:0.75rem; }
    .stats { display:flex; gap:2rem; flex-wrap:wrap; }
    .stat-item { display:flex; flex-direction:column; }
    .stat-label { color:var(--muted); font-size:0.75rem; }
    .stat-value { font-size:1.25rem; font-weight:bold; }
    .file-section { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:1.5rem; margin-bottom:1.5rem; }
    .file-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem; flex-wrap:wrap; gap:0.5rem; }
    .file-header h3 { color:var(--cyan); font-size:0.95rem; }
    .ai-score { color:var(--muted); font-size:0.8rem; }
    .finding { padding:1rem; border-radius:6px; margin-bottom:0.75rem; }
    .finding-header { display:flex; gap:1rem; align-items:center; margin-bottom:0.5rem; flex-wrap:wrap; }
    .severity-badge { font-weight:bold; font-size:0.75rem; text-transform:uppercase; }
    .rule-id { color:var(--cyan); font-size:0.8rem; }
    .location { color:var(--muted); font-size:0.8rem; }
    .message { margin-bottom:0.5rem; }
    .snippet { background:#0d0d0d; border:1px solid var(--border); border-radius:4px; padding:0.75rem; overflow-x:auto; font-size:0.8rem; color:#a8b3c3; margin-bottom:0.5rem; }
    .fix { font-size:0.85rem; color:#4ade80; }
    .fix-label { font-weight:bold; color:#22c55e; }`;
}

function getInlineJs(): string {
  return `
    function filterBySeverity(sev) {
      document.querySelectorAll('.finding').forEach(function(el) {
        const badge = el.querySelector('.severity-badge');
        if (!badge) return;
        const s = badge.textContent.toLowerCase().trim();
        el.style.display = (!sev || s === sev) ? '' : 'none';
      });
    }
    document.querySelectorAll('[data-filter]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        document.querySelectorAll('[data-filter]').forEach(function(b) { b.classList.remove('active'); });
        btn.classList.add('active');
        filterBySeverity(btn.dataset.filter);
      });
    });`;
}

export function formatHtml(result: ScanResult, version: string): string {
  const scanDate = new Date().toLocaleString();
  const fileSections = result.files.map(renderFileSection).join('');
  const sidebarItems = renderSidebarItems(result.files);
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VibeCop Report — ${scanDate}</title>
<style>${getInlineCss()}</style>
</head>
<body>
<div class="layout">
  <nav class="sidebar">
    <h2>🛡️ VibeCop</h2>
    <p style="color:var(--muted);font-size:0.75rem;margin-bottom:1rem">${result.filesWithIssues} files with issues</p>
    <ul>${sidebarItems}</ul>
  </nav>
  <main class="main">
    <div class="topbar">
      <h1>🛡️ VibeCop Scan Report</h1>
      <p style="color:var(--muted);margin-bottom:1rem">Scanned ${result.filesScanned} files on ${scanDate} in ${result.scanDurationMs}ms · v${version}</p>
      <div class="stats">
        <div class="stat-item"><span class="stat-label">VibeScore™</span><span class="stat-value" style="color:#7c3aed">${result.vibeScore}/100</span></div>
        <div class="stat-item"><span class="stat-label">🔴 Errors</span><span class="stat-value" style="color:#ef4444">${result.errorCount}</span></div>
        <div class="stat-item"><span class="stat-label">🟡 Warnings</span><span class="stat-value" style="color:#f59e0b">${result.warnCount}</span></div>
        <div class="stat-item"><span class="stat-label">🔵 Info</span><span class="stat-value" style="color:#3b82f6">${result.infoCount}</span></div>
      </div>
      <div style="margin-top:1rem;display:flex;gap:0.5rem;">
        <button data-filter="" style="background:var(--border);color:var(--text);border:none;padding:0.35rem 0.75rem;border-radius:4px;cursor:pointer">All</button>
        <button data-filter="error" style="background:rgba(239,68,68,0.2);color:#ef4444;border:none;padding:0.35rem 0.75rem;border-radius:4px;cursor:pointer">Errors</button>
        <button data-filter="warn" style="background:rgba(245,158,11,0.2);color:#f59e0b;border:none;padding:0.35rem 0.75rem;border-radius:4px;cursor:pointer">Warnings</button>
        <button data-filter="info" style="background:rgba(59,130,246,0.2);color:#3b82f6;border:none;padding:0.35rem 0.75rem;border-radius:4px;cursor:pointer">Info</button>
      </div>
    </div>
    ${fileSections}
  </main>
</div>
<script>${getInlineJs()}</script>
</body>
</html>`;
}
