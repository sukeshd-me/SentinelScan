/**
 * Render complete scan results and threat telemetry
 */

export function renderScanResults(data, container) {
  const { scan, findings, engineResults } = data;

  const score = scan.riskScore || 0;
  const verdict = scan.verdict || 'UNKNOWN';
  const confidence = scan.confidence || 'MODERATE';

  // Calculate SVG stroke offset for 100 max circumference (radius=40 -> circ = 2 * PI * 40 = 251.3)
  const radius = 40;
  const circumference = 2 * Math.PI * radius;
  const strokeOffset = circumference - (score / 100) * circumference;

  let gaugeColor = 'var(--sev-clean)';
  if (score >= 75) gaugeColor = 'var(--sev-critical)';
  else if (score >= 50) gaugeColor = 'var(--sev-high)';
  else if (score >= 20) gaugeColor = 'var(--sev-moderate)';

  const html = `
    <!-- Verdict Banner -->
    <div class="results-header-banner banner-${verdict}">
      <div class="verdict-info">
        <span class="badge badge-${verdict.replace('_RISK', '')}">${verdict.replace('_', ' ')}</span>
        <h2 style="margin-top: 0.5rem;">${formatVerdictHeading(verdict)}</h2>
        <p>Deterministic analysis concluded with <strong>${confidence} Confidence</strong>. ${findings.length} threat indicators observed.</p>
      </div>

      <div class="score-container">
        <div class="score-circle">
          <svg viewBox="0 0 100 100">
            <circle class="score-circle-bg" cx="50" cy="50" r="${radius}" />
            <circle class="score-circle-progress" cx="50" cy="50" r="${radius}"
              style="stroke: ${gaugeColor}; stroke-dasharray: ${circumference}; stroke-dashoffset: ${strokeOffset};" />
          </svg>
          <div class="score-number" style="color: ${gaugeColor};">${score}</div>
        </div>
        <div>
          <div style="font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; font-weight: 600;">Risk Index</div>
          <div style="font-size: 1.1rem; font-weight: 700; color: ${gaugeColor};">${score} / 100</div>
        </div>
      </div>
    </div>

    <!-- Actions Toolbar -->
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 1rem;">
      <div style="display: flex; gap: 0.75rem;">
        <button class="btn btn-secondary btn-sm" id="btnExportJson" data-scan-id="${scan.id}">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          Export JSON
        </button>
        <button class="btn btn-secondary btn-sm" id="btnExportMd" data-scan-id="${scan.id}">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
          Export Markdown
        </button>
        <button class="btn btn-secondary btn-sm" onclick="window.print()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
          Print Report
        </button>
      </div>

      <div>
        ${scan.fileDeleted
          ? `<span class="badge badge-CLEAN">File Permanently Deleted</span>`
          : `<button class="btn btn-danger btn-sm" id="btnDeleteNow" data-scan-id="${scan.id}">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
              Delete Uploaded File Now
             </button>`
        }
      </div>
    </div>

    <!-- File Identification & Hash Card -->
    <div class="cyber-card" style="margin-bottom: 2rem;">
      <div class="card-header">
        <h3 class="card-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
          File Metadata & Cryptographic Hashes
        </h3>
        <span class="status-pill">Scan ID: ${scan.id.slice(0, 8)}...</span>
      </div>

      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.25rem; margin-bottom: 1.5rem;">
        <div>
          <div style="font-size: 0.8rem; color: var(--text-muted);">Original Filename</div>
          <div style="font-weight: 600; font-size: 1.05rem; word-break: break-all;">${escapeHtml(scan.filename)}</div>
        </div>
        <div>
          <div style="font-size: 0.8rem; color: var(--text-muted);">File Size</div>
          <div style="font-weight: 600;">${(scan.fileSize / 1024).toFixed(2)} KB (${scan.fileSize.toLocaleString()} bytes)</div>
        </div>
        <div>
          <div style="font-size: 0.8rem; color: var(--text-muted);">Detected MIME & Format</div>
          <div style="font-weight: 600; font-family: var(--font-mono); color: var(--cyber-cyan);">${escapeHtml(scan.detectedMime || 'Unknown')}</div>
        </div>
        <div>
          <div style="font-size: 0.8rem; color: var(--text-muted);">Analyzed At</div>
          <div style="font-weight: 600;">${new Date(scan.createdAt).toLocaleString()}</div>
        </div>
      </div>

      <div style="background: var(--bg-secondary); border-radius: var(--radius-md); padding: 1rem; border: 1px solid var(--border-subtle);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
          <span style="font-size: 0.75rem; color: var(--text-muted); font-weight: 700; text-transform: uppercase;">SHA-256 (Primary Checksum)</span>
          <button class="copy-btn" data-copy="${scan.sha256}">Copy</button>
        </div>
        <div class="mono-hash">${scan.sha256 || 'N/A'}</div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 1rem; padding-top: 0.75rem; border-top: 1px solid var(--border-subtle);">
          <div>
            <div style="font-size: 0.75rem; color: var(--text-muted); font-weight: 700;">SHA-1</div>
            <div class="mono-hash" style="font-size: 0.75rem;">${scan.sha1 || 'N/A'}</div>
          </div>
          <div>
            <div style="font-size: 0.75rem; color: var(--text-muted); font-weight: 700;">MD5</div>
            <div class="mono-hash" style="font-size: 0.75rem;">${scan.md5 || 'N/A'}</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="tab-navigation">
      <button class="tab-nav-btn active" data-tab="tab-findings">Observed Findings (${findings.length})</button>
      <button class="tab-nav-btn" data-tab="tab-engines">Engines & Parsers (${engineResults.length})</button>
      <button class="tab-nav-btn" data-tab="tab-limitations">Defensive Limitations</button>
    </div>

    <!-- Tab 1: Findings -->
    <div class="tab-content active" id="tab-findings">
      ${findings.length === 0
        ? `<div class="cyber-card" style="text-align: center; padding: 3rem;">
             <div style="color: var(--sev-clean); font-size: 2.5rem; margin-bottom: 1rem;">✓</div>
             <h3>No Security Threats or Anomalies Detected</h3>
             <p style="color: var(--text-secondary); max-width: 500px; margin: 0.5rem auto 0;">
               All static parsing modules and signature checks completed without identifying malicious patterns or high-risk structural anomalies.
             </p>
           </div>`
        : findings.map(f => `
            <div class="finding-card severity-${f.severity}">
              <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem;">
                <h4 style="font-size: 1.05rem; font-weight: 700;">${escapeHtml(f.title)}</h4>
                <div style="display: flex; gap: 0.5rem;">
                  <span class="badge badge-${f.severity}">${f.severity}</span>
                  <span class="badge" style="background: rgba(255,255,255,0.05); color: var(--text-secondary);">${escapeHtml(f.category)}</span>
                </div>
              </div>
              <p style="color: var(--text-secondary); font-size: 0.9rem;">${escapeHtml(f.description)}</p>
              ${f.evidence ? `<div class="evidence-box">${escapeHtml(f.evidence)}</div>` : ''}
            </div>
          `).join('')
      }
    </div>

    <!-- Tab 2: Engines -->
    <div class="tab-content" id="tab-engines">
      <div class="cyber-card">
        <div class="data-table-wrapper">
          <table class="cyber-table">
            <thead>
              <tr>
                <th>Engine / Inspector</th>
                <th>Status</th>
                <th>Duration</th>
                <th>Summary Details</th>
              </tr>
            </thead>
            <tbody>
              ${engineResults.map(e => `
                <tr>
                  <td style="font-weight: 600;">${escapeHtml(e.engine_name)}</td>
                  <td><span class="badge ${getEngineStatusClass(e.status)}">${escapeHtml(e.status)}</span></td>
                  <td style="font-family: var(--font-mono); font-size: 0.8rem;">${e.duration_ms ? `${e.duration_ms}ms` : '—'}</td>
                  <td style="color: var(--text-secondary); font-size: 0.85rem;">${escapeHtml(e.summary || 'Completed without anomalies')}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Tab 3: Limitations & Zero-Execution Policy -->
    <div class="tab-content" id="tab-limitations">
      <div class="cyber-card">
        <h3 style="margin-bottom: 1rem; color: var(--cyber-cyan);">Zero-Execution Architecture & Defensive Scope</h3>
        <p style="color: var(--text-secondary); margin-bottom: 1rem;">
          SentinelScan operates under a strict defensive zero-execution guarantee. All files are inspected in read-only binary mode using specialized structural parsers. The binary was not executed in operating system process space.
        </p>

        <h4 style="margin-top: 1.5rem; margin-bottom: 0.5rem; font-size: 0.95rem;">Transparent Analysis Limitations:</h4>
        <ul style="margin-left: 1.5rem; color: var(--text-secondary); font-size: 0.9rem; line-height: 1.8;">
          <li>Static analysis cannot observe payloads decrypted strictly in runtime memory.</li>
          <li>If the ClamAV daemon is unreachable on the host system, signature matching is reported honestly as unavailable rather than clean.</li>
          <li>No defensive security platform can provide an absolute 100% mathematical guarantee against novel, customized zero-day threats.</li>
          <li>Automated secure file deletion will erase the physical file within 5 minutes of analysis completion.</li>
        </ul>
      </div>
    </div>
  `;

  container.innerHTML = html;

  // Bind tabs
  container.querySelectorAll('.tab-nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      container.querySelectorAll('.tab-nav-btn').forEach(b => b.classList.remove('active'));
      container.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetTab = container.querySelector(`#${btn.dataset.tab}`);
      if (targetTab) targetTab.classList.add('active');
    });
  });

  // Bind Export buttons
  container.querySelector('#btnExportJson')?.addEventListener('click', (e) => {
    const scanId = e.currentTarget.dataset.scanId;
    window.open(`/api/scans/${scanId}/report?format=json`, '_blank');
  });

  container.querySelector('#btnExportMd')?.addEventListener('click', (e) => {
    const scanId = e.currentTarget.dataset.scanId;
    window.open(`/api/scans/${scanId}/report?format=markdown`, '_blank');
  });

  // Bind Delete button
  container.querySelector('#btnDeleteNow')?.addEventListener('click', async (e) => {
    const scanId = e.currentTarget.dataset.scanId;
    const clientToken = localStorage.getItem('sentinel_client_token');

    if (!confirm('Permanently delete this uploaded file now?')) return;

    try {
      const resp = await fetch(`/api/scans/${scanId}`, {
        method: 'DELETE',
        headers: { 'x-client-token': clientToken }
      });
      if (resp.ok) {
        alert('File permanently erased.');
        // Refresh view
        const updated = await fetch(`/api/scans/${scanId}`).then(r => r.json());
        renderScanResults(updated, container);
      } else {
        const err = await resp.json();
        alert(`Deletion error: ${err.error}`);
      }
    } catch (err) {
      alert(`Network error: ${err.message}`);
    }
  });

  // Bind Copy buttons
  container.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      navigator.clipboard.writeText(btn.dataset.copy).then(() => {
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = orig; }, 1500);
      });
    });
  });
}

function formatVerdictHeading(verdict) {
  switch (verdict) {
    case 'CRITICAL_RISK': return 'Critical Security Threat Detected';
    case 'HIGH_RISK': return 'High Risk Potential Identified';
    case 'MODERATE_RISK': return 'Moderate Risk / Suspicious Indicators';
    case 'LOW_RISK': return 'Low Risk Anomaly Identified';
    case 'CLEAN': return 'File Appears Clean & Free of Known Threats';
    default: return 'Analysis Complete';
  }
}

function getEngineStatusClass(status) {
  if (status === 'SUCCESS' || status === 'CLEAN') return 'badge-CLEAN';
  if (status === 'INFECTED') return 'badge-CRITICAL';
  if (status === 'SKIPPED') return 'badge-LOW';
  return 'badge-MEDIUM';
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
