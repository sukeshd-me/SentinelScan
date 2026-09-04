/**
 * Scan History View with live filtering, pagination, and file management
 */

export function initHistoryView(container, onViewScan) {
  let allScans = [];

  async function loadScans() {
    try {
      const resp = await fetch('/api/scans?limit=100');
      const data = await resp.json();
      allScans = data.scans || [];
      renderTable();
    } catch (err) {
      container.innerHTML = `<div class="cyber-card" style="color: var(--sev-critical);">Failed to load scan history: ${err.message}</div>`;
    }
  }

  function renderTable() {
    const searchVal = container.querySelector('#historySearch')?.value.toLowerCase() || '';
    const filterVerdict = container.querySelector('#historyVerdictFilter')?.value || 'ALL';

    const filtered = allScans.filter(s => {
      const matchSearch = s.filename.toLowerCase().includes(searchVal) || (s.sha256 && s.sha256.toLowerCase().includes(searchVal));
      const matchVerdict = filterVerdict === 'ALL' || s.verdict === filterVerdict;
      return matchSearch && matchVerdict;
    });

    const tbody = container.querySelector('#historyTableBody');
    if (!tbody) return;

    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 3rem;">No matching scan records found.</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(s => `
      <tr>
        <td style="font-weight: 600; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          ${escapeHtml(s.filename)}
        </td>
        <td>${(s.file_size / 1024).toFixed(1)} KB</td>
        <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--cyber-cyan);">${escapeHtml(s.detected_mime || '—')}</td>
        <td>
          <span class="badge badge-${(s.verdict || 'CLEAN').replace('_RISK', '')}">${s.verdict || s.status}</span>
          ${s.risk_score !== null ? `<span style="font-family: var(--font-mono); font-size: 0.8rem; margin-left: 0.4rem;">${s.risk_score}/100</span>` : ''}
        </td>
        <td>
          <span class="mono-hash" style="font-size: 0.75rem;">${s.sha256 ? `${s.sha256.slice(0, 10)}...` : 'Pending'}</span>
        </td>
        <td style="font-size: 0.8rem; color: var(--text-muted);">${new Date(s.created_at).toLocaleString()}</td>
        <td>
          <div style="display: flex; gap: 0.5rem;">
            <button class="btn btn-primary btn-sm btn-view-scan" data-id="${s.id}">View</button>
            ${!s.file_deleted ? `<button class="btn btn-danger btn-sm btn-del-scan" data-id="${s.id}">Erase</button>` : `<span style="font-size: 0.75rem; color: var(--text-muted);">Erased</span>`}
          </div>
        </td>
      </tr>
    `).join('');

    // Bind action buttons
    tbody.querySelectorAll('.btn-view-scan').forEach(btn => {
      btn.addEventListener('click', () => onViewScan(btn.dataset.id));
    });

    tbody.querySelectorAll('.btn-del-scan').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!confirm('Erase this uploaded file immediately?')) return;
        const clientToken = localStorage.getItem('sentinel_client_token');
        await fetch(`/api/scans/${btn.dataset.id}`, {
          method: 'DELETE',
          headers: { 'x-client-token': clientToken }
        });
        await loadScans();
      });
    });
  }

  container.innerHTML = `
    <div class="cyber-card" style="margin-bottom: 2rem;">
      <div class="card-header">
        <h3 class="card-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          Historical Scan Telemetry
        </h3>
        <button class="btn btn-secondary btn-sm" id="btnRefreshHistory">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
          Refresh
        </button>
      </div>

      <div style="display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap;">
        <input type="text" id="historySearch" placeholder="Search by filename or SHA-256 hash..."
          style="flex: 1; min-width: 250px; background: var(--bg-secondary); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 0.6rem 1rem; color: #fff; font-family: var(--font-sans);" />

        <select id="historyVerdictFilter"
          style="background: var(--bg-secondary); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 0.6rem 1rem; color: #fff; font-family: var(--font-sans);">
          <option value="ALL">All Verdicts</option>
          <option value="CRITICAL_RISK">Critical Risk</option>
          <option value="HIGH_RISK">High Risk</option>
          <option value="MODERATE_RISK">Moderate Risk</option>
          <option value="LOW_RISK">Low Risk</option>
          <option value="CLEAN">Clean</option>
        </select>
      </div>

      <div class="data-table-wrapper">
        <table class="cyber-table">
          <thead>
            <tr>
              <th>File Name</th>
              <th>Size</th>
              <th>Detected Type</th>
              <th>Verdict / Score</th>
              <th>SHA-256</th>
              <th>Timestamp</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="historyTableBody">
            <tr><td colspan="7" style="text-align: center; padding: 2rem;">Loading scan records...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  `;

  container.querySelector('#historySearch').addEventListener('input', renderTable);
  container.querySelector('#historyVerdictFilter').addEventListener('change', renderTable);
  container.querySelector('#btnRefreshHistory').addEventListener('click', loadScans);

  loadScans();
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
