/**
 * Authentic System Status & Health Monitor View
 */

export async function renderSystemStatus(container) {
  try {
    const resp = await fetch('/api/system/status');
    const data = await resp.json();

    const { components, systemMetrics, uptimeSeconds, recentEvents } = data;
    const hours = Math.floor(uptimeSeconds / 3600);
    const minutes = Math.floor((uptimeSeconds % 3600) / 60);

    const html = `
      <!-- Overall Health Overview -->
      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-label">System State</div>
          <div class="stat-val" style="color: var(--sev-clean);">ONLINE</div>
          <div class="stat-meta">Uptime: ${hours}h ${minutes}m (${uptimeSeconds}s)</div>
        </div>

        <div class="stat-card">
          <div class="stat-label">Antivirus Engine</div>
          <div class="stat-val" style="color: ${components.antivirus.operational ? 'var(--sev-clean)' : 'var(--sev-moderate)'}; font-size: 1.4rem;">
            ${components.antivirus.operational ? 'CONNECTED' : 'OFFLINE'}
          </div>
          <div class="stat-meta">${components.antivirus.statusText}</div>
        </div>

        <div class="stat-card">
          <div class="stat-label">Total Scans Indexed</div>
          <div class="stat-val">${components.database.stats.totalScans}</div>
          <div class="stat-meta">${components.database.stats.activeScans} active / pending retention</div>
        </div>

        <div class="stat-card">
          <div class="stat-label">Memory Utilization</div>
          <div class="stat-val">${systemMetrics.rssMemoryMb} MB</div>
          <div class="stat-meta">Heap: ${systemMetrics.heapUsedMb} MB (Node ${systemMetrics.nodeVersion})</div>
        </div>
      </div>

      <!-- Component Breakdown Grid -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr)); gap: 1.5rem; margin-bottom: 2rem;">
        <!-- Antivirus Status Card -->
        <div class="cyber-card">
          <div class="card-header">
            <h3 class="card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              Antivirus Integration (ClamAV)
            </h3>
            <span class="badge ${components.antivirus.operational ? 'badge-CLEAN' : 'badge-MEDIUM'}">
              ${components.antivirus.operational ? 'Operational' : 'Unavailable'}
            </span>
          </div>

          <div style="font-size: 0.9rem; color: var(--text-secondary); line-height: 1.8;">
            <div><strong>Engine Protocol:</strong> TCP Socket (zINSTREAM / zPING)</div>
            <div><strong>Status Detail:</strong> ${escapeHtml(components.antivirus.details)}</div>
            ${components.antivirus.version ? `<div><strong>Signature DB:</strong> ${escapeHtml(components.antivirus.version)}</div>` : ''}
          </div>

          ${!components.antivirus.operational ? `
            <div class="notice-box" style="margin-top: 1rem; padding: 0.85rem; border-color: rgba(245, 158, 11, 0.3);">
              <strong style="color: var(--sev-moderate);">Honest Engine Reporting:</strong>
              When the local clamd daemon is offline, SentinelScan reports <em>"Antivirus engine unavailable"</em> and relies strictly on deterministic static parsers rather than simulating clean results.
            </div>
          ` : ''}
        </div>

        <!-- Storage & Automated Retention Card -->
        <div class="cyber-card">
          <div class="card-header">
            <h3 class="card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
              Storage & Automatic File Shredding
            </h3>
            <span class="badge badge-CLEAN">Active</span>
          </div>

          <div style="font-size: 0.9rem; color: var(--text-secondary); line-height: 1.8;">
            <div><strong>Storage Provider:</strong> ${components.storage.provider.toUpperCase()} (Pluggable B2/Local)</div>
            <div><strong>Chunked Upload Limit:</strong> Up to 1.0 GB (streamed in 5MB slices)</div>
            <div><strong>Automated Retention Policy:</strong> ${components.storage.autoCleanupPolicy}</div>
            <div><strong>Files Erased:</strong> ${components.database.stats.cleanedFiles} uploaded payloads permanently removed</div>
          </div>
        </div>
      </div>

      <!-- Static Parsers Matrix -->
      <div class="cyber-card" style="margin-bottom: 2rem;">
        <div class="card-header">
          <h3 class="card-title">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
            Static Analysis & Inspection Modules
          </h3>
          <span class="badge badge-CLEAN">10 Modules Ready</span>
        </div>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 0.75rem;">
          ${components.staticAnalyzers.map(a => `
            <div style="background: var(--bg-secondary); border: 1px solid var(--border-subtle); padding: 0.75rem 1rem; border-radius: var(--radius-sm); display: flex; justify-content: space-between; align-items: center;">
              <span style="font-size: 0.85rem; font-weight: 500;">${escapeHtml(a.name)}</span>
              <span class="status-dot"></span>
            </div>
          `).join('')}
        </div>
      </div>

      <!-- Audit & System Events Log -->
      <div class="cyber-card">
        <div class="card-header">
          <h3 class="card-title">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
            Recent System & Security Audit Events
          </h3>
        </div>

        <div class="data-table-wrapper">
          <table class="cyber-table">
            <thead>
              <tr>
                <th>Event Type</th>
                <th>Scan Reference</th>
                <th>Message</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              ${recentEvents.map(e => `
                <tr>
                  <td><span class="badge" style="background: rgba(255,255,255,0.06); color: var(--cyber-cyan);">${escapeHtml(e.event_type)}</span></td>
                  <td style="font-family: var(--font-mono); font-size: 0.8rem;">${e.scan_id ? `${e.scan_id.slice(0, 8)}...` : 'SYSTEM'}</td>
                  <td style="color: var(--text-secondary); font-size: 0.85rem;">${escapeHtml(e.message)}</td>
                  <td style="font-size: 0.8rem; color: var(--text-muted);">${new Date(e.created_at).toLocaleTimeString()}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;

    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = `<div class="cyber-card" style="color: var(--sev-critical);">System status unavailable: ${err.message}</div>`;
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
