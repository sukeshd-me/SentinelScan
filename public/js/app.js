/**
 * SentinelScan Application Main Controller
 */

import { SentinelUploader } from './uploader.js';
import { renderScanResults } from './scanner_view.js';
import { initHistoryView } from './history_view.js';
import { renderSystemStatus } from './status_view.js';

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initScanner();
  initDashboard();
  initSettings();
  initSampleGenerator();
});

/**
 * Tab Navigation Controller
 */
function initNavigation() {
  const navBtns = document.querySelectorAll('.nav-btn');
  const sections = document.querySelectorAll('.view-section');

  function switchView(targetViewId) {
    navBtns.forEach(b => {
      if (b.dataset.view === targetViewId) b.classList.add('active');
      else b.classList.remove('active');
    });

    sections.forEach(s => {
      if (s.id === targetViewId) s.classList.add('active');
      else s.classList.remove('active');
    });

    // View-specific trigger hooks
    if (targetViewId === 'view-history') {
      const container = document.getElementById('historyContainer');
      initHistoryView(container, (scanId) => {
        loadScanIntoScanner(scanId);
      });
    } else if (targetViewId === 'view-status') {
      const container = document.getElementById('statusContainer');
      renderSystemStatus(container);
    } else if (targetViewId === 'view-dashboard') {
      initDashboard();
    }
  }

  navBtns.forEach(btn => {
    btn.addEventListener('click', () => switchView(btn.dataset.view));
  });

  // Global links to switch views
  document.querySelectorAll('[data-switch-view]').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      switchView(link.dataset.switchView);
    });
  });

  // Check header health indicator
  updateHeaderStatus();
}

async function updateHeaderStatus() {
  try {
    const resp = await fetch('/api/system/status');
    const data = await resp.json();
    const dot = document.getElementById('headerStatusDot');
    const text = document.getElementById('headerStatusText');

    if (data.components.antivirus.operational) {
      dot.className = 'status-dot';
      text.textContent = 'Engines & AV Online';
    } else {
      dot.className = 'status-dot warning';
      text.textContent = 'Static Active (AV Offline)';
    }
  } catch (err) {
    const dot = document.getElementById('headerStatusDot');
    const text = document.getElementById('headerStatusText');
    if (dot && text) {
      dot.className = 'status-dot warning';
      text.textContent = 'Connecting...';
    }
  }
}

/**
 * Scanner View Controller (Drag and Drop, Upload, Progress)
 */
function initScanner() {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const telemetry = document.getElementById('uploadTelemetry');
  const progressBar = document.getElementById('progressBarFill');
  const progressPercent = document.getElementById('progressPercent');
  const uploadSpeed = document.getElementById('uploadSpeed');
  const uploadEta = document.getElementById('uploadEta');
  const uploadBytes = document.getElementById('uploadBytes');
  const uploadChunks = document.getElementById('uploadChunks');
  const currentStageMsg = document.getElementById('currentStageMessage');
  const resultsContainer = document.getElementById('scanResultsContainer');
  const cancelBtn = document.getElementById('btnCancelUpload');

  let activeUploader = null;

  if (!dropzone || !fileInput) return;

  dropzone.addEventListener('click', () => fileInput.click());

  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
    });
  });

  dropzone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) handleFile(files[0]);
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) handleFile(e.target.files[0]);
  });

  cancelBtn?.addEventListener('click', () => {
    if (activeUploader) {
      activeUploader.abort();
      telemetry.classList.remove('active');
      dropzone.style.display = 'block';
    }
  });

  function handleFile(file) {
    dropzone.style.display = 'none';
    resultsContainer.innerHTML = '';
    telemetry.classList.add('active');

    // Reset stages
    document.querySelectorAll('.scan-stage-item').forEach(el => el.className = 'scan-stage-item');
    document.getElementById('stage-1')?.classList.add('active');

    activeUploader = new SentinelUploader({
      onProgress: (p) => {
        progressBar.style.width = `${p.percent}%`;
        progressPercent.textContent = `${p.percent}%`;
        uploadSpeed.textContent = `${(p.speedBps / (1024 * 1024)).toFixed(1)} MB/s`;
        uploadEta.textContent = p.etaSeconds > 0 ? `${Math.round(p.etaSeconds)}s` : '—';
        uploadBytes.textContent = `${(p.bytesUploaded / (1024 * 1024)).toFixed(1)} / ${(p.totalBytes / (1024 * 1024)).toFixed(1)} MB`;
        uploadChunks.textContent = `${p.currentChunk} / ${p.totalChunks}`;
      },
      onStage: ({ stage, message }) => {
        currentStageMsg.textContent = message;
        if (stage === 'UPLOADING') {
          setStageActive('stage-1');
        } else if (stage === 'ASSEMBLING' || stage === 'ANALYZING') {
          setStageDone('stage-1');
          setStageActive('stage-2');
          setStageActive('stage-3');
        } else if (stage === 'COMPLETED') {
          setStageDone('stage-1');
          setStageDone('stage-2');
          setStageDone('stage-3');
          setStageDone('stage-4');
        }
      },
      onComplete: (data) => {
        telemetry.classList.remove('active');
        dropzone.style.display = 'block';
        renderScanResults(data, resultsContainer);
      },
      onError: (err) => {
        telemetry.classList.remove('active');
        dropzone.style.display = 'block';
        alert(`Analysis Error: ${err.message}`);
      }
    });

    activeUploader.upload(file);
  }

  function setStageActive(id) {
    const el = document.getElementById(id);
    if (el) el.className = 'scan-stage-item active';
  }

  function setStageDone(id) {
    const el = document.getElementById(id);
    if (el) el.className = 'scan-stage-item completed';
  }
}

/**
 * Load existing scan from history or URL into Scanner View
 */
export async function loadScanIntoScanner(scanId) {
  // Switch to scanner view
  document.querySelectorAll('.nav-btn').forEach(b => {
    if (b.dataset.view === 'view-scanner') b.classList.add('active');
    else b.classList.remove('active');
  });

  document.querySelectorAll('.view-section').forEach(s => {
    if (s.id === 'view-scanner') s.classList.add('active');
    else s.classList.remove('active');
  });

  const resultsContainer = document.getElementById('scanResultsContainer');
  resultsContainer.innerHTML = '<div class="cyber-card" style="text-align: center; padding: 3rem;">Loading scan record...</div>';

  try {
    const resp = await fetch(`/api/scans/${scanId}`);
    if (!resp.ok) throw new Error('Scan not found');
    const data = await resp.json();
    renderScanResults(data, resultsContainer);
  } catch (err) {
    resultsContainer.innerHTML = `<div class="cyber-card" style="color: var(--sev-critical);">Error: ${err.message}</div>`;
  }
}

/**
 * Dashboard View Controller
 */
async function initDashboard() {
  try {
    const statusResp = await fetch('/api/system/status');
    const statusData = await statusResp.json();

    const stats = statusData.components.database.stats;

    const elTotal = document.getElementById('dashTotalScans');
    const elClean = document.getElementById('dashCleanScans');
    const elThreats = document.getElementById('dashThreatScans');
    const elActive = document.getElementById('dashActiveFiles');

    if (elTotal) elTotal.textContent = stats.totalScans;
    if (elClean) elClean.textContent = stats.cleanScans;
    if (elThreats) elThreats.textContent = stats.threatScans;
    if (elActive) elActive.textContent = stats.activeScans;

    // Load recent activity preview
    const recentResp = await fetch('/api/scans?limit=5');
    const recentData = await recentResp.json();
    const tbody = document.getElementById('dashRecentTable');

    if (tbody && recentData.scans) {
      if (recentData.scans.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 2rem;">No scans recorded yet. Upload a file above to start!</td></tr>`;
      } else {
        tbody.innerHTML = recentData.scans.map(s => `
          <tr>
            <td style="font-weight: 600;">${escapeHtml(s.filename)}</td>
            <td><span class="badge badge-${(s.verdict || 'CLEAN').replace('_RISK', '')}">${s.verdict || s.status}</span></td>
            <td><span class="mono-hash" style="font-size: 0.75rem;">${s.sha256 ? `${s.sha256.slice(0, 12)}...` : '—'}</span></td>
            <td><button class="btn btn-secondary btn-sm" onclick="window.sentinelLoadScan('${s.id}')">Inspect</button></td>
          </tr>
        `).join('');
      }
    }
  } catch (err) {
    console.warn('Failed to load dashboard metrics:', err);
  }
}

// Global hook for inspect button
window.sentinelLoadScan = loadScanIntoScanner;

/**
 * Settings Controller
 */
function initSettings() {
  const tokenInput = document.getElementById('settingClientToken');
  const saveBtn = document.getElementById('btnSaveToken');
  const genBtn = document.getElementById('btnGenToken');

  if (tokenInput) {
    tokenInput.value = localStorage.getItem('sentinel_client_token') || '';
  }

  saveBtn?.addEventListener('click', () => {
    localStorage.setItem('sentinel_client_token', tokenInput.value.trim());
    alert('Client ownership token saved!');
  });

  genBtn?.addEventListener('click', () => {
    const newToken = 'ct_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
    tokenInput.value = newToken;
    localStorage.setItem('sentinel_client_token', newToken);
    alert('Generated new cryptographically random client token!');
  });
}

/**
 * Sample Test Generator Controller
 * Safely generates defensive in-browser test samples for live verification
 */
function initSampleGenerator() {
  document.querySelectorAll('[data-sample]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const sampleType = btn.dataset.sample;
      let blob = null;
      let filename = '';

      if (sampleType === 'eicar') {
        // Standard EICAR string
        const eicarString = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
        blob = new Blob([eicarString], { type: 'text/plain' });
        filename = 'eicar_test.com.txt';
      } else if (sampleType === 'zipbomb') {
        // High-ratio test pattern (repeating null bytes in compressed form)
        const content = '0'.repeat(1000000);
        blob = new Blob([content], { type: 'text/plain' });
        filename = 'decompression_test.txt';
      } else if (sampleType === 'powershell') {
        // Safe script with flagged patterns for static parser testing
        const psScript = `# Defensive Static Analyzer Test Sample\nInvoke-Expression -Command "Write-Host 'Safe Test'"\n$client = New-Object System.Net.WebClient\n# DownloadString test comment\n`;
        blob = new Blob([psScript], { type: 'text/plain' });
        filename = 'suspicious_sample.ps1';
      } else if (sampleType === 'pdf_active') {
        // Safe PDF with /JavaScript test directive
        const pdfContent = `%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Names << /JavaScript << /Names [(Test) << /S /JavaScript /JS (app.alert('Test');) >>] >> >> >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f\n0000000009 00000 n\n0000000140 00000 n\ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n190\n%%EOF`;
        blob = new Blob([pdfContent], { type: 'application/pdf' });
        filename = 'active_js_sample.pdf';
      }

      if (blob && filename) {
        const file = new File([blob], filename, { type: blob.type });
        // Switch to scanner view and upload
        document.querySelector('[data-view="view-scanner"]')?.click();
        const dropzone = document.getElementById('dropzone');
        if (dropzone) {
          const dt = new DataTransfer();
          dt.items.add(file);
          const fileInput = document.getElementById('fileInput');
          if (fileInput) {
            fileInput.files = dt.files;
            fileInput.dispatchEvent(new Event('change'));
          }
        }
      }
    });
  });
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
