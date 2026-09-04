import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

const DB_PATH = process.env.DATABASE_PATH || './data/sentinelscan.sqlite';

// Ensure data directory exists
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

export const db = new DatabaseSync(DB_PATH);

// Initialize tables with parameterized/safe schema execution
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  PRAGMA busy_timeout = 10000;

  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    client_token TEXT NOT NULL,
    filename TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    detected_mime TEXT,
    sha256 TEXT,
    sha1 TEXT,
    md5 TEXT,
    status TEXT NOT NULL,
    verdict TEXT DEFAULT 'UNKNOWN',
    risk_score INTEGER DEFAULT 0,
    confidence TEXT DEFAULT 'LOW',
    duration_ms INTEGER DEFAULT 0,
    storage_path TEXT,
    storage_provider TEXT DEFAULT 'local',
    created_at TEXT NOT NULL,
    completed_at TEXT,
    deletion_scheduled_at TEXT,
    deleted_at TEXT,
    deletion_status TEXT DEFAULT 'SCHEDULED',
    deletion_attempts INTEGER DEFAULT 0,
    deletion_error TEXT
  );

  CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS analysis_results (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    engine TEXT NOT NULL,
    status TEXT NOT NULL,
    duration_ms INTEGER DEFAULT 0,
    summary TEXT,
    details_json TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS system_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    scan_id TEXT,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
`);

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
  CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
  CREATE INDEX IF NOT EXISTS idx_scans_deletion ON scans(deletion_status, deletion_scheduled_at);
  CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
  CREATE INDEX IF NOT EXISTS idx_analysis_scan ON analysis_results(scan_id);
`);

try {
  db.exec('ALTER TABLE scans ADD COLUMN file_deleted INTEGER DEFAULT 0;');
} catch {}

/**
 * Parameterized Database Helpers
 */

export function createScanRecord(record) {
  const status = record.status || 'PENDING';
  const stmt = db.prepare(`
    INSERT INTO scans (
      id, client_token, filename, file_size, status, storage_path, storage_provider, created_at, deletion_scheduled_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    record.id,
    record.client_token || record.clientToken || 'anonymous',
    record.filename,
    record.file_size !== undefined ? record.file_size : (record.fileSize !== undefined ? record.fileSize : 0),
    status,
    record.storage_path || null,
    record.storage_provider || 'local',
    record.created_at || new Date().toISOString(),
    record.deletion_scheduled_at || null
  );
  return { ...record, status };
}

export function updateScanRecord(id, updates) {
  const fields = [];
  const values = [];

  const keyMap = {
    riskScore: 'risk_score',
    fileSize: 'file_size',
    clientToken: 'client_token',
    storagePath: 'storage_path',
    storageProvider: 'storage_provider',
    createdAt: 'created_at',
    completedAt: 'completed_at',
    finishedAt: 'completed_at',
    deletionScheduledAt: 'deletion_scheduled_at',
    deletedAt: 'deleted_at',
    deletionStatus: 'deletion_status',
    deletionAttempts: 'deletion_attempts',
    deletionError: 'deletion_error',
    fileDeleted: 'file_deleted',
    durationMs: 'duration_ms',
    detectedMime: 'detected_mime'
  };

  for (const [key, val] of Object.entries(updates)) {
    const colName = keyMap[key] || key;
    fields.push(`${colName} = ?`);
    values.push(val);
  }

  if (fields.length === 0) return;

  values.push(id);
  const stmt = db.prepare(`UPDATE scans SET ${fields.join(', ')} WHERE id = ?`);
  stmt.run(...values);
}

export function getScanById(id) {
  const stmt = db.prepare('SELECT * FROM scans WHERE id = ?');
  return stmt.get(id);
}

export function addFinding(finding) {
  const stmt = db.prepare(`
    INSERT INTO findings (id, scan_id, severity, category, title, description, evidence, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    finding.id,
    finding.scan_id,
    finding.severity,
    finding.category,
    finding.title,
    finding.description,
    finding.evidence || '',
    finding.created_at || new Date().toISOString()
  );
}

export function saveScanFinding(finding) {
  const findingId = finding.id || Math.random().toString(36).substring(2) + Date.now().toString(36);
  return addFinding({
    id: findingId,
    scan_id: finding.scanId || finding.scan_id,
    severity: finding.severity || 'INFO',
    category: finding.category || 'ANALYSIS',
    title: finding.title || 'Security Finding',
    description: finding.description || '',
    evidence: typeof finding.evidence === 'object' ? JSON.stringify(finding.evidence) : (finding.evidence || ''),
    created_at: finding.created_at || new Date().toISOString()
  });
}

export function getFindingsByScanId(scanId) {
  const stmt = db.prepare(`
    SELECT * FROM findings 
    WHERE scan_id = ? 
    ORDER BY CASE severity 
      WHEN 'CRITICAL' THEN 1 
      WHEN 'HIGH' THEN 2 
      WHEN 'MEDIUM' THEN 3 
      WHEN 'LOW' THEN 4 
      ELSE 5 
    END
  `);
  return stmt.all(scanId);
}

export const getScanFindings = getFindingsByScanId;

export function addAnalysisResult(result) {
  const stmt = db.prepare(`
    INSERT INTO analysis_results (id, scan_id, engine, status, duration_ms, summary, details_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    result.id,
    result.scan_id,
    result.engine,
    result.status,
    result.duration_ms || 0,
    result.summary || '',
    typeof result.details_json === 'object' ? JSON.stringify(result.details_json) : (result.details_json || '{}'),
    result.created_at || new Date().toISOString()
  );
}

export function saveAnalysisResult(result) {
  const resId = result.id || Math.random().toString(36).substring(2) + Date.now().toString(36);
  return addAnalysisResult({
    id: resId,
    scan_id: result.scanId || result.scan_id,
    engine: result.engineName || result.engine || 'StaticEngine',
    status: result.status || 'SUCCESS',
    duration_ms: result.durationMs || result.duration_ms || 0,
    summary: result.summary || '',
    details_json: result.details || result.details_json || {},
    created_at: result.created_at || new Date().toISOString()
  });
}

export function getAnalysisResultsByScanId(scanId) {
  const stmt = db.prepare('SELECT * FROM analysis_results WHERE scan_id = ?');
  const results = stmt.all(scanId);
  return results.map(r => ({
    ...r,
    details: r.details_json ? JSON.parse(r.details_json) : {}
  }));
}

export const getAnalysisResults = getAnalysisResultsByScanId;
export const initDb = () => {};

export function logSystemEvent(arg1, arg2, arg3) {
  let eventType, scanId, message;
  if (typeof arg1 === 'object' && arg1 !== null) {
    eventType = arg1.eventType || arg1.event_type || 'SYSTEM';
    scanId = arg1.scanId || arg1.scan_id || null;
    message = arg1.message || '';
  } else {
    eventType = arg1 || 'SYSTEM';
    scanId = arg2 || null;
    message = arg3 || '';
  }
  const stmt = db.prepare('INSERT INTO system_events (event_type, scan_id, message, created_at) VALUES (?, ?, ?, ?)');
  stmt.run(eventType, scanId, message, new Date().toISOString());
}

export function getRecentScans(limit = 10) {
  const stmt = db.prepare(`
    SELECT id, filename, file_size, detected_mime, sha256, verdict, risk_score, confidence, status, created_at, deletion_status
    FROM scans
    ORDER BY created_at DESC
    LIMIT ?
  `);
  return stmt.all(limit);
}

export const listRecentScans = getRecentScans;

export function getSystemStats() {
  const totalStmt = db.prepare('SELECT COUNT(*) as count FROM scans');
  const total = totalStmt.get().count;

  const threatsStmt = db.prepare(`SELECT COUNT(*) as count FROM scans WHERE verdict IN ('CRITICAL_RISK', 'HIGH_RISK')`);
  const threats = threatsStmt.get().count;

  const suspiciousStmt = db.prepare(`SELECT COUNT(*) as count FROM scans WHERE verdict = 'MODERATE_RISK'`);
  const suspicious = suspiciousStmt.get().count;

  const cleanStmt = db.prepare(`SELECT COUNT(*) as count FROM scans WHERE verdict = 'CLEAN'`);
  const clean = cleanStmt.get().count;

  const todayIso = new Date().toISOString().slice(0, 10);
  const todayStmt = db.prepare('SELECT COUNT(*) as count FROM scans WHERE created_at LIKE ?');
  const today = todayStmt.get(`${todayIso}%`).count;

  const verdictsStmt = db.prepare('SELECT verdict, COUNT(*) as count FROM scans GROUP BY verdict');
  const verdicts = verdictsStmt.all();

  const mimesStmt = db.prepare('SELECT detected_mime, COUNT(*) as count FROM scans WHERE detected_mime IS NOT NULL GROUP BY detected_mime ORDER BY count DESC LIMIT 5');
  const mimes = mimesStmt.all();

  return {
    totalScans: total,
    threatsDetected: threats,
    suspiciousFiles: suspicious,
    noThreatDetected: clean,
    scansToday: today,
    verdictsDistribution: verdicts,
    fileTypesDistribution: mimes
  };
}

export const getScanStats = getSystemStats;

export function getRecentSystemEvents(limit = 20) {
  const stmt = db.prepare('SELECT * FROM system_events ORDER BY created_at DESC LIMIT ?');
  return stmt.all(limit);
}

export function deleteScanRecord(id) {
  const stmt = db.prepare('DELETE FROM scans WHERE id = ?');
  return stmt.run(id);
}

export function getScansPendingDeletion(olderThanIsoString) {
  const stmt = db.prepare(`
    SELECT * FROM scans
    WHERE deletion_status = 'SCHEDULED'
      AND deletion_scheduled_at <= ?
      AND deletion_attempts < 3
  `);
  return stmt.all(olderThanIsoString);
}
