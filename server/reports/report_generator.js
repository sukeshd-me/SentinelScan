import { getScanById, getScanFindings, getAnalysisResults } from '../db/db.js';

/**
 * Generate full JSON report
 */
export function generateJsonReport(scanId) {
  const scan = getScanById(scanId);
  if (!scan) return null;

  const findings = getScanFindings(scanId);
  const engineResults = getAnalysisResults(scanId);

  return {
    reportVersion: '1.0.0',
    platform: 'SentinelScan File Safety & Malware Analysis Platform',
    generatedAt: new Date().toISOString(),
    scan: {
      id: scan.id,
      filename: scan.filename,
      fileSize: scan.file_size,
      detectedMime: scan.detected_mime,
      status: scan.status,
      verdict: scan.verdict,
      riskScore: scan.risk_score,
      confidence: scan.confidence,
      createdAt: scan.created_at,
      finishedAt: scan.finished_at,
      retentionExpiresAt: scan.retention_expires_at,
      fileDeleted: Boolean(scan.file_deleted)
    },
    hashes: {
      sha256: scan.sha256,
      sha1: scan.sha1,
      md5: scan.md5
    },
    findings: findings.map(f => ({
      severity: f.severity,
      category: f.category,
      title: f.title,
      description: f.description,
      evidence: f.evidence,
      timestamp: f.created_at
    })),
    engineResults: engineResults.map(e => {
      let parsedDetails = null;
      if (typeof e.details === 'object' && e.details !== null) {
        parsedDetails = e.details;
      } else if (typeof e.details === 'string') {
        try { parsedDetails = JSON.parse(e.details); } catch { parsedDetails = e.details; }
      } else if (typeof e.details_json === 'string') {
        try { parsedDetails = JSON.parse(e.details_json); } catch { parsedDetails = e.details_json; }
      }
      return {
        engine: e.engine || e.engine_name,
        status: e.status,
        durationMs: e.duration_ms,
        summary: e.summary,
        details: parsedDetails
      };
    }),
    defensiveNotice: {
      zeroExecution: 'Analysis was performed exclusively using safe static parsing and stream inspection. The uploaded binary was never executed in memory or process space.',
      limitations: [
        'Static analysis cannot observe runtime behavior or memory-only payloads.',
        'Antivirus engine status depends on local daemon availability.'
      ]
    }
  };
}

/**
 * Generate Markdown executive summary report
 */
export function generateMarkdownReport(scanId) {
  const data = generateJsonReport(scanId);
  if (!data) return null;

  const { scan, hashes, findings, engineResults } = data;

  const findingsTable = findings.length === 0
    ? '_No security anomalies or risk indicators identified._\n'
    : `| Severity | Category | Title | Evidence |
|---|---|---|---|
${findings.map(f => `| **${f.severity}** | \`${f.category}\` | ${f.title} | ${String(f.evidence || '').replace(/\n/g, ' ')} |`).join('\n')}
`;

  const enginesTable = engineResults.map(e => `- **${e.engine}**: \`${e.status}\` — ${e.summary}`).join('\n');

  return `# SentinelScan — File Security Analysis Report

**Scan ID:** \`${scan.id}\`  
**Generated:** ${data.generatedAt}  
**Platform:** SentinelScan (Defensive Zero-Execution Architecture)

---

## 1. Executive Summary

- **File Name:** \`${scan.filename}\`
- **File Size:** ${(scan.fileSize / 1024).toFixed(2)} KB (${scan.fileSize} bytes)
- **Detected Type:** \`${scan.detectedMime || 'Unknown'}\`
- **Verdict:** **${scan.verdict}**
- **Risk Score:** **${scan.riskScore}/100**
- **Confidence Rating:** **${scan.confidence}**
- **File Retention:** Uploaded file ${scan.fileDeleted ? 'has been securely permanently erased' : 'pending automated cleanup'}.

---

## 2. Cryptographic Hashes

- **SHA-256 (Primary):** \`${hashes.sha256 || 'N/A'}\`
- **SHA-1 (Legacy):** \`${hashes.sha1 || 'N/A'}\`
- **MD5 (Legacy):** \`${hashes.md5 || 'N/A'}\`

---

## 3. Findings Summary (${findings.length} total)

${findingsTable}

---

## 4. Engine & Inspector Details

${enginesTable}

---

## 5. Security & Limitations Notice

1. **Zero-Execution Architecture:** SentinelScan parses and inspects binary structures without process execution.
2. **Defensive Limitations:** Static analysis cannot guarantee detection of highly sophisticated dynamic unpacking or unconfigured zero-day threats.
3. SentinelScan is free and open-source defensive cybersecurity software.
`;
}
