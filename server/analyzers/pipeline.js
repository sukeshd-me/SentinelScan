import fs from 'node:fs';
import { calculateHashes } from './hasher.js';
import { detectFileType } from './file_type.js';
import { parsePE } from './pe_analyzer.js';
import { parseELF } from './elf_analyzer.js';
import { parsePDF } from './pdf_analyzer.js';
import { parseOffice } from './office_analyzer.js';
import { parseArchive } from './archive_analyzer.js';
import { parseAPK } from './apk_analyzer.js';
import { parseScript } from './script_analyzer.js';
import { scanWithClamAV } from './clamav.js';
import { calculateRiskAssessment } from './risk_engine.js';
import {
  updateScanRecord,
  saveScanFinding,
  saveAnalysisResult,
  logSystemEvent
} from '../db/db.js';
import { scheduleScanCleanup } from '../storage/cleanup.js';

/**
 * Master analysis pipeline coordinator
 */
export async function runAnalysisPipeline(scanId, filePath, originalFilename) {
  logSystemEvent({
    scanId,
    eventType: 'ANALYSIS_STARTED',
    message: `Starting static and antivirus analysis for file: ${originalFilename}`
  });

  updateScanRecord(scanId, { status: 'ANALYZING' });

  try {
    const allFindings = [];

    // Stage 1: Streaming Hashes
    const hashes = await calculateHashes(filePath);

    // Read first 20MB for static buffer analysis if file is large, or full buffer if small
    const stat = await fs.promises.stat(filePath);
    const readSize = Math.min(stat.size, 20 * 1024 * 1024);
    const fd = await fs.promises.open(filePath, 'r');
    const buffer = Buffer.alloc(readSize);
    await fd.read(buffer, 0, readSize, 0);
    await fd.close();

    // Stage 2: File Type Identification & Extension Mismatch
    const fileType = detectFileType(buffer, originalFilename);
    saveAnalysisResult({
      scanId,
      engineName: 'FileTypeDetector',
      status: 'SUCCESS',
      summary: `Identified as ${fileType.mime} (${fileType.format})`,
      details: fileType
    });

    if (fileType.mismatchDetails?.findings) {
      for (const finding of fileType.mismatchDetails.findings) {
        allFindings.push(finding);
      }
    }

    // Stage 3: Format-Specific Analyzers
    let peResult = null;
    let elfResult = null;
    let pdfResult = null;
    let officeResult = null;
    let archiveResult = null;
    let apkResult = null;
    let scriptResult = null;

    // 3a. PE Analysis
    if (fileType.format === 'PE' || fileType.mime === 'application/x-dosexec' || originalFilename.endsWith('.exe') || originalFilename.endsWith('.dll')) {
      peResult = await parsePE(buffer);
      saveAnalysisResult({
        scanId,
        engineName: 'PEStaticParser',
        status: peResult.isPE ? 'SUCCESS' : 'SKIPPED',
        summary: peResult.isPE ? `PE32/PE32+ parsed (${peResult.sections?.length || 0} sections, entropy: ${peResult.overallEntropy})` : 'Not valid PE',
        details: peResult
      });
      if (peResult.findings) allFindings.push(...peResult.findings);
    }

    // 3b. ELF Analysis
    if (fileType.format === 'ELF' || fileType.mime === 'application/x-elf') {
      elfResult = await parseELF(buffer);
      saveAnalysisResult({
        scanId,
        engineName: 'ELFStaticParser',
        status: elfResult.isELF ? 'SUCCESS' : 'SKIPPED',
        summary: elfResult.isELF ? `ELF parsed (${elfResult.programHeaders?.length || 0} program headers)` : 'Not valid ELF',
        details: elfResult
      });
      if (elfResult.findings) allFindings.push(...elfResult.findings);
    }

    // 3c. PDF Analysis
    if (fileType.format === 'PDF' || fileType.mime === 'application/pdf') {
      pdfResult = await parsePDF(buffer);
      saveAnalysisResult({
        scanId,
        engineName: 'PDFStaticParser',
        status: pdfResult.isPDF ? 'SUCCESS' : 'SKIPPED',
        summary: pdfResult.isPDF ? `PDF scanned (JS: ${pdfResult.hasJavaScript}, Launch: ${pdfResult.hasLaunch})` : 'Not valid PDF',
        details: pdfResult
      });
      if (pdfResult.findings) allFindings.push(...pdfResult.findings);
    }

    // 3d. Office Analysis
    if (fileType.format === 'OFFICE_LEGACY' || originalFilename.match(/\.(docx?|xlsx?|pptx?|docm|xlsm|pptm)$/i)) {
      officeResult = await parseOffice(buffer);
      saveAnalysisResult({
        scanId,
        engineName: 'OfficeStaticParser',
        status: officeResult.isOffice ? 'SUCCESS' : 'SKIPPED',
        summary: officeResult.isOffice ? `Office analyzed (${officeResult.formatType}, Macros: ${officeResult.hasVbaMacros})` : 'Not an Office doc',
        details: officeResult
      });
      if (officeResult.findings) allFindings.push(...officeResult.findings);
    }

    // 3e. Archive Analysis (ZIP, TAR, etc.)
    if (fileType.format === 'ZIP' || fileType.format === 'TAR' || originalFilename.match(/\.(zip|tar|gz|apk|jar)$/i)) {
      archiveResult = await parseArchive(buffer);
      saveAnalysisResult({
        scanId,
        engineName: 'ArchiveInspector',
        status: archiveResult.isArchive ? 'SUCCESS' : 'SKIPPED',
        summary: archiveResult.isArchive ? `Archive parsed (${archiveResult.fileCount} entries, ratio: ${archiveResult.compressionRatio}:1)` : 'Not an archive',
        details: archiveResult
      });
      if (archiveResult.findings) allFindings.push(...archiveResult.findings);
    }

    // 3f. APK Analysis
    if (originalFilename.endsWith('.apk') || (archiveResult?.isArchive && buffer.toString('binary').includes('AndroidManifest.xml'))) {
      apkResult = await parseAPK(buffer);
      saveAnalysisResult({
        scanId,
        engineName: 'APKStaticParser',
        status: apkResult.isAPK ? 'SUCCESS' : 'SKIPPED',
        summary: apkResult.isAPK ? `Android package analyzed (${apkResult.permissions.length} perms, ${apkResult.highRiskPermissions.length} sensitive)` : 'Not an APK',
        details: apkResult
      });
      if (apkResult.findings) allFindings.push(...apkResult.findings);
    }

    // 3g. Script / Text Analysis
    if (fileType.mime.startsWith('text/') || originalFilename.match(/\.(ps1|bat|cmd|vbs|sh|bash|py|js|html|svg|xml)$/i)) {
      scriptResult = await parseScript(buffer, fileType.mime);
      saveAnalysisResult({
        scanId,
        engineName: 'ScriptPatternInspector',
        status: 'SUCCESS',
        summary: `Script inspected (${scriptResult.dangerousPatternsFound.length} dangerous patterns)`,
        details: scriptResult
      });
      if (scriptResult.findings) allFindings.push(...scriptResult.findings);
    }

    // Stage 4: Antivirus Scan (ClamAV)
    const clamAvResult = await scanWithClamAV(filePath);
    saveAnalysisResult({
      scanId,
      engineName: 'ClamAV_Antivirus',
      status: clamAvResult.state,
      durationMs: clamAvResult.durationMs,
      summary: clamAvResult.message,
      details: clamAvResult
    });

    if (clamAvResult.state === 'INFECTED') {
      allFindings.push({
        severity: 'CRITICAL',
        category: 'ANTIVIRUS',
        title: `ClamAV Signature Detection: ${clamAvResult.virusName}`,
        description: `Antivirus engine matched known malware signature '${clamAvResult.virusName}'.`,
        evidence: clamAvResult.rawOutput
      });
    }

    // Save all accumulated findings to database
    for (const finding of allFindings) {
      saveScanFinding({
        scanId,
        severity: finding.severity,
        category: finding.category,
        title: finding.title,
        description: finding.description,
        evidence: finding.evidence
      });
    }

    // Stage 5: Deterministic Risk Assessment
    const assessment = calculateRiskAssessment({
      fileTypeResult: fileType,
      clamAvResult,
      peResult,
      elfResult,
      pdfResult,
      officeResult,
      archiveResult,
      apkResult,
      scriptResult,
      allFindings
    });

    // Finalize Scan Record
    updateScanRecord(scanId, {
      status: 'COMPLETED',
      sha256: hashes.sha256,
      sha1: hashes.sha1,
      md5: hashes.md5,
      detectedMime: fileType.mime,
      verdict: assessment.verdict,
      riskScore: assessment.score,
      confidence: assessment.confidence,
      finishedAt: new Date().toISOString()
    });

    logSystemEvent({
      scanId,
      eventType: 'ANALYSIS_COMPLETED',
      message: `Completed analysis for scan ${scanId}. Score: ${assessment.score}/100, Verdict: ${assessment.verdict}, Confidence: ${assessment.confidence}`
    });

    // Stage 6: Schedule automatic 5-minute file deletion
    scheduleScanCleanup(scanId, 5 * 60 * 1000);

    return {
      scanId,
      hashes,
      fileType,
      assessment,
      findings: allFindings
    };
  } catch (err) {
    console.error(`Pipeline failure on scan ${scanId}:`, err);
    updateScanRecord(scanId, {
      status: 'FAILED',
      verdict: 'ERROR',
      confidence: 'LOW',
      finishedAt: new Date().toISOString()
    });

    logSystemEvent({
      scanId,
      eventType: 'ANALYSIS_FAILED',
      message: `Analysis pipeline encountered unrecoverable error: ${err.message}`
    });

    // Schedule cleanup even if failed
    scheduleScanCleanup(scanId, 60 * 1000);
    throw err;
  }
}
