/**
 * Deterministic Evidence-Based Risk Engine
 */

export function calculateRiskAssessment({
  fileTypeResult,
  clamAvResult,
  peResult,
  elfResult,
  pdfResult,
  officeResult,
  archiveResult,
  apkResult,
  scriptResult,
  allFindings = []
}) {
  let score = 0;
  const weightedEvidence = [];
  const limitations = [];

  // 1. Antivirus Evidence (ClamAV)
  if (clamAvResult) {
    if (clamAvResult.state === 'INFECTED') {
      const weight = 85;
      score += weight;
      weightedEvidence.push({
        source: 'Antivirus (ClamAV)',
        weight,
        description: `Known malware signature identified: ${clamAvResult.virusName}`
      });
    } else if (clamAvResult.state === 'NOT_SCANNED' || !clamAvResult.available) {
      limitations.push('Antivirus signature engine was unavailable during this scan (clamd daemon offline).');
    }
  } else {
    limitations.push('Antivirus scan was not performed.');
  }

  // 2. Extension Mismatch Evidence
  if (fileTypeResult?.mismatchDetails?.hasMismatch) {
    for (const finding of fileTypeResult.mismatchDetails.findings) {
      let weight = 20;
      if (finding.severity === 'CRITICAL') weight = 65;
      else if (finding.severity === 'HIGH') weight = 45;
      score += weight;
      weightedEvidence.push({
        source: 'File Identification',
        weight,
        description: finding.reason
      });
    }
  }

  // 3. Archive Threats (Zip Slip, Zip Bomb, Nested Executables)
  if (archiveResult?.isArchive) {
    if (archiveResult.hasZipBombCharacteristics) {
      const weight = 80;
      score += weight;
      weightedEvidence.push({
        source: 'Archive Security',
        weight,
        description: `Decompression bomb characteristics detected (expansion ratio: ${archiveResult.compressionRatio}:1)`
      });
    }

    if (archiveResult.hasTraversalAttacks) {
      const weight = 75;
      score += weight;
      weightedEvidence.push({
        source: 'Archive Security',
        weight,
        description: 'Directory traversal (Zip Slip) sequences found targeting filesystem escape.'
      });
    }

    if (archiveResult.executableCount > 0) {
      const weight = Math.min(40, archiveResult.executableCount * 20);
      score += weight;
      weightedEvidence.push({
        source: 'Archive Security',
        weight,
        description: `Archive packages ${archiveResult.executableCount} executable binary/script file(s).`
      });
    }
  }

  // 4. PDF Active Elements
  if (pdfResult?.isPDF) {
    if (pdfResult.hasLaunch) {
      const weight = 60;
      score += weight;
      weightedEvidence.push({
        source: 'PDF Static Analysis',
        weight,
        description: 'Automatic application launch action (/Launch) configured in document.'
      });
    }
    if (pdfResult.hasJavaScript) {
      const weight = 35;
      score += weight;
      weightedEvidence.push({
        source: 'PDF Static Analysis',
        weight,
        description: 'Embedded JavaScript scripts (/JS or /JavaScript) present.'
      });
    }
    if (pdfResult.hasEmbeddedFiles) {
      const weight = 30;
      score += weight;
      weightedEvidence.push({
        source: 'PDF Static Analysis',
        weight,
        description: 'Secondary embedded payload files detected inside document.'
      });
    }
  }

  // 5. Office Active Threats
  if (officeResult?.isOffice) {
    if (officeResult.hasRemoteTemplateInjection) {
      const weight = 65;
      score += weight;
      weightedEvidence.push({
        source: 'Office Static Analysis',
        weight,
        description: 'Remote template injection target URL configured in relationships.'
      });
    }
    if (officeResult.hasDdeLinks) {
      const weight = 60;
      score += weight;
      weightedEvidence.push({
        source: 'Office Static Analysis',
        weight,
        description: 'Dynamic Data Exchange (DDE) command execution directive identified.'
      });
    }
    if (officeResult.hasVbaMacros) {
      const weight = 40;
      score += weight;
      weightedEvidence.push({
        source: 'Office Static Analysis',
        weight,
        description: 'Visual Basic for Applications (VBA) macro storage components found.'
      });
    }
  }

  // 6. PE Binary Anomalies
  if (peResult?.isPE) {
    const hasWX = peResult.findings?.some(f => f.title.includes('Writable & Executable'));
    if (hasWX) {
      const weight = 45;
      score += weight;
      weightedEvidence.push({
        source: 'PE Static Analysis',
        weight,
        description: 'Writable and Executable section (W^X violation) indicates unpacker or shellcode stub.'
      });
    }

    const hasHighEntropy = peResult.sections?.some(s => s.entropy > 7.2 && s.rawSize > 2048);
    if (hasHighEntropy) {
      const weight = 30;
      score += weight;
      weightedEvidence.push({
        source: 'PE Static Analysis',
        weight,
        description: 'High Shannon entropy section indicates binary packing, encryption, or compression.'
      });
    }

    if (!peResult.hasDigitalSignature) {
      const weight = 10;
      score += weight;
      weightedEvidence.push({
        source: 'PE Static Analysis',
        weight,
        description: 'Binary does not contain an embedded digital signature.'
      });
    }
  }

  // 7. ELF Binary Anomalies
  if (elfResult?.isELF) {
    const hasWX = elfResult.findings?.some(f => f.title.includes('Writable and Executable'));
    if (hasWX) {
      const weight = 45;
      score += weight;
      weightedEvidence.push({
        source: 'ELF Static Analysis',
        weight,
        description: 'RWX segment detected violating W^X security invariants.'
      });
    }
  }

  // 8. Script Pattern Findings
  if (scriptResult?.dangerousPatternsFound?.length > 0) {
    const weight = Math.min(65, scriptResult.dangerousPatternsFound.length * 25);
    score += weight;
    weightedEvidence.push({
      source: 'Script Static Analysis',
      weight,
      description: `Suspicious execution patterns found: ${scriptResult.dangerousPatternsFound.join(', ')}`
    });
  }

  // 9. APK Findings
  if (apkResult?.isAPK) {
    if (apkResult.highRiskPermissions?.length > 0) {
      const weight = Math.min(40, apkResult.highRiskPermissions.length * 15);
      score += weight;
      weightedEvidence.push({
        source: 'APK Static Analysis',
        weight,
        description: `High-risk Android permissions declared: ${apkResult.highRiskPermissions.length} sensitive permissions.`
      });
    }
  }

  // Cap score strictly at 100
  score = Math.min(100, Math.max(0, score));

  // Determine Verdict
  let verdict = 'CLEAN';
  if (score >= 75) {
    verdict = 'CRITICAL_RISK';
  } else if (score >= 50) {
    verdict = 'HIGH_RISK';
  } else if (score >= 20) {
    verdict = 'MODERATE_RISK';
  } else if (score > 0) {
    verdict = 'LOW_RISK';
  }

  // Calculate Confidence Metric
  let confidence = 'HIGH';
  if (fileTypeResult?.format === 'UNKNOWN') {
    confidence = 'LOW';
    limitations.push('File format could not be identified by magic bytes; specialized structural parsing was unavailable.');
  } else if (!clamAvResult?.available) {
    confidence = 'MODERATE';
    limitations.push('Confidence is moderate because signature-based antivirus confirmation was offline.');
  }

  // Universal Defensive Security Limitations
  limitations.push('Static analysis cannot observe dynamic runtime code injection, memory-only execution, or network C2 activity.');
  limitations.push('Defensive security scanners cannot provide a 100% mathematical guarantee that a file is completely free of risk.');
  limitations.push('External paid threat-intelligence APIs are not configured (free-first open-source deployment).');

  return {
    score,
    verdict,
    confidence,
    weightedEvidence,
    limitations,
    findingsCount: allFindings.length
  };
}
