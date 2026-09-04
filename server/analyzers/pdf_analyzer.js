import fs from 'node:fs';

/**
 * Safe stream-based PDF static analyzer
 */
export async function parsePDF(filePathOrBuffer) {
  let text = '';
  if (typeof filePathOrBuffer === 'string') {
    const data = await fs.promises.readFile(filePathOrBuffer);
    text = data.toString('binary');
  } else {
    text = filePathOrBuffer.toString('binary');
  }

  const findings = [];
  const details = {
    isPDF: false,
    version: 'Unknown',
    objectCount: 0,
    streamCount: 0,
    hasJavaScript: false,
    hasLaunch: false,
    hasOpenAction: false,
    hasEmbeddedFiles: false,
    hasAcroForm: false,
    suspiciousFeatures: []
  };

  if (!text.includes('%PDF-')) {
    return { ...details, error: 'Missing %PDF- header magic' };
  }

  details.isPDF = true;

  // Extract PDF version from header
  const versionMatch = text.match(/%PDF-(\d+\.\d+)/);
  if (versionMatch) {
    details.version = versionMatch[1];
  }

  // Count basic objects and streams
  const objMatches = text.match(/\b\d+\s+\d+\s+obj\b/g);
  details.objectCount = objMatches ? objMatches.length : 0;

  const streamMatches = text.match(/\bstream\b/g);
  details.streamCount = streamMatches ? streamMatches.length : 0;

  // 1. Check for /JavaScript and /JS
  const jsMatches = text.match(/\/JavaScript|\/JS\b/gi);
  if (jsMatches) {
    details.hasJavaScript = true;
    details.suspiciousFeatures.push('/JavaScript');
    findings.push({
      severity: 'HIGH',
      category: 'STATIC_PDF',
      title: 'Active JavaScript in PDF Document',
      description: 'The PDF document contains embedded JavaScript actions (/JS or /JavaScript), which can be abused to exploit PDF viewer vulnerabilities or execute client-side scripts.',
      evidence: `Found ${jsMatches.length} occurrences of /JavaScript or /JS tags.`
    });
  }

  // 2. Check for /Launch action (Command/application execution)
  const launchMatches = text.match(/\/Launch\b/gi);
  if (launchMatches) {
    details.hasLaunch = true;
    details.suspiciousFeatures.push('/Launch');
    findings.push({
      severity: 'CRITICAL',
      category: 'STATIC_PDF',
      title: 'Automatic Application Launch Action (/Launch)',
      description: 'The PDF contains a /Launch action directive designed to spawn an external binary, shell script, or operating system command when viewed.',
      evidence: `Found ${launchMatches.length} occurrence(s) of the /Launch directive.`
    });
  }

  // 3. Check for /OpenAction or /AA (Automatic trigger on open)
  const openActionMatches = text.match(/\/OpenAction|\/AA\b/gi);
  if (openActionMatches) {
    details.hasOpenAction = true;
    details.suspiciousFeatures.push('/OpenAction');
    findings.push({
      severity: 'MEDIUM',
      category: 'STATIC_PDF',
      title: 'Automated Document Open Action (/OpenAction)',
      description: 'The document specifies an automated action to be executed immediately upon viewing without user interaction.',
      evidence: `Found /OpenAction or /AA directives in PDF catalog/trailer.`
    });
  }

  // 4. Check for /EmbeddedFiles (Dropper/stager behavior)
  const embeddedFilesMatches = text.match(/\/EmbeddedFiles|\/Filespec\b/gi);
  if (embeddedFilesMatches) {
    details.hasEmbeddedFiles = true;
    details.suspiciousFeatures.push('/EmbeddedFiles');
    findings.push({
      severity: 'HIGH',
      category: 'STATIC_PDF',
      title: 'Embedded Files Inside PDF Document',
      description: 'The document embeds secondary files (/EmbeddedFiles), a common technique for stagers to drop malicious scripts or executables.',
      evidence: `Found ${embeddedFilesMatches.length} /EmbeddedFiles or /Filespec tags.`
    });
  }

  // 5. Check for /AcroForm
  if (text.includes('/AcroForm')) {
    details.hasAcroForm = true;
  }

  // 6. Check for /RichMedia or /Flash
  if (text.includes('/RichMedia') || text.includes('/Flash')) {
    details.suspiciousFeatures.push('/RichMedia');
    findings.push({
      severity: 'MEDIUM',
      category: 'STATIC_PDF',
      title: 'Embedded RichMedia / Flash Content',
      description: 'Document references deprecated RichMedia / Flash content streams.',
      evidence: 'Found /RichMedia directive.'
    });
  }

  return {
    ...details,
    findings
  };
}
