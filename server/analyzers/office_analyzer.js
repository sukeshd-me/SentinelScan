import fs from 'node:fs';

/**
 * Safe inspection of Office documents (OpenXML and legacy OLE formats)
 */
export async function parseOffice(filePathOrBuffer) {
  let text = '';
  if (typeof filePathOrBuffer === 'string') {
    const data = await fs.promises.readFile(filePathOrBuffer);
    text = data.toString('binary');
  } else {
    text = filePathOrBuffer.toString('binary');
  }

  const findings = [];
  const details = {
    isOffice: false,
    formatType: 'UNKNOWN',
    hasVbaMacros: false,
    hasRemoteTemplateInjection: false,
    hasEmbeddedOleObjects: false,
    hasDdeLinks: false,
    remoteTargets: [],
    macroArtifacts: []
  };

  // Detect format: OpenXML (starts with PK) or Legacy OLE (D0 CF 11 E0)
  const isPK = text.startsWith('PK\x03\x04') || text.startsWith('PK\x05\x06');
  const isOLE = text.charCodeAt(0) === 0xD0 && text.charCodeAt(1) === 0xCF && text.charCodeAt(2) === 0x11 && text.charCodeAt(3) === 0xE0;

  if (!isPK && !isOLE) {
    return { ...details, error: 'File is not a recognizable Office document container' };
  }

  details.isOffice = true;
  details.formatType = isPK ? 'Office OpenXML (ZIP Container)' : 'Legacy OLE Compound File';

  // 1. VBA Macro Detection
  const macroIndicators = [
    'vbaProject.bin',
    'word/vbaProject.bin',
    'xl/vbaProject.bin',
    'ppt/vbaProject.bin',
    '_VBA_PROJECT',
    'VBA/dir',
    'VBA_PROJECT_CUR'
  ];

  for (const indicator of macroIndicators) {
    if (text.includes(indicator)) {
      details.hasVbaMacros = true;
      details.macroArtifacts.push(indicator);
    }
  }

  if (details.hasVbaMacros) {
    findings.push({
      severity: 'HIGH',
      category: 'STATIC_OFFICE',
      title: 'VBA Macros Detected in Office Document',
      description: 'Document contains embedded Visual Basic for Applications (VBA) macro code. Macros can execute arbitrary commands, download payloads, and manipulate system files.',
      evidence: `Found macro storage components: ${details.macroArtifacts.join(', ')}`
    });
  }

  // 2. Remote Template Injection (Follina / malicious dotm template injection)
  const remoteRelPattern = /TargetMode=["']External["'][^>]*Target=["'](https?:\/\/[^"']+)["']/gi;
  let match;
  while ((match = remoteRelPattern.exec(text)) !== null) {
    const targetUrl = match[1];
    details.hasRemoteTemplateInjection = true;
    details.remoteTargets.push(targetUrl);
  }

  if (details.hasRemoteTemplateInjection) {
    findings.push({
      severity: 'CRITICAL',
      category: 'STATIC_OFFICE',
      title: 'Remote Template Injection Detected',
      description: 'Document is configured with an external relationship to fetch an external template via HTTP/HTTPS upon opening. Highly prevalent in phishing and initial access campaigns.',
      evidence: `External targets: ${details.remoteTargets.join(', ')}`
    });
  }

  // 3. Embedded OLE Objects & Packages (stagers/droppers)
  if (text.includes('oleObject') || text.includes('embeddings/') || text.includes('Package.bin')) {
    details.hasEmbeddedOleObjects = true;
    findings.push({
      severity: 'MEDIUM',
      category: 'STATIC_OFFICE',
      title: 'Embedded OLE Object / Binary Package',
      description: 'Document contains embedded OLE objects or binary packages that can hold dropped binaries, scripts, or malicious attachments.',
      evidence: 'Found OLE embedding stream references (e.g. oleObject, embeddings/)'
    });
  }

  // 4. DDE (Dynamic Data Exchange) command execution
  if (/\b(DDEAUTO|DDE)\s+"[^"]+"/i.test(text)) {
    details.hasDdeLinks = true;
    findings.push({
      severity: 'CRITICAL',
      category: 'STATIC_OFFICE',
      title: 'Dynamic Data Exchange (DDE) Command Execution',
      description: 'Document contains DDE field codes configured to execute external system processes without requiring macro permissions.',
      evidence: 'DDEAUTO or DDE directive string identified in document body.'
    });
  }

  return {
    ...details,
    findings
  };
}
