import fs from 'node:fs';

/**
 * Safe text/script static analyzer
 * Evaluates scripts and web documents without executing them.
 */
export async function parseScript(filePathOrBuffer, detectedMime = '') {
  let content = '';
  if (typeof filePathOrBuffer === 'string') {
    const data = await fs.promises.readFile(filePathOrBuffer);
    content = data.toString('utf8');
  } else {
    content = filePathOrBuffer.toString('utf8');
  }

  const findings = [];
  const details = {
    isScriptOrText: true,
    dangerousPatternsFound: [],
    lineCount: content.split('\n').length
  };

  // Rule 1: PowerShell Invocations & Payload Downloaders
  const psPatterns = [
    { regex: /\b(Invoke-Expression|iex)\b/i, name: 'Invoke-Expression / IEX', desc: 'Dynamic code execution directive commonly used in fileless PowerShell attacks.' },
    { regex: /\bDownloadString\s*\(/i, name: 'WebClient.DownloadString', desc: 'Remote script download and memory execution pattern.' },
    { regex: /-EncodedCommand\s+[a-zA-Z0-9+/=]{20,}/i, name: 'Base64 Encoded PowerShell Command', desc: 'Obfuscated command execution with -EncodedCommand parameter.' },
    { regex: /-ExecutionPolicy\s+Bypass\b/i, name: 'ExecutionPolicy Bypass Flag', desc: 'Explicitly circumvents system script execution restrictions.' },
    { regex: /-WindowStyle\s+Hidden\b/i, name: 'Hidden Window Style Execution', desc: 'Attempts stealth execution without user-visible console window.' }
  ];

  // Rule 2: Bash / Linux Shell Reverse Shells & Pipe Executions
  const shellPatterns = [
    { regex: /(curl|wget)\s+[^|]+\|\s*(ba)?sh/i, name: 'Pipe to Shell (curl|sh)', desc: 'Unverified external script fetched and directly executed via shell pipe.' },
    { regex: /\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+/i, name: 'Bash /dev/tcp Reverse Shell', desc: 'Direct network socket redirection to remote IP/port.' },
    { regex: /\bmkfifo\s+\/tmp\//i, name: 'Named Pipe Creation in /tmp', desc: 'Common mechanism used for interactive reverse shell establishment.' }
  ];

  // Rule 3: Windows Script Host & Obfuscation
  const wshPatterns = [
    { regex: /WScript\.CreateObject\s*\(\s*["']WScript\.Shell["']\s*\)/i, name: 'WScript.Shell Object Instantiation', desc: 'Creates Windows Script Host shell capable of running external processes.' },
    { regex: /Shell\.Application/i, name: 'Shell.Application COM Object', desc: 'Accesses Windows shell functionality to launch applications.' }
  ];

  // Rule 4: Embedded Scripts in SVG / XML / HTML
  const webPatterns = [
    { regex: /<script[^>]*>[\s\S]*?<\/script>/i, name: 'Embedded <script> Tag', desc: 'Active executable JavaScript block embedded inside document or vector graphic.' },
    { regex: /on(load|error|click|mouseover)\s*=\s*["'][^"']+["']/i, name: 'Inline Event Handler Script', desc: 'Executable DOM event handler (e.g. onload, onerror) present.' },
    { regex: /javascript:\s*[^"'\s]+/i, name: 'javascript: URI Scheme', desc: 'Inline script execution trigger via pseudo-protocol URL.' }
  ];

  const allRules = [
    ...psPatterns.map(p => ({ ...p, severity: 'HIGH', category: 'SCRIPT' })),
    ...shellPatterns.map(p => ({ ...p, severity: 'HIGH', category: 'SCRIPT' })),
    ...wshPatterns.map(p => ({ ...p, severity: 'HIGH', category: 'SCRIPT' })),
    ...webPatterns.map(p => ({ ...p, severity: 'MEDIUM', category: 'SCRIPT' }))
  ];

  for (const rule of allRules) {
    const match = rule.regex.exec(content);
    if (match) {
      details.dangerousPatternsFound.push(rule.name);
      findings.push({
        severity: rule.severity,
        category: 'SCRIPT',
        title: `Suspicious Script Pattern: ${rule.name}`,
        description: rule.desc,
        evidence: `Pattern match: "${match[0].slice(0, 100)}"`
      });
    }
  }

  return {
    ...details,
    findings
  };
}
