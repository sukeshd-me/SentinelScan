import fs from 'node:fs';

/**
 * Calculate Shannon Entropy of a buffer
 * Range: 0.0 (uniform) to 8.0 (completely random / encrypted / compressed)
 */
export function calculateShannonEntropy(buffer) {
  if (!buffer || buffer.length === 0) return 0;

  const frequencies = new Uint32Array(256);
  for (let i = 0; i < buffer.length; i++) {
    frequencies[buffer[i]]++;
  }

  let entropy = 0;
  const total = buffer.length;
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / total;
      entropy -= p * Math.log2(p);
    }
  }

  return Number(entropy.toFixed(3));
}

/**
 * Safe read-only static analysis of Portable Executable (Windows PE32/PE32+) binaries
 */
export async function parsePE(bufferOrPath) {
  let buffer;
  if (typeof bufferOrPath === 'string') {
    // Read up to 2MB to safely inspect headers, section table, and imports
    const fd = await fs.promises.open(bufferOrPath, 'r');
    try {
      const stat = await fd.stat();
      const readLen = Math.min(stat.size, 2 * 1024 * 1024);
      buffer = Buffer.alloc(readLen);
      await fd.read(buffer, 0, readLen, 0);
    } finally {
      await fd.close();
    }
  } else {
    buffer = bufferOrPath;
  }

  const findings = [];
  const result = {
    isPE: false,
    machine: 'UNKNOWN',
    architecture: 'UNKNOWN',
    subsystem: 'UNKNOWN',
    entryPoint: '0x0',
    numberOfSections: 0,
    sections: [],
    hasDigitalSignature: false,
    suspiciousCharacteristics: [],
    imports: [],
    overallEntropy: 0
  };

  if (!buffer || buffer.length < 64) {
    return { ...result, error: 'Buffer too small for DOS header' };
  }

  // 1. Verify DOS Header ('MZ')
  if (buffer[0] !== 0x4D || buffer[1] !== 0x5A) {
    return { ...result, error: 'Not a valid MZ header' };
  }

  const peOffset = buffer.readUInt32LE(0x3C);
  if (peOffset + 24 > buffer.length) {
    return { ...result, error: 'Truncated PE header offset' };
  }

  // 2. Verify PE Signature ('PE\0\0')
  if (buffer[peOffset] !== 0x50 || buffer[peOffset + 1] !== 0x45 ||
      buffer[peOffset + 2] !== 0x00 || buffer[peOffset + 3] !== 0x00) {
    return { ...result, error: 'Invalid PE signature' };
  }

  result.isPE = true;

  // 3. COFF File Header
  const coffOffset = peOffset + 4;
  const machineCode = buffer.readUInt16LE(coffOffset);
  const numberOfSections = buffer.readUInt16LE(coffOffset + 2);
  const timeDateStamp = buffer.readUInt32LE(coffOffset + 4);
  const sizeOfOptionalHeader = buffer.readUInt16LE(coffOffset + 16);
  const characteristics = buffer.readUInt16LE(coffOffset + 18);

  const machines = {
    0x014c: 'x86 (32-bit)',
    0x8664: 'x64 (64-bit AMD/Intel)',
    0x01c0: 'ARM (32-bit)',
    0xaa64: 'ARM64 (64-bit)'
  };
  result.machine = machines[machineCode] || `0x${machineCode.toString(16)}`;
  result.architecture = machineCode === 0x8664 || machineCode === 0xaa64 ? '64-bit' : '32-bit';
  result.numberOfSections = numberOfSections;
  result.compilationTimestamp = new Date(timeDateStamp * 1000).toISOString();

  // 4. Optional Header
  const optOffset = coffOffset + 20;
  let certTableOffset = 0;
  let certTableSize = 0;

  if (sizeOfOptionalHeader > 0 && optOffset + 68 <= buffer.length) {
    const magic = buffer.readUInt16LE(optOffset);
    const isPE32Plus = magic === 0x20b;
    result.format = isPE32Plus ? 'PE32+ (64-bit)' : 'PE32 (32-bit)';

    const entryPoint = buffer.readUInt32LE(optOffset + 16);
    result.entryPoint = `0x${entryPoint.toString(16).toUpperCase()}`;

    const subsystemCode = buffer.readUInt16LE(optOffset + 68);
    const subsystems = {
      1: 'Native',
      2: 'Windows GUI',
      3: 'Windows Console (CUI)',
      7: 'POSIX CUI',
      9: 'Windows CE GUI',
      10: 'EFI Application'
    };
    result.subsystem = subsystems[subsystemCode] || `Subsystem ${subsystemCode}`;

    // Data Directories offset
    const dataDirsOffset = isPE32Plus ? optOffset + 112 : optOffset + 96;
    // Security Directory is entry index 4 (offset + 4*8 = +32)
    if (dataDirsOffset + 40 <= buffer.length) {
      certTableOffset = buffer.readUInt32LE(dataDirsOffset + 32);
      certTableSize = buffer.readUInt32LE(dataDirsOffset + 36);
      result.hasDigitalSignature = certTableSize > 0 && certTableOffset > 0;
    }
  }

  if (!result.hasDigitalSignature) {
    findings.push({
      severity: 'LOW',
      category: 'STATIC_PE',
      title: 'Unsigned Executable Binary',
      description: 'The binary does not contain an embedded digital signature directory.',
      evidence: 'PE Security Data Directory (Entry 4) is null/empty.'
    });
  }

  // 5. Section Headers & Entropy Analysis
  const sectionsOffset = optOffset + sizeOfOptionalHeader;
  let totalEntropySum = 0;
  const knownPackerSections = ['UPX0', 'UPX1', 'UPX2', '.aspack', '.adata', '.packer', 'FSG!', 'PEC2', 'Themida'];

  for (let i = 0; i < numberOfSections && sectionsOffset + (i + 1) * 40 <= buffer.length; i++) {
    const sOffset = sectionsOffset + i * 40;
    const rawName = buffer.subarray(sOffset, sOffset + 8).toString('ascii').replace(/\0/g, '').trim();
    const virtualSize = buffer.readUInt32LE(sOffset + 8);
    const virtualAddress = buffer.readUInt32LE(sOffset + 12);
    const sizeOfRawData = buffer.readUInt32LE(sOffset + 16);
    const pointerToRawData = buffer.readUInt32LE(sOffset + 20);
    const sectionCharacteristics = buffer.readUInt32LE(sOffset + 36);

    // Section buffer for entropy
    let sectionEntropy = 0;
    if (pointerToRawData > 0 && pointerToRawData + sizeOfRawData <= buffer.length) {
      const secBuf = buffer.subarray(pointerToRawData, pointerToRawData + sizeOfRawData);
      sectionEntropy = calculateShannonEntropy(secBuf);
    }

    const isWritable = (sectionCharacteristics & 0x80000000) !== 0;
    const isExecutable = (sectionCharacteristics & 0x20000000) !== 0;

    const sectionInfo = {
      name: rawName,
      virtualSize,
      virtualAddress: `0x${virtualAddress.toString(16)}`,
      rawSize: sizeOfRawData,
      entropy: sectionEntropy,
      isWritable,
      isExecutable,
      isWritableAndExecutable: isWritable && isExecutable
    };
    result.sections.push(sectionInfo);
    totalEntropySum += sectionEntropy;

    // Check W^X violation (Self-modifying / unpacker stub)
    if (isWritable && isExecutable) {
      findings.push({
        severity: 'HIGH',
        category: 'STATIC_PE',
        title: `Writable & Executable Section: ${rawName}`,
        description: 'Section has both write and execute permissions (W^X violation). Commonly observed in polymorphic code, unpackers, or injected shellcode.',
        evidence: `Section '${rawName}' flags: 0x${sectionCharacteristics.toString(16)} (MEM_WRITE | MEM_EXECUTE)`
      });
    }

    // High Entropy Packing Check
    if (sectionEntropy > 7.2 && sizeOfRawData > 2048) {
      findings.push({
        severity: 'HIGH',
        category: 'STATIC_PE',
        title: `High Shannon Entropy in Section: ${rawName}`,
        description: `Section entropy of ${sectionEntropy}/8.0 strongly indicates encrypted, obfuscated, or compressed payload data.`,
        evidence: `Section '${rawName}' rawSize=${sizeOfRawData}, Shannon Entropy=${sectionEntropy}`
      });
    }

    // Known packer signature name check
    if (knownPackerSections.some(pk => rawName.toUpperCase().startsWith(pk))) {
      findings.push({
        severity: 'HIGH',
        category: 'STATIC_PE',
        title: `Packer Signature Detected: ${rawName}`,
        description: `Section name '${rawName}' matches known binary runtime packer or protector signatures.`,
        evidence: `Known packer section name '${rawName}' detected in PE section headers.`
      });
    }
  }

  result.overallEntropy = numberOfSections > 0 ? Number((totalEntropySum / numberOfSections).toFixed(3)) : 0;

  // Safe scan for suspicious Win32 API strings in import / binary space
  const bufStr = buffer.toString('binary');
  const suspiciousApis = [
    { api: 'VirtualAllocEx', desc: 'Remote memory allocation commonly used in process injection' },
    { api: 'WriteProcessMemory', desc: 'Writing memory of another process (code injection)' },
    { api: 'CreateRemoteThread', desc: 'Remote thread execution for DLL injection' },
    { api: 'InternetOpenUrl', desc: 'Network request invocation for secondary payload download' },
    { api: 'URLDownloadToFile', desc: 'Direct URL payload file download' },
    { api: 'SetWindowsHookEx', desc: 'Keystroke logging / system-wide message hooking' },
    { api: 'QueueUserAPC', desc: 'Early bird process injection / APC thread queuing' }
  ];

  for (const item of suspiciousApis) {
    if (bufStr.includes(item.api)) {
      result.imports.push(item.api);
      findings.push({
        severity: 'MEDIUM',
        category: 'STATIC_PE',
        title: `Suspicious API Reference: ${item.api}`,
        description: `${item.api} found in binary imports: ${item.desc}.`,
        evidence: `API string reference '${item.api}' identified.`
      });
    }
  }

  return {
    ...result,
    findings
  };
}
