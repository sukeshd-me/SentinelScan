import fs from 'node:fs';
import { calculateShannonEntropy } from './pe_analyzer.js';

/**
 * Safe read-only static analysis of Linux/Unix ELF32 and ELF64 binaries
 */
export async function parseELF(bufferOrPath) {
  let buffer;
  if (typeof bufferOrPath === 'string') {
    const fd = await fs.promises.open(bufferOrPath, 'r');
    try {
      const stat = await fd.stat();
      const readLen = Math.min(stat.size, 1024 * 1024);
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
    isELF: false,
    format: 'ELF',
    architecture: 'UNKNOWN',
    endianness: 'UNKNOWN',
    fileType: 'UNKNOWN',
    machine: 'UNKNOWN',
    entryPoint: '0x0',
    programHeadersCount: 0,
    programHeaders: [],
    sectionHeadersCount: 0,
    overallEntropy: 0
  };

  if (!buffer || buffer.length < 52) {
    return { ...result, error: 'Buffer too small for ELF header' };
  }

  // 1. Check Magic: 0x7F, 'E', 'L', 'F'
  if (buffer[0] !== 0x7F || buffer[1] !== 0x45 || buffer[2] !== 0x4C || buffer[3] !== 0x46) {
    return { ...result, error: 'Not an ELF header' };
  }

  result.isELF = true;

  const is64Bit = buffer[4] === 2;
  const isLittleEndian = buffer[5] === 1;

  result.architecture = is64Bit ? '64-bit' : '32-bit';
  result.class = is64Bit ? 'ELF64' : 'ELF32';
  result.endianness = isLittleEndian ? 'Little-endian' : 'Big-endian';

  // Read helpers respecting endianness
  const readUInt16 = (off) => isLittleEndian ? buffer.readUInt16LE(off) : buffer.readUInt16BE(off);
  const readUInt32 = (off) => isLittleEndian ? buffer.readUInt32LE(off) : buffer.readUInt32BE(off);

  const typeCode = readUInt16(16);
  const types = {
    1: 'ET_REL (Relocatable object)',
    2: 'ET_EXEC (Executable)',
    3: 'ET_DYN (Shared object / PIE Executable)',
    4: 'ET_CORE (Core dump)'
  };
  result.fileType = types[typeCode] || `Type ${typeCode}`;

  const machineCode = readUInt16(18);
  const machines = {
    0x03: 'x86 (Intel 80386)',
    0x3E: 'x86_64 (AMD/Intel 64)',
    0x28: 'ARM (32-bit)',
    0xB7: 'AArch64 (ARM 64-bit)',
    0xF3: 'RISC-V'
  };
  result.machine = machines[machineCode] || `0x${machineCode.toString(16)}`;

  // Entry point
  if (is64Bit) {
    if (buffer.length >= 32) {
      const entryLow = readUInt32(24);
      result.entryPoint = `0x${entryLow.toString(16)}`;
    }
  } else {
    if (buffer.length >= 28) {
      const entry = readUInt32(24);
      result.entryPoint = `0x${entry.toString(16)}`;
    }
  }

  // Program Headers
  const phOffset = is64Bit ? Number(buffer.readBigUInt64LE ? buffer.readBigUInt64LE(32) : buffer.readUInt32LE(32)) : readUInt32(28);
  const phCount = readUInt16(is64Bit ? 56 : 44);
  const phEntrySize = readUInt16(is64Bit ? 54 : 42);
  result.programHeadersCount = phCount;

  // Inspect Program Headers for W^X violations (RWX segments)
  if (phOffset > 0 && phCount > 0 && phOffset + phCount * phEntrySize <= buffer.length) {
    for (let i = 0; i < phCount; i++) {
      const off = phOffset + i * phEntrySize;
      const pType = readUInt32(off);
      // PT_LOAD = 1
      if (pType === 1) {
        const pFlags = is64Bit ? readUInt32(off + 4) : readUInt32(off + 24);
        const PF_X = 1; // Executable
        const PF_W = 2; // Writable
        const PF_R = 4; // Readable

        const isWritableAndExecutable = Boolean((pFlags & PF_X) && (pFlags & PF_W));
        result.programHeaders.push({
          type: pType,
          flags: pFlags,
          isWritableAndExecutable
        });

        if (isWritableAndExecutable) {
          findings.push({
            severity: 'HIGH',
            category: 'STATIC_ELF',
            title: 'Writable and Executable Program Segment (RWX)',
            description: 'Segment possesses both write and execute permissions, violating W^X security invariants. Often used for unpackers, JIT, or shellcode execution.',
            evidence: `Program Header #${i} flags: 0x${pFlags.toString(16)} (PF_X | PF_W)`
          });
        }
      } else {
        result.programHeaders.push({
          type: pType,
          flags: 0,
          isWritableAndExecutable: false
        });
      }
    }
  }

  // Calculate Overall Entropy
  result.overallEntropy = calculateShannonEntropy(buffer.subarray(0, Math.min(buffer.length, 65536)));
  if (result.overallEntropy > 7.3) {
    findings.push({
      severity: 'HIGH',
      category: 'STATIC_ELF',
      title: 'High Overall Entropy in ELF Binary',
      description: `Entropy is ${result.overallEntropy}/8.0, indicating the ELF binary is likely packed, compressed, or encrypted.`,
      evidence: `ELF entropy: ${result.overallEntropy}`
    });
  }

  // Search for suspicious Linux malware indicators in strings
  const bufStr = buffer.toString('binary');
  const indicators = [
    { text: 'ptrace', desc: 'Anti-debugging or process injection capability' },
    { text: '/etc/shadow', desc: 'Targeting password hash file' },
    { text: 'mprotect', desc: 'Memory protection modification (often used to mark pages executable)' },
    { text: '/bin/sh', desc: 'Direct shell execution reference' }
  ];

  for (const item of indicators) {
    if (bufStr.includes(item.text)) {
      findings.push({
        severity: 'MEDIUM',
        category: 'STATIC_ELF',
        title: `Sensitive Pattern Identified: ${item.text}`,
        description: `Reference to '${item.text}' found in binary: ${item.desc}.`,
        evidence: `Literal occurrence of '${item.text}' in ELF binary.`
      });
    }
  }

  return {
    ...result,
    findings
  };
}
