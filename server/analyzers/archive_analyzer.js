import fs from 'node:fs';
import path from 'node:path';

/**
 * Safe archive inspector (ZIP / TAR / Central Directory parser)
 * Reads structural headers WITHOUT blind extraction to disk.
 */
export async function parseArchive(filePathOrBuffer) {
  let buffer;
  if (typeof filePathOrBuffer === 'string') {
    buffer = await fs.promises.readFile(filePathOrBuffer);
  } else {
    buffer = filePathOrBuffer;
  }

  const findings = [];
  const details = {
    isArchive: false,
    archiveType: 'UNKNOWN',
    fileCount: 0,
    totalCompressedSize: 0,
    totalUncompressedSize: 0,
    compressionRatio: 0,
    executableCount: 0,
    nestedArchiveCount: 0,
    hasZipBombCharacteristics: false,
    hasTraversalAttacks: false,
    hasSymlinks: false,
    files: []
  };

  if (!buffer || buffer.length < 22) {
    return { ...details, error: 'File too small for archive header' };
  }

  // Check if ZIP format (PK\x03\x04 or PK\x05\x06)
  const isZip = buffer[0] === 0x50 && buffer[1] === 0x4B;
  const isTar = buffer.length >= 512 && buffer.subarray(257, 262).toString('ascii') === 'ustar';

  if (!isZip && !isTar) {
    return { ...details, error: 'Not a supported ZIP or TAR archive structure' };
  }

  if (isZip) {
    details.isArchive = true;
    details.archiveType = 'ZIP';
    parseZipStructure(buffer, details, findings);
  } else if (isTar) {
    details.isArchive = true;
    details.archiveType = 'TAR';
    parseTarStructure(buffer, details, findings);
  }

  return {
    ...details,
    findings
  };
}

/**
 * Parse ZIP Central Directory and Local File Headers safely
 */
function parseZipStructure(buffer, details, findings) {
  const executableExts = ['.exe', '.dll', '.scr', '.bat', '.ps1', '.vbs', '.js', '.cmd', '.hta', '.cpl', '.msi', '.jar', '.com', '.pif'];
  const archiveExts = ['.zip', '.7z', '.rar', '.tar', '.gz', '.bz2', '.iso', '.img', '.cab'];

  // Search for End of Central Directory Record (EOCD) signature: 0x06054b50 (PK\x05\x06)
  // Searching backwards from end of buffer (max comment size is 65535 bytes + 22 bytes header)
  let eocdOffset = -1;
  const maxSearch = Math.min(buffer.length - 22, 65557);
  for (let i = buffer.length - 22; i >= buffer.length - maxSearch; i--) {
    if (buffer[i] === 0x50 && buffer[i + 1] === 0x4B && buffer[i + 2] === 0x05 && buffer[i + 3] === 0x06) {
      eocdOffset = i;
      break;
    }
  }

  if (eocdOffset === -1) {
    // Fallback: parse sequential local file headers (PK\x03\x04)
    parseZipLocalHeaders(buffer, details, findings);
    return;
  }

  const totalEntries = buffer.readUInt16LE(eocdOffset + 10);
  const cdSize = buffer.readUInt32LE(eocdOffset + 12);
  const cdOffset = buffer.readUInt32LE(eocdOffset + 16);

  if (cdOffset + cdSize > buffer.length) {
    findings.push({
      severity: 'HIGH',
      category: 'ARCHIVE',
      title: 'Corrupted or Truncated ZIP Central Directory',
      description: 'The ZIP central directory offset points beyond the boundary of the file.',
      evidence: `Reported CD offset=${cdOffset}, cdSize=${cdSize}, fileLength=${buffer.length}`
    });
    return;
  }

  let offset = cdOffset;
  let entriesParsed = 0;

  while (offset + 46 <= buffer.length && entriesParsed < totalEntries) {
    // Check Central Directory Header signature: 0x02014b50 (PK\x01\x02)
    if (buffer[offset] !== 0x50 || buffer[offset + 1] !== 0x4B || buffer[offset + 2] !== 0x01 || buffer[offset + 3] !== 0x02) {
      break;
    }

    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const filenameLen = buffer.readUInt16LE(offset + 28);
    const extraLen = buffer.readUInt16LE(offset + 30);
    const commentLen = buffer.readUInt16LE(offset + 32);

    offset += 46;
    if (offset + filenameLen > buffer.length) break;

    const entryName = buffer.subarray(offset, offset + filenameLen).toString('utf8');
    offset += filenameLen + extraLen + commentLen;
    entriesParsed++;

    details.fileCount++;
    details.totalCompressedSize += compressedSize;
    details.totalUncompressedSize += uncompressedSize;

    checkEntrySecurity(entryName, compressedSize, uncompressedSize, details, findings, executableExts, archiveExts);
  }

  finalizeArchiveMetrics(details, findings);
}

/**
 * Fallback: Scan sequential local headers (PK\x03\x04)
 */
function parseZipLocalHeaders(buffer, details, findings) {
  const executableExts = ['.exe', '.dll', '.scr', '.bat', '.ps1', '.vbs', '.js', '.cmd', '.hta', '.cpl', '.msi'];
  const archiveExts = ['.zip', '.7z', '.rar', '.tar', '.gz', '.bz2', '.iso'];

  let offset = 0;
  const maxEntries = 5000;

  while (offset + 30 <= buffer.length && details.fileCount < maxEntries) {
    if (buffer[offset] !== 0x50 || buffer[offset + 1] !== 0x4B || buffer[offset + 2] !== 0x03 || buffer[offset + 3] !== 0x04) {
      offset++;
      continue;
    }

    const compressedSize = buffer.readUInt32LE(offset + 18);
    const uncompressedSize = buffer.readUInt32LE(offset + 22);
    const filenameLen = buffer.readUInt16LE(offset + 26);
    const extraLen = buffer.readUInt16LE(offset + 28);

    offset += 30;
    if (offset + filenameLen > buffer.length) break;

    const entryName = buffer.subarray(offset, offset + filenameLen).toString('utf8');
    offset += filenameLen + extraLen;

    details.fileCount++;
    details.totalCompressedSize += compressedSize;
    details.totalUncompressedSize += uncompressedSize;

    checkEntrySecurity(entryName, compressedSize, uncompressedSize, details, findings, executableExts, archiveExts);

    if (compressedSize > 0 && offset + compressedSize <= buffer.length) {
      offset += compressedSize;
    }
  }

  finalizeArchiveMetrics(details, findings);
}

/**
 * Parse TAR Header Blocks (512-byte blocks) safely
 */
function parseTarStructure(buffer, details, findings) {
  const executableExts = ['.exe', '.dll', '.scr', '.bat', '.ps1', '.vbs', '.sh'];
  const archiveExts = ['.zip', '.tar', '.gz'];

  let offset = 0;
  while (offset + 512 <= buffer.length) {
    const block = buffer.subarray(offset, offset + 512);
    // Check if zero block
    if (block[0] === 0 && block[1] === 0) break;

    const name = block.subarray(0, 100).toString('utf8').replace(/\0.*$/g, '').trim();
    const sizeStr = block.subarray(124, 136).toString('ascii').replace(/\0.*$/g, '').trim();
    const size = parseInt(sizeStr, 8) || 0;
    const typeFlag = String.fromCharCode(block[156]);

    if (name) {
      details.fileCount++;
      details.totalUncompressedSize += size;
      details.totalCompressedSize += size;

      // Type 2 = Symlink
      if (typeFlag === '2') {
        details.hasSymlinks = true;
        findings.push({
          severity: 'HIGH',
          category: 'ARCHIVE',
          title: 'Symbolic Link Detected in Archive',
          description: `Archive entry '${name}' is a symbolic link, which can be leveraged for link-following or privilege escalation attacks.`,
          evidence: `TAR link entry: ${name}`
        });
      }

      checkEntrySecurity(name, size, size, details, findings, executableExts, archiveExts);
    }

    // Skip to next 512-byte block boundary
    const blocksToSkip = Math.ceil(size / 512);
    offset += 512 + blocksToSkip * 512;
  }

  finalizeArchiveMetrics(details, findings);
}

/**
 * Check individual archive entry for security threats
 */
function checkEntrySecurity(entryName, compressedSize, uncompressedSize, details, findings, executableExts, archiveExts) {
  const ext = path.extname(entryName).toLowerCase();

  if (details.files.length < 50) {
    details.files.push({
      name: entryName,
      size: uncompressedSize,
      compressedSize
    });
  }

  // 1. Directory Traversal Check (Zip Slip)
  const isTraversal = entryName.includes('../') ||
                      entryName.includes('..\\') ||
                      entryName.startsWith('/') ||
                      entryName.startsWith('\\') ||
                      /^[a-zA-Z]:[\\/]/.test(entryName) ||
                      entryName.includes('\0');

  if (isTraversal) {
    details.hasTraversalAttacks = true;
    findings.push({
      severity: 'CRITICAL',
      category: 'ARCHIVE',
      title: 'Directory Traversal Attempt (Zip Slip)',
      description: `Archive entry contains path traversal characters or absolute paths designed to write outside destination directories during extraction: ${entryName}`,
      evidence: `Malicious archive path: '${entryName}'`
    });
  }

  // 2. Executables inside archive
  if (executableExts.includes(ext)) {
    details.executableCount++;
    findings.push({
      severity: 'HIGH',
      category: 'ARCHIVE',
      title: `Executable Binary Inside Archive: ${path.basename(entryName)}`,
      description: `Archive packages an executable file '${entryName}'. Archives containing executables are standard vectors for initial malware delivery.`,
      evidence: `Executable path: ${entryName} (ext: ${ext})`
    });
  }

  // 3. Nested Archive
  if (archiveExts.includes(ext)) {
    details.nestedArchiveCount++;
  }
}

/**
 * Compute global archive metrics and evaluate Zip Bomb conditions
 */
function finalizeArchiveMetrics(details, findings) {
  if (details.totalCompressedSize > 0) {
    details.compressionRatio = Number((details.totalUncompressedSize / details.totalCompressedSize).toFixed(1));
  }

  // Zip Bomb Condition 1: Compression ratio > 100:1 with meaningful expansion
  if (details.compressionRatio > 100 && details.totalUncompressedSize > 50 * 1024 * 1024) {
    details.hasZipBombCharacteristics = true;
    findings.push({
      severity: 'CRITICAL',
      category: 'ARCHIVE',
      title: 'Decompression Bomb (Zip Bomb) Detected',
      description: `Abnormal compression ratio of ${details.compressionRatio}:1 indicates a decompression bomb designed to exhaust system disk or memory upon extraction.`,
      evidence: `Compressed: ${(details.totalCompressedSize / (1024*1024)).toFixed(2)} MB, Uncompressed: ${(details.totalUncompressedSize / (1024*1024)).toFixed(2)} MB, Ratio: ${details.compressionRatio}:1`
    });
  }

  // Zip Bomb Condition 2: Uncompressed size exceeds 1 GB limit
  if (details.totalUncompressedSize > 1024 * 1024 * 1024) {
    details.hasZipBombCharacteristics = true;
    findings.push({
      severity: 'CRITICAL',
      category: 'ARCHIVE',
      title: 'Excessive Archive Expansion Size (> 1 GB)',
      description: `Total uncompressed size of ${details.totalUncompressedSize} bytes exceeds the maximum safety extraction threshold.`,
      evidence: `Total uncompressed size: ${(details.totalUncompressedSize / (1024*1024*1024)).toFixed(2)} GB`
    });
  }
}
