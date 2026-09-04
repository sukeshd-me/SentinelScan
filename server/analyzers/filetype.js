import path from 'node:path';

/**
 * Identify real file format from magic bytes and detect extension/MIME mismatches
 */
export function identifyFileType(buffer, filename = '') {
  if (!buffer || buffer.length === 0) {
    return {
      format: 'EMPTY',
      mime: 'application/x-empty',
      description: 'Empty file',
      isExecutable: false,
      isArchive: false,
      mismatch: false
    };
  }

  let format = 'UNKNOWN';
  let mime = 'application/octet-stream';
  let description = 'Unknown binary data';
  let isExecutable = false;
  let isArchive = false;
  let category = 'BINARY';

  const len = buffer.length;

  // 1. Check PE (Portable Executable - Windows EXE/DLL/SYS)
  if (len >= 2 && buffer[0] === 0x4D && buffer[1] === 0x5A) { // MZ
    if (len >= 0x40) {
      const peOffset = buffer.readUInt32LE(0x3C);
      if (peOffset + 4 <= len &&
          buffer[peOffset] === 0x50 &&
          buffer[peOffset + 1] === 0x45 &&
          buffer[peOffset + 2] === 0x00 &&
          buffer[peOffset + 3] === 0x00) {
        format = 'PE_EXECUTABLE';
        mime = 'application/vnd.microsoft.portable-executable';
        description = 'Windows Portable Executable (EXE/DLL/SYS)';
        isExecutable = true;
        category = 'EXECUTABLE';
      } else {
        format = 'DOS_EXECUTABLE';
        mime = 'application/x-dosexec';
        description = 'DOS MZ Executable';
        isExecutable = true;
        category = 'EXECUTABLE';
      }
    } else {
      format = 'DOS_EXECUTABLE';
      mime = 'application/x-dosexec';
      description = 'DOS Executable';
      isExecutable = true;
      category = 'EXECUTABLE';
    }
  }
  // 2. Check ELF (Linux / Unix Executable)
  else if (len >= 4 && buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x46) {
    format = 'ELF_EXECUTABLE';
    mime = 'application/x-executable';
    description = buffer[4] === 2 ? 'Linux/Unix ELF 64-bit Executable' : 'Linux/Unix ELF 32-bit Executable';
    isExecutable = true;
    category = 'EXECUTABLE';
  }
  // 3. Mach-O (macOS / iOS)
  else if (len >= 4 && (
    (buffer[0] === 0xFE && buffer[1] === 0xED && buffer[2] === 0xFA && buffer[3] === 0xCE) ||
    (buffer[0] === 0xFE && buffer[1] === 0xED && buffer[2] === 0xFA && buffer[3] === 0xCF) ||
    (buffer[0] === 0xCF && buffer[1] === 0xFA && buffer[2] === 0xED && buffer[3] === 0xFE) ||
    (buffer[0] === 0xCE && buffer[1] === 0xFA && buffer[2] === 0xED && buffer[3] === 0xFE)
  )) {
    format = 'MACHO_EXECUTABLE';
    mime = 'application/x-mach-binary';
    description = 'Apple Mach-O Binary';
    isExecutable = true;
    category = 'EXECUTABLE';
  }
  // 4. Java Class file
  else if (len >= 4 && buffer[0] === 0xCA && buffer[1] === 0xFE && buffer[2] === 0xBA && buffer[3] === 0xBE) {
    format = 'JAVA_CLASS';
    mime = 'application/java-vm';
    description = 'Compiled Java Class File';
    isExecutable = true;
    category = 'EXECUTABLE';
  }
  // 5. WebAssembly
  else if (len >= 4 && buffer[0] === 0x00 && buffer[1] === 0x61 && buffer[2] === 0x73 && buffer[3] === 0x6D) {
    format = 'WASM';
    mime = 'application/wasm';
    description = 'WebAssembly Binary';
    isExecutable = true;
    category = 'EXECUTABLE';
  }
  // 6. PDF Document
  else if (len >= 5 && buffer.subarray(0, 1024).indexOf(Buffer.from('%PDF-')) !== -1) {
    format = 'PDF';
    mime = 'application/pdf';
    description = 'Portable Document Format (PDF)';
    category = 'DOCUMENT';
  }
  // 7. ZIP Archive / OpenXML / APK / JAR
  else if (len >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4B && (buffer[2] === 0x03 || buffer[2] === 0x05 || buffer[2] === 0x07)) {
    format = 'ZIP_ARCHIVE';
    mime = 'application/zip';
    description = 'ZIP Compressed Archive';
    isArchive = true;
    category = 'ARCHIVE';

    // Sub-identify Office OpenXML, APK, JAR if entries can be read
    const headStr = buffer.subarray(0, Math.min(len, 4096)).toString('utf8');
    if (headStr.includes('word/') || headStr.includes('[Content_Types].xml')) {
      format = 'OFFICE_OPENXML';
      mime = 'application/vnd.openxmlformats-officedocument';
      description = 'Microsoft Office OpenXML Document';
      category = 'DOCUMENT';
    } else if (headStr.includes('AndroidManifest.xml') || headStr.includes('classes.dex')) {
      format = 'ANDROID_APK';
      mime = 'application/vnd.android.package-archive';
      description = 'Android Application Package (APK)';
      isExecutable = true;
      category = 'PACKAGE';
    } else if (headStr.includes('META-INF/MANIFEST.MF')) {
      format = 'JAVA_JAR';
      mime = 'application/java-archive';
      description = 'Java Archive (JAR)';
      isExecutable = true;
      category = 'PACKAGE';
    }
  }
  // 8. 7-Zip
  else if (len >= 6 && buffer[0] === 0x37 && buffer[1] === 0x7A && buffer[2] === 0xBC && buffer[3] === 0xAF && buffer[4] === 0x27 && buffer[5] === 0x1C) {
    format = '7Z_ARCHIVE';
    mime = 'application/x-7z-compressed';
    description = '7-Zip Compressed Archive';
    isArchive = true;
    category = 'ARCHIVE';
  }
  // 9. RAR Archive
  else if (len >= 7 && buffer[0] === 0x52 && buffer[1] === 0x61 && buffer[2] === 0x72 && buffer[3] === 0x21 && buffer[4] === 0x1A && buffer[5] === 0x07) {
    format = 'RAR_ARCHIVE';
    mime = 'application/vnd.rar';
    description = 'RAR Compressed Archive';
    isArchive = true;
    category = 'ARCHIVE';
  }
  // 10. GZIP
  else if (len >= 2 && buffer[0] === 0x1F && buffer[1] === 0x8B) {
    format = 'GZIP_ARCHIVE';
    mime = 'application/gzip';
    description = 'Gzip Compressed Archive';
    isArchive = true;
    category = 'ARCHIVE';
  }
  // 11. TAR Archive
  else if (len >= 512 && buffer.subarray(257, 262).toString('ascii') === 'ustar') {
    format = 'TAR_ARCHIVE';
    mime = 'application/x-tar';
    description = 'TAR Archive (POSIX ustar)';
    isArchive = true;
    category = 'ARCHIVE';
  }
  // 12. OLE Compound File (Legacy DOC/XLS/PPT or MSI)
  else if (len >= 8 && buffer[0] === 0xD0 && buffer[1] === 0xCF && buffer[2] === 0x11 && buffer[3] === 0xE0 && buffer[4] === 0xA1 && buffer[5] === 0xB1 && buffer[6] === 0x1A && buffer[7] === 0xE1) {
    format = 'OLE_COMPOUND';
    mime = 'application/x-ole-storage';
    description = 'Microsoft Compound File Binary / Legacy Office Document';
    category = 'DOCUMENT';
  }
  // 13. Images
  else if (len >= 8 && buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47 && buffer[4] === 0x0D && buffer[5] === 0x0A && buffer[6] === 0x1A && buffer[7] === 0x0A) {
    format = 'PNG_IMAGE';
    mime = 'image/png';
    description = 'Portable Network Graphics (PNG)';
    category = 'IMAGE';
  }
  else if (len >= 3 && buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
    format = 'JPEG_IMAGE';
    mime = 'image/jpeg';
    description = 'JPEG Image';
    category = 'IMAGE';
  }
  else if (len >= 6 && (buffer.subarray(0, 6).toString('ascii') === 'GIF87a' || buffer.subarray(0, 6).toString('ascii') === 'GIF89a')) {
    format = 'GIF_IMAGE';
    mime = 'image/gif';
    description = 'Graphics Interchange Format (GIF)';
    category = 'IMAGE';
  }
  else if (len >= 12 && buffer.subarray(0, 4).toString('ascii') === 'RIFF' && buffer.subarray(8, 12).toString('ascii') === 'WEBP') {
    format = 'WEBP_IMAGE';
    mime = 'image/webp';
    description = 'WebP Image';
    category = 'IMAGE';
  }
  // 14. Text / Script inspection
  else {
    const isAsciiOrUtf8 = isTextBuffer(buffer.subarray(0, Math.min(len, 2048)));
    if (isAsciiOrUtf8) {
      const textHead = buffer.subarray(0, Math.min(len, 1024)).toString('utf8');
      if (textHead.startsWith('#!')) {
        format = 'SHELL_SCRIPT';
        mime = 'text/x-shellscript';
        description = 'Executable Script with Shebang';
        isExecutable = true;
        category = 'SCRIPT';
      } else if (textHead.includes('<svg') || textHead.includes('xmlns="http://www.w3.org/2000/svg"')) {
        format = 'SVG_IMAGE';
        mime = 'image/svg+xml';
        description = 'Scalable Vector Graphics (SVG)';
        category = 'IMAGE';
      } else if (textHead.includes('<html') || textHead.includes('<!DOCTYPE html')) {
        format = 'HTML_DOCUMENT';
        mime = 'text/html';
        description = 'HTML Document';
        category = 'DOCUMENT';
      } else if (textHead.includes('<?xml')) {
        format = 'XML_DOCUMENT';
        mime = 'application/xml';
        description = 'XML Document';
        category = 'DOCUMENT';
      } else {
        format = 'PLAIN_TEXT';
        mime = 'text/plain';
        description = 'Plain Text File';
        category = 'TEXT';
      }
    }
  }

  // Mismatch Analysis against filename
  const mismatchDetails = checkExtensionMismatch(filename, format, mime, isExecutable);

  return {
    format,
    mime,
    description,
    isExecutable,
    isArchive,
    category,
    mismatch: mismatchDetails.hasMismatch,
    mismatchDetails
  };
}

/**
 * Check if a buffer contains valid ASCII / UTF-8 text without high null-byte concentration
 */
function isTextBuffer(buf) {
  let nullCount = 0;
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] === 0) nullCount++;
  }
  // If more than 2% null bytes, likely binary
  return (nullCount / buf.length) < 0.02;
}

/**
 * Compare filename extension against detected format
 */
export function checkExtensionMismatch(filename, detectedFormat, detectedMime, isExecutable) {
  if (!filename) {
    return { hasMismatch: false, severity: 'INFO', reason: null };
  }

  const clean = filename.toLowerCase();
  const ext = path.extname(clean);
  const baseWithoutExt = clean.slice(0, clean.length - ext.length);
  const secondExt = path.extname(baseWithoutExt);

  const findings = [];

  // Check 1: Double extension trick (e.g. invoice.pdf.exe or picture.jpg.ps1)
  const deceptiveSecondExts = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.jpg', '.jpeg', '.png', '.mp4', '.txt'];
  const dangerousFinalExts = ['.exe', '.dll', '.scr', '.vbs', '.js', '.ps1', '.bat', '.cmd', '.jar', '.apk', '.hta', '.msi'];

  if (dangerousFinalExts.includes(ext) && deceptiveSecondExts.includes(secondExt)) {
    findings.push({
      type: 'DOUBLE_EXTENSION',
      severity: 'HIGH',
      reason: `Deceptive double extension detected: File masquerades as a document/image (${secondExt}) with an executable extension (${ext}).`
    });
  }

  // Check 2: Executable binary disguised as image, document, or audio/video
  const safeDocumentExts = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.pdf', '.docx', '.xlsx', '.txt', '.mp3', '.mp4'];
  if (safeDocumentExts.includes(ext) && isExecutable) {
    findings.push({
      type: 'EXECUTABLE_MASQUERADE',
      severity: 'CRITICAL',
      reason: `Severe extension mismatch: File name ends with harmless extension '${ext}', but content is a real executable format (${detectedFormat}).`
    });
  }

  // Check 3: Archive disguised as document/image
  if (safeDocumentExts.includes(ext) && detectedFormat === 'ZIP_ARCHIVE') {
    findings.push({
      type: 'ARCHIVE_MASQUERADE',
      severity: 'HIGH',
      reason: `Extension mismatch: File name ends with '${ext}', but file is actually a compressed archive (${detectedFormat}).`
    });
  }

  return {
    hasMismatch: findings.length > 0,
    findings,
    primaryReason: findings[0]?.reason || null,
    highestSeverity: findings.reduce((max, f) => {
      const ranks = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
      return (ranks[f.severity] || 0) > (ranks[max] || 0) ? f.severity : max;
    }, 'INFO')
  };
}

export const detectFileType = identifyFileType;
