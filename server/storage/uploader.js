import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { getStorageProvider } from './storage.js';
import { createScanRecord, updateScanRecord, getScanById, logSystemEvent } from '../db/db.js';

export const MAX_FILE_SIZE = 1024 * 1024 * 1024; // 1 GB in bytes
export const DEFAULT_CHUNK_SIZE = 5 * 1024 * 1024; // 5 MB per chunk
export const MAX_CHUNK_SIZE = 10 * 1024 * 1024;  // 10 MB max per chunk
export const RETENTION_MINUTES = parseInt(process.env.SCAN_FILE_RETENTION_MINUTES || '5', 10);

// Active in-flight upload sessions
const activeUploadSessions = new Map();

/**
 * Sanitize filename to prevent directory traversal and null byte injections
 */
export function sanitizeFilename(rawName) {
  if (!rawName || typeof rawName !== 'string') return 'unnamed_upload.bin';
  // Strip paths, null bytes, control characters
  const basename = path.basename(rawName.replace(/\\/g, '/')).replace(/\0/g, '');
  const clean = basename.replace(/[<>:"/\\|?*\x00-\x1F]/g, '_').trim();
  return clean.slice(0, 255) || 'unnamed_upload.bin';
}

/**
 * Initialize Chunked Upload
 */
export async function initUpload({ filename, fileSize, clientToken, customChunkSize }) {
  if (!fileSize || typeof fileSize !== 'number' || fileSize <= 0) {
    throw new Error('Invalid file size provided');
  }

  if (fileSize > MAX_FILE_SIZE) {
    throw new Error(`File exceeds maximum permitted size of 1 GB (${MAX_FILE_SIZE} bytes)`);
  }

  const safeName = sanitizeFilename(filename);
  const scanId = crypto.randomUUID();
  const token = clientToken || crypto.randomBytes(24).toString('hex');
  const chunkSize = customChunkSize || DEFAULT_CHUNK_SIZE;
  const totalChunks = Math.ceil(fileSize / chunkSize);

  const now = new Date();
  const deletionScheduled = new Date(now.getTime() + RETENTION_MINUTES * 60 * 1000).toISOString();

  const storage = getStorageProvider();
  storage.initUpload(scanId);

  createScanRecord({
    id: scanId,
    client_token: token,
    filename: safeName,
    file_size: fileSize,
    status: 'UPLOADING',
    storage_provider: process.env.STORAGE_PROVIDER || 'local',
    created_at: now.toISOString(),
    deletion_scheduled_at: deletionScheduled
  });

  const session = {
    scanId,
    clientToken: token,
    filename: safeName,
    fileSize,
    chunkSize,
    totalChunks,
    receivedChunks: new Set(),
    createdAt: Date.now()
  };

  activeUploadSessions.set(scanId, session);

  logSystemEvent('UPLOAD_INIT', scanId, `Upload initialized for ${safeName} (${fileSize} bytes, ${totalChunks} chunks)`);

  return {
    scanId,
    uploadId: scanId, // compatibility alias
    chunkSize,
    totalChunks,
    clientToken: token,
    maxFileSize: MAX_FILE_SIZE
  };
}

export const initUploadSession = initUpload;

/**
 * Save an uploaded chunk
 */
export async function saveUploadedChunk({ scanId, chunkIndex, chunkBuffer, clientToken, totalChunks: totalChunksParam }) {
  let session = activeUploadSessions.get(scanId);
  const scan = getScanById(scanId);

  if (!session && !scan) {
    throw new Error('Upload session expired or invalid scan ID');
  }

  if (session && clientToken && session.clientToken !== clientToken) {
    throw new Error('Unauthorized access to upload session');
  }

  const expectedTotalChunks = session ? session.totalChunks : (totalChunksParam || 1);

  if (chunkIndex < 0 || chunkIndex >= expectedTotalChunks) {
    throw new Error(`Chunk index ${chunkIndex} out of bounds [0..${expectedTotalChunks - 1}]`);
  }

  if (chunkBuffer.length > MAX_CHUNK_SIZE + 1024) {
    throw new Error('Chunk exceeds maximum chunk size limit');
  }

  const storage = getStorageProvider();
  await storage.saveChunk(scanId, chunkIndex, chunkBuffer);

  if (!session) {
    // Reconstruct session if server restarted during upload
    session = {
      scanId,
      clientToken: scan.client_token,
      filename: scan.filename,
      fileSize: scan.file_size,
      chunkSize: DEFAULT_CHUNK_SIZE,
      totalChunks: expectedTotalChunks,
      receivedChunks: new Set(),
      createdAt: Date.now()
    };
    activeUploadSessions.set(scanId, session);
  }

  session.receivedChunks.add(chunkIndex);
  const isLastChunk = session.receivedChunks.size === session.totalChunks;

  return {
    success: true,
    scanId,
    chunkIndex,
    isLastChunk,
    receivedCount: session.receivedChunks.size,
    totalChunks: session.totalChunks
  };
}

export const processChunk = async (opts) => {
  return saveUploadedChunk({
    scanId: opts.scanId,
    chunkIndex: opts.chunkIndex,
    chunkBuffer: opts.chunkBuffer,
    clientToken: opts.clientToken,
    totalChunks: opts.totalChunks
  });
};

/**
 * Assemble uploaded chunks into a single file
 */
export async function assembleUploadedChunks(scanId, clientToken) {
  let session = activeUploadSessions.get(scanId);
  const scan = getScanById(scanId);

  if (!scan) {
    throw new Error('Scan record not found');
  }

  if (clientToken && scan.client_token !== clientToken) {
    throw new Error('Unauthorized access to scan');
  }

  const filename = session ? session.filename : scan.filename;
  const totalChunks = session ? session.totalChunks : Math.ceil(scan.file_size / DEFAULT_CHUNK_SIZE);

  if (session && session.receivedChunks.size !== totalChunks) {
    throw new Error(`Cannot assemble file: received ${session.receivedChunks.size} of ${totalChunks} chunks`);
  }

  const storage = getStorageProvider();
  const assembledPath = await storage.assembleChunks(scanId, totalChunks, filename);

  const stats = await fs.promises.stat(assembledPath);
  activeUploadSessions.delete(scanId);

  updateScanRecord(scanId, {
    status: 'PROCESSING',
    storage_path: assembledPath
  });

  logSystemEvent('UPLOAD_COMPLETE', scanId, `File assembled: ${filename} (${stats.size} bytes)`);

  return {
    scanId,
    filename,
    filePath: assembledPath,
    assembledPath,
    fileSize: stats.size
  };
}

export const completeChunkedUpload = async (opts) => {
  return assembleUploadedChunks(opts.scanId, opts.clientToken);
};

/**
 * Handle direct upload (multipart or buffer)
 */
export async function saveDirectUpload({ tempFilePath, originalFilename, fileSize, clientToken }) {
  const safeName = sanitizeFilename(originalFilename);
  const scanId = crypto.randomUUID();
  const token = clientToken || crypto.randomBytes(24).toString('hex');

  const now = new Date();
  const deletionScheduled = new Date(now.getTime() + RETENTION_MINUTES * 60 * 1000).toISOString();

  const storage = getStorageProvider();
  const fileStream = fs.createReadStream(tempFilePath);
  const savedPath = await storage.saveDirectFile(scanId, safeName, fileStream);

  // Remove temporary multipart upload
  await fs.promises.unlink(tempFilePath).catch(() => {});

  createScanRecord({
    id: scanId,
    client_token: token,
    filename: safeName,
    file_size: fileSize,
    status: 'PROCESSING',
    storage_path: savedPath,
    storage_provider: process.env.STORAGE_PROVIDER || 'local',
    created_at: now.toISOString(),
    deletion_scheduled_at: deletionScheduled
  });

  logSystemEvent('DIRECT_UPLOAD', scanId, `Direct upload received: ${safeName} (${fileSize} bytes)`);

  return {
    scanId,
    clientToken: token,
    filename: safeName,
    filePath: savedPath,
    fileSize
  };
}

export async function handleDirectUpload({ filename, buffer, clientToken }) {
  if (!buffer || buffer.length === 0) {
    throw new Error('No file data received');
  }

  if (buffer.length > MAX_FILE_SIZE) {
    throw new Error('File exceeds maximum permitted size of 1 GB');
  }

  const safeName = sanitizeFilename(filename);
  const scanId = crypto.randomUUID();
  const token = clientToken || crypto.randomBytes(24).toString('hex');

  const now = new Date();
  const deletionScheduled = new Date(now.getTime() + RETENTION_MINUTES * 60 * 1000).toISOString();

  const storage = getStorageProvider();
  const savedPath = await storage.saveDirectFile(scanId, safeName, buffer);

  createScanRecord({
    id: scanId,
    client_token: token,
    filename: safeName,
    file_size: buffer.length,
    status: 'PROCESSING',
    storage_path: savedPath,
    storage_provider: process.env.STORAGE_PROVIDER || 'local',
    created_at: now.toISOString(),
    deletion_scheduled_at: deletionScheduled
  });

  logSystemEvent('DIRECT_UPLOAD', scanId, `Direct upload received: ${safeName} (${buffer.length} bytes)`);

  return {
    scanId,
    clientToken: token,
    filename: safeName,
    filePath: savedPath,
    fileSize: buffer.length
  };
}
