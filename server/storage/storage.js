import fs from 'node:fs';
import path from 'node:path';
import { S3Client, PutObjectCommand, DeleteObjectCommand, HeadObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';

/**
 * Storage Provider Factory and Implementations
 */

export class LocalDiskStorageProvider {
  constructor(baseDir = process.env.LOCAL_TEMP_DIR || './temp/uploads') {
    this.baseDir = path.resolve(baseDir);
    if (!fs.existsSync(this.baseDir)) {
      fs.mkdirSync(this.baseDir, { recursive: true });
    }
  }

  _sanitizeScanId(scanId) {
    if (!scanId || typeof scanId !== 'string') throw new Error('Invalid scanId');
    // Enforce strict UUID / alphanumeric format to prevent directory traversal
    const clean = scanId.replace(/[^a-zA-Z0-9_-]/g, '');
    if (!clean) throw new Error('Invalid scanId characters');
    return clean;
  }

  getScanDir(scanId) {
    const cleanId = this._sanitizeScanId(scanId);
    const dir = path.join(this.baseDir, cleanId);
    if (!dir.startsWith(this.baseDir)) {
      throw new Error('Directory traversal attempt detected');
    }
    return dir;
  }

  initUpload(scanId) {
    const dir = this.getScanDir(scanId);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    return { dir };
  }

  async saveChunk(scanId, chunkIndex, buffer) {
    const dir = this.getScanDir(scanId);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const chunkPath = path.join(dir, `chunk_${String(chunkIndex).padStart(6, '0')}.part`);
    await fs.promises.writeFile(chunkPath, buffer);
    return chunkPath;
  }

  async assembleChunks(scanId, totalChunks, originalFilename) {
    const dir = this.getScanDir(scanId);
    const safeName = path.basename(originalFilename).replace(/[^a-zA-Z0-9._-]/g, '_');
    const assembledPath = path.join(dir, `file_${safeName}`);

    const writeStream = fs.createWriteStream(assembledPath);

    for (let i = 0; i < totalChunks; i++) {
      const chunkPath = path.join(dir, `chunk_${String(i).padStart(6, '0')}.part`);
      if (!fs.existsSync(chunkPath)) {
        writeStream.destroy();
        throw new Error(`Missing chunk ${i} during assembly`);
      }
      const chunkData = await fs.promises.readFile(chunkPath);
      writeStream.write(chunkData);
      // Clean chunk part immediately to free space
      await fs.promises.unlink(chunkPath).catch(() => {});
    }

    await new Promise((resolve, reject) => {
      writeStream.end((err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    return assembledPath;
  }

  async saveDirectFile(scanId, originalFilename, bufferOrStream) {
    const dir = this.getScanDir(scanId);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const safeName = path.basename(originalFilename).replace(/[^a-zA-Z0-9._-]/g, '_');
    const targetPath = path.join(dir, `file_${safeName}`);

    if (Buffer.isBuffer(bufferOrStream)) {
      await fs.promises.writeFile(targetPath, bufferOrStream);
    } else {
      const writeStream = fs.createWriteStream(targetPath);
      await new Promise((resolve, reject) => {
        bufferOrStream.pipe(writeStream);
        writeStream.on('finish', resolve);
        writeStream.on('error', reject);
      });
    }

    return targetPath;
  }

  getFilePath(scanId) {
    const dir = this.getScanDir(scanId);
    if (!fs.existsSync(dir)) return null;

    const files = fs.readdirSync(dir);
    const mainFile = files.find(f => f.startsWith('file_'));
    if (!mainFile) return null;

    return path.join(dir, mainFile);
  }

  getFileStream(scanId) {
    const filePath = this.getFilePath(scanId);
    if (!filePath || !fs.existsSync(filePath)) return null;
    return fs.createReadStream(filePath);
  }

  async getFileBuffer(scanId, maxBytes = 4096) {
    const filePath = this.getFilePath(scanId);
    if (!filePath || !fs.existsSync(filePath)) return null;

    const stat = await fs.promises.stat(filePath);
    const readLength = Math.min(stat.size, maxBytes);
    const buffer = Buffer.alloc(readLength);

    const fd = await fs.promises.open(filePath, 'r');
    try {
      await fd.read(buffer, 0, readLength, 0);
    } finally {
      await fd.close();
    }

    return buffer;
  }

  async deleteFile(scanId) {
    const dir = this.getScanDir(scanId);
    if (fs.existsSync(dir)) {
      await fs.promises.rm(dir, { recursive: true, force: true });
    }
    return true;
  }

  async verifyDeletion(scanId) {
    const dir = this.getScanDir(scanId);
    return !fs.existsSync(dir);
  }
}

export class B2StorageProvider {
  constructor(config = {}) {
    this.keyId = config.keyId || process.env.B2_APPLICATION_KEY_ID;
    this.key = config.key || process.env.B2_APPLICATION_KEY;
    this.bucket = config.bucket || process.env.B2_BUCKET_NAME;
    this.endpoint = config.endpoint || process.env.B2_ENDPOINT || 'https://s3.us-west-004.backblazeb2.com';

    this.isConfigured = Boolean(this.keyId && this.key && this.bucket);

    if (this.isConfigured) {
      this.client = new S3Client({
        endpoint: this.endpoint,
        region: 'us-west-004',
        credentials: {
          accessKeyId: this.keyId,
          secretAccessKey: this.key
        }
      });
    }

    // Local staging fallback for assembling and temporary scanner access
    this.localCache = new LocalDiskStorageProvider('./temp/b2-cache');
  }

  async saveDirectFile(scanId, originalFilename, buffer) {
    if (!this.isConfigured) {
      return this.localCache.saveDirectFile(scanId, originalFilename, buffer);
    }

    const key = `sentinel-scans/${scanId}/${path.basename(originalFilename)}`;
    await this.client.send(new PutObjectCommand({
      Bucket: this.bucket,
      Key: key,
      Body: buffer
    }));

    // Cache locally for scanner access
    await this.localCache.saveDirectFile(scanId, originalFilename, buffer);
    return key;
  }

  async deleteFile(scanId) {
    await this.localCache.deleteFile(scanId);
    if (!this.isConfigured) return true;

    try {
      const key = `sentinel-scans/${scanId}/`;
      await this.client.send(new DeleteObjectCommand({
        Bucket: this.bucket,
        Key: key
      }));
      return true;
    } catch (err) {
      console.error('B2 deletion error:', err.message);
      return false;
    }
  }

  async verifyDeletion(scanId) {
    const localDeleted = await this.localCache.verifyDeletion(scanId);
    if (!this.isConfigured) return localDeleted;

    try {
      const key = `sentinel-scans/${scanId}/`;
      await this.client.send(new HeadObjectCommand({
        Bucket: this.bucket,
        Key: key
      }));
      return false; // Still exists
    } catch (err) {
      if (err.name === 'NotFound' || err.$metadata?.httpStatusCode === 404) {
        return true;
      }
      return false;
    }
  }

  getFilePath(scanId) {
    return this.localCache.getFilePath(scanId);
  }

  getFileStream(scanId) {
    return this.localCache.getFileStream(scanId);
  }

  async getFileBuffer(scanId, maxBytes) {
    return this.localCache.getFileBuffer(scanId, maxBytes);
  }

  async saveChunk(scanId, chunkIndex, buffer) {
    return this.localCache.saveChunk(scanId, chunkIndex, buffer);
  }

  async assembleChunks(scanId, totalChunks, originalFilename) {
    const localAssembled = await this.localCache.assembleChunks(scanId, totalChunks, originalFilename);
    if (this.isConfigured) {
      const data = await fs.promises.readFile(localAssembled);
      const key = `sentinel-scans/${scanId}/${path.basename(originalFilename)}`;
      await this.client.send(new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: data
      }));
    }
    return localAssembled;
  }
}

let activeProvider = null;

export function getStorageProvider() {
  if (!activeProvider) {
    const providerType = process.env.STORAGE_PROVIDER || 'local';
    if (providerType === 'b2' && process.env.B2_APPLICATION_KEY_ID && process.env.B2_APPLICATION_KEY) {
      activeProvider = new B2StorageProvider();
    } else {
      activeProvider = new LocalDiskStorageProvider();
    }
  }
  return activeProvider;
}
