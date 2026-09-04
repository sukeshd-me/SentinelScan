import crypto from 'node:crypto';
import fs from 'node:fs';

/**
 * Calculate SHA-256 (primary), SHA-1 (legacy), and MD5 (legacy) in a single stream pass
 */
export async function calculateHashes(filePathOrStream) {
  const sha256 = crypto.createHash('sha256');
  const sha1 = crypto.createHash('sha1');
  const md5 = crypto.createHash('md5');

  const stream = typeof filePathOrStream === 'string'
    ? fs.createReadStream(filePathOrStream)
    : filePathOrStream;

  return new Promise((resolve, reject) => {
    stream.on('data', (chunk) => {
      sha256.update(chunk);
      sha1.update(chunk);
      md5.update(chunk);
    });

    stream.on('end', () => {
      resolve({
        sha256: sha256.digest('hex'),
        sha1: sha1.digest('hex'),
        md5: md5.digest('hex'),
        legacyHashNotice: 'SHA-1 and MD5 are cryptographic legacy hashes provided for historical indexing only and must not be used as collision-resistant identifiers.'
      });
    });

    stream.on('error', (err) => {
      reject(err);
    });
  });
}

/**
 * Synchronous hash calculation for buffers (e.g. in-memory fixtures/chunks)
 */
export function calculateBufferHashes(buffer) {
  return {
    sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
    sha1: crypto.createHash('sha1').update(buffer).digest('hex'),
    md5: crypto.createHash('md5').update(buffer).digest('hex'),
    legacyHashNotice: 'SHA-1 and MD5 are cryptographic legacy hashes provided for historical indexing only and must not be used as collision-resistant identifiers.'
  };
}
