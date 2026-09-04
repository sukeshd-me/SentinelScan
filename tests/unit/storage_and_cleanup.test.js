import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { initDb, createScanRecord, getScanById, updateScanRecord } from '../../server/db/db.js';
import { getStorageProvider } from '../../server/storage/storage.js';
import { initUpload, saveUploadedChunk, assembleUploadedChunks } from '../../server/storage/uploader.js';
import { executeSecureCleanup } from '../../server/storage/cleanup.js';

describe('SentinelScan Storage & Automated Cleanup Suite', () => {

  test('Database Record Lifecycle', () => {
    initDb();
    const scanId = 'test-scan-' + Date.now();
    const record = createScanRecord({
      id: scanId,
      filename: 'sample.bin',
      fileSize: 1024,
      clientToken: 'token_abc123'
    });

    assert.strictEqual(record.id, scanId);
    assert.strictEqual(record.status, 'PENDING');

    updateScanRecord(scanId, {
      status: 'COMPLETED',
      riskScore: 25,
      verdict: 'MODERATE_RISK'
    });

    const updated = getScanById(scanId);
    assert.strictEqual(updated.status, 'COMPLETED');
    assert.strictEqual(updated.risk_score, 25);
    assert.strictEqual(updated.verdict, 'MODERATE_RISK');
  });

  test('Chunked Slicing, Storage, and Assembly Pipeline', async () => {
    const storage = getStorageProvider();
    const testFileSize = 1024 * 100; // 100 KB
    const dummyData = Buffer.alloc(testFileSize, 0x41); // 'A's

    const { scanId, chunkSize, totalChunks } = await initUpload({
      filename: 'chunk_test.bin',
      fileSize: testFileSize,
      clientToken: 'token_test'
    });

    // Write chunks
    for (let i = 0; i < totalChunks; i++) {
      const start = i * chunkSize;
      const end = Math.min(start + chunkSize, testFileSize);
      const chunk = dummyData.subarray(start, end);

      const chunkRes = await saveUploadedChunk({
        scanId,
        chunkIndex: i,
        chunkBuffer: chunk,
        clientToken: 'token_test'
      });

      if (i === totalChunks - 1) {
        assert.strictEqual(chunkRes.isLastChunk, true);
      }
    }

    // Assemble file
    const { filePath, fileSize } = await assembleUploadedChunks(scanId);
    assert.strictEqual(fileSize, testFileSize);
    assert.strictEqual(fs.existsSync(filePath), true);

    const assembledData = await fs.promises.readFile(filePath);
    assert.strictEqual(assembledData.length, testFileSize);
    assert.strictEqual(assembledData[0], 0x41);

    // Verify cleanup removes the payload permanently
    const cleanupResult = await executeSecureCleanup(scanId);
    assert.strictEqual(cleanupResult.deleted, true);
    assert.strictEqual(fs.existsSync(filePath), false);

    const postCleanupScan = getScanById(scanId);
    assert.strictEqual(postCleanupScan.file_deleted, 1);
  });
});
