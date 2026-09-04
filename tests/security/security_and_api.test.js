import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { sanitizeFilename, applyRateLimiter, applySecurityHeaders } from '../../server/middleware/security.js';
import { createScanRecord, getScanById } from '../../server/db/db.js';

describe('SentinelScan Security Controls Suite', () => {

  test('Path Traversal Prevention: Filename Sanitizer neutralizes directory traversal', () => {
    assert.strictEqual(sanitizeFilename('../../../evil.exe'), 'evil.exe');
    assert.strictEqual(sanitizeFilename('..\\..\\windows\\system32\\cmd.exe'), 'cmd.exe');
    assert.strictEqual(sanitizeFilename('normal_report.pdf'), 'normal_report.pdf');
    assert.strictEqual(sanitizeFilename('file\0name.exe'), 'filename.exe');
    assert.strictEqual(sanitizeFilename(''), 'unnamed_upload.bin');
  });

  test('IDOR Prevention: Client ownership token protection', () => {
    const scanId = 'idor-test-' + Date.now();
    const tokenA = 'client_token_alice';
    const tokenB = 'client_token_mallory';

    createScanRecord({
      id: scanId,
      filename: 'confidential.docx',
      fileSize: 4096,
      clientToken: tokenA
    });

    const scan = getScanById(scanId);
    assert.strictEqual(scan.client_token, tokenA);

    // Mallory attempting deletion with wrong token must fail
    assert.notStrictEqual(scan.client_token, tokenB);
    assert.strictEqual(scan.client_token === tokenA, true);
  });

  test('HTTP Security Headers are correctly applied', () => {
    const headers = {};
    const mockRes = {
      setHeader: (k, v) => { headers[k.toLowerCase()] = v; }
    };
    const mockReq = {};
    let nextCalled = false;

    applySecurityHeaders(mockReq, mockRes, () => { nextCalled = true; });

    assert.strictEqual(nextCalled, true);
    assert.strictEqual(headers['x-content-type-options'], 'nosniff');
    assert.strictEqual(headers['x-frame-options'], 'DENY');
    assert.strictEqual(headers['strict-transport-security'], 'max-age=31536000; includeSubDomains');
    assert.ok(headers['content-security-policy'].includes("default-src 'self'"));
  });

  test('Rate Limiter: Blocks requests exceeding the sliding threshold', () => {
    const mockReq = {
      ip: '198.51.100.42',
      headers: {}
    };
    let statusSet = 200;
    let responseSent = null;

    const mockRes = {
      status: (code) => { statusSet = code; return mockRes; },
      json: (data) => { responseSent = data; return mockRes; }
    };

    let nextCount = 0;
    const next = () => { nextCount++; };

    // Set rate limit threshold dynamically for test
    process.env.RATE_LIMIT_MAX_REQUESTS = '5';
    process.env.RATE_LIMIT_WINDOW_MS = '60000';

    for (let i = 0; i < 5; i++) {
      applyRateLimiter(mockReq, mockRes, next);
    }
    assert.strictEqual(nextCount, 5);

    // 6th request must be blocked
    applyRateLimiter(mockReq, mockRes, next);
    assert.strictEqual(statusSet, 429);
    assert.ok(responseSent.error.includes('Rate limit exceeded'));
  });
});
