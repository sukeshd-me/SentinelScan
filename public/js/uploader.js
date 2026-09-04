/**
 * SentinelScan Chunked & Direct File Uploader
 * Slices large files (up to 1 GB) using File.slice() without browser heap exhaustion.
 */

export class SentinelUploader {
  constructor(options = {}) {
    this.chunkSize = options.chunkSize || 5 * 1024 * 1024; // 5 MB
    this.onProgress = options.onProgress || (() => {});
    this.onStage = options.onStage || (() => {});
    this.onError = options.onError || (() => {});
    this.onComplete = options.onComplete || (() => {});
    this.isAborted = false;

    // Retrieve or generate persistent client token to maintain ownership
    this.clientToken = localStorage.getItem('sentinel_client_token');
    if (!this.clientToken) {
      this.clientToken = 'ct_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
      localStorage.setItem('sentinel_client_token', this.clientToken);
    }
  }

  abort() {
    this.isAborted = true;
  }

  /**
   * Upload file automatically selecting chunked or direct strategy
   */
  async upload(file) {
    this.isAborted = false;

    try {
      // Small files (< 10MB) use direct upload for maximum speed; larger files use chunking
      if (file.size < 10 * 1024 * 1024) {
        return await this.uploadDirect(file);
      } else {
        return await this.uploadChunked(file);
      }
    } catch (err) {
      this.onError(err);
      throw err;
    }
  }

  /**
   * Direct multipart upload for files < 10MB
   */
  async uploadDirect(file) {
    this.onStage({ stage: 'UPLOADING', message: 'Streaming file directly to SentinelScan...' });

    const formData = new FormData();
    formData.append('file', file);

    const xhr = new XMLHttpRequest();
    const startTime = Date.now();

    const uploadPromise = new Promise((resolve, reject) => {
      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
          const percent = Math.round((e.loaded / e.total) * 100);
          const elapsed = (Date.now() - startTime) / 1000;
          const speedBps = elapsed > 0 ? e.loaded / elapsed : 0;
          this.onProgress({
            percent,
            bytesUploaded: e.loaded,
            totalBytes: e.total,
            currentChunk: 1,
            totalChunks: 1,
            speedBps,
            etaSeconds: speedBps > 0 ? (e.total - e.loaded) / speedBps : 0
          });
        }
      });

      xhr.addEventListener('load', () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            resolve(JSON.parse(xhr.responseText));
          } catch (e) {
            reject(new Error('Invalid response from server'));
          }
        } else {
          reject(new Error(`Upload failed with HTTP ${xhr.status}: ${xhr.responseText}`));
        }
      });

      xhr.addEventListener('error', () => reject(new Error('Network connection error')));
      xhr.addEventListener('abort', () => reject(new Error('Upload aborted')));
    });

    xhr.open('POST', '/api/scans/direct');
    xhr.setRequestHeader('x-client-token', this.clientToken);
    xhr.send(formData);

    const result = await uploadPromise;
    return await this.pollScanResults(result.scanId);
  }

  /**
   * Chunked upload for large files up to 1 GB
   */
  async uploadChunked(file) {
    this.onStage({ stage: 'INITIALIZING', message: 'Initializing chunked upload session...' });

    // Step 1: Initialize session
    const initResp = await fetch('/api/scans/init', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        filename: file.name,
        fileSize: file.size,
        clientToken: this.clientToken
      })
    });

    if (!initResp.ok) {
      const err = await initResp.json();
      throw new Error(err.error || 'Failed to initialize chunked upload');
    }

    const { scanId, chunkSize, totalChunks } = await initResp.json();

    // Step 2: Upload chunks sequentially
    let bytesUploaded = 0;
    const startTime = Date.now();

    for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
      if (this.isAborted) throw new Error('Upload cancelled by user');

      const startByte = chunkIndex * chunkSize;
      const endByte = Math.min(startByte + chunkSize, file.size);
      const chunkBlob = file.slice(startByte, endByte);

      this.onStage({
        stage: 'UPLOADING',
        message: `Uploading chunk ${chunkIndex + 1} of ${totalChunks}...`
      });

      let retries = 3;
      let success = false;

      while (retries > 0 && !success) {
        try {
          const chunkResp = await fetch(`/api/scans/${scanId}/chunk`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/octet-stream',
              'x-chunk-index': chunkIndex.toString(),
              'x-client-token': this.clientToken
            },
            body: chunkBlob
          });

          if (!chunkResp.ok) {
            throw new Error(`Server returned HTTP ${chunkResp.status}`);
          }

          success = true;
          bytesUploaded += (endByte - startByte);

          const percent = Math.round((bytesUploaded / file.size) * 100);
          const elapsed = (Date.now() - startTime) / 1000;
          const speedBps = elapsed > 0 ? bytesUploaded / elapsed : 0;

          this.onProgress({
            percent,
            bytesUploaded,
            totalBytes: file.size,
            currentChunk: chunkIndex + 1,
            totalChunks,
            speedBps,
            etaSeconds: speedBps > 0 ? (file.size - bytesUploaded) / speedBps : 0
          });
        } catch (err) {
          retries--;
          if (retries === 0) throw new Error(`Chunk ${chunkIndex} failed after 3 attempts: ${err.message}`);
          await new Promise(r => setTimeout(r, 1000));
        }
      }
    }

    this.onStage({ stage: 'ASSEMBLING', message: 'Assembling chunks and initiating analysis pipeline...' });
    return await this.pollScanResults(scanId);
  }

  /**
   * Poll scan status until completed or failed
   */
  async pollScanResults(scanId) {
    const maxPollTime = 120000; // 2 minutes max
    const pollInterval = 1000;
    const startTime = Date.now();

    while (Date.now() - startTime < maxPollTime) {
      if (this.isAborted) throw new Error('Scan monitoring aborted');

      const resp = await fetch(`/api/scans/${scanId}`);
      if (!resp.ok) throw new Error(`Failed to fetch scan status: HTTP ${resp.status}`);

      const data = await resp.json();
      const status = data.scan.status;

      if (status === 'COMPLETED') {
        this.onStage({ stage: 'COMPLETED', message: 'Analysis complete.' });
        this.onComplete(data);
        return data;
      }

      if (status === 'FAILED') {
        throw new Error('Analysis pipeline encountered a terminal error.');
      }

      this.onStage({
        stage: status,
        message: status === 'ANALYZING' ? 'Running static parsing & ClamAV checks...' : 'Processing file...'
      });

      await new Promise(r => setTimeout(r, pollInterval));
    }

    throw new Error('Analysis timed out waiting for results.');
  }
}
