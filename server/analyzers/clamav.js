import net from 'node:net';
import fs from 'node:fs';

const CLAMAV_HOST = process.env.CLAMAV_HOST || '127.0.0.1';
const CLAMAV_PORT = parseInt(process.env.CLAMAV_PORT || '3310', 10);
const CLAMAV_TIMEOUT = parseInt(process.env.CLAMAV_TIMEOUT_MS || '10000', 10);

/**
 * Real ClamAV TCP Client communicating directly with clamd
 */
export async function checkClamAvHealth() {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let isResolved = false;

    const cleanup = () => {
      if (!socket.destroyed) socket.destroy();
    };

    socket.setTimeout(3000);

    socket.connect(CLAMAV_PORT, CLAMAV_HOST, () => {
      socket.write('zPING\0');
    });

    socket.on('data', (data) => {
      if (isResolved) return;
      isResolved = true;
      const resp = data.toString('utf8').trim();
      cleanup();
      resolve({
        available: resp.includes('PONG'),
        status: resp.includes('PONG') ? 'Operational' : 'Degraded',
        details: resp
      });
    });

    socket.on('timeout', () => {
      if (isResolved) return;
      isResolved = true;
      cleanup();
      resolve({ available: false, status: 'Unavailable', details: 'Connection timed out' });
    });

    socket.on('error', (err) => {
      if (isResolved) return;
      isResolved = true;
      cleanup();
      resolve({ available: false, status: 'Unavailable', details: err.message });
    });
  });
}

/**
 * Fetch ClamAV version and signature database info
 */
export async function getClamAvVersion() {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let isResolved = false;

    socket.setTimeout(3000);

    socket.connect(CLAMAV_PORT, CLAMAV_HOST, () => {
      socket.write('zVERSION\0');
    });

    socket.on('data', (data) => {
      if (isResolved) return;
      isResolved = true;
      const resp = data.toString('utf8').trim();
      socket.destroy();
      resolve(resp);
    });

    socket.on('error', () => {
      if (isResolved) return;
      isResolved = true;
      socket.destroy();
      resolve(null);
    });

    socket.on('timeout', () => {
      if (isResolved) return;
      isResolved = true;
      socket.destroy();
      resolve(null);
    });
  });
}

/**
 * Scan file using ClamAV clamd INSTREAM protocol
 */
export async function scanWithClamAV(filePathOrStream) {
  const startTime = Date.now();

  return new Promise((resolve) => {
    const socket = new net.Socket();
    let responseData = '';
    let isFinished = false;

    const finish = (result) => {
      if (isFinished) return;
      isFinished = true;
      if (!socket.destroyed) socket.destroy();
      resolve({
        ...result,
        durationMs: Date.now() - startTime
      });
    };

    socket.setTimeout(CLAMAV_TIMEOUT);

    socket.connect(CLAMAV_PORT, CLAMAV_HOST, async () => {
      try {
        // ClamAV zINSTREAM command
        socket.write('zINSTREAM\0');

        const stream = typeof filePathOrStream === 'string'
          ? fs.createReadStream(filePathOrStream)
          : filePathOrStream;

        stream.on('data', (chunk) => {
          if (isFinished) return;
          // Chunk prefix: 4-byte big-endian unsigned int containing chunk length
          const lenBuf = Buffer.alloc(4);
          lenBuf.writeUInt32BE(chunk.length, 0);
          socket.write(lenBuf);
          socket.write(chunk);
        });

        stream.on('end', () => {
          if (isFinished) return;
          // Terminating chunk: 4 bytes of 0
          const zeroBuf = Buffer.alloc(4);
          zeroBuf.writeUInt32BE(0, 0);
          socket.write(zeroBuf);
        });

        stream.on('error', (err) => {
          finish({
            state: 'ERROR',
            available: true,
            virusName: null,
            message: `Stream read error: ${err.message}`
          });
        });
      } catch (err) {
        finish({
          state: 'ERROR',
          available: true,
          virusName: null,
          message: err.message
        });
      }
    });

    socket.on('data', (data) => {
      responseData += data.toString('utf8');
      if (responseData.includes('\0') || responseData.includes('\n')) {
        const line = responseData.trim();
        // Responses:
        // stream: OK
        // stream: <VirusName> FOUND
        // stream: <Error> ERROR
        if (line.includes('FOUND')) {
          const match = line.match(/stream:\s+(.+?)\s+FOUND/);
          const virus = match ? match[1] : 'Unknown_Signature';
          finish({
            state: 'INFECTED',
            available: true,
            virusName: virus,
            rawOutput: line,
            message: `Malware signature detected by ClamAV: ${virus}`
          });
        } else if (line.includes('OK')) {
          finish({
            state: 'CLEAN',
            available: true,
            virusName: null,
            rawOutput: line,
            message: 'No malware signatures identified by ClamAV'
          });
        } else {
          finish({
            state: 'ERROR',
            available: true,
            virusName: null,
            rawOutput: line,
            message: `ClamAV reported: ${line}`
          });
        }
      }
    });

    socket.on('timeout', () => {
      finish({
        state: 'TIMEOUT',
        available: false,
        virusName: null,
        message: `ClamAV scan timed out after ${CLAMAV_TIMEOUT}ms`
      });
    });

    socket.on('error', (err) => {
      // Connection refused or clamd not running
      finish({
        state: 'NOT_SCANNED',
        available: false,
        virusName: null,
        message: 'Antivirus engine unavailable (clamd daemon unreachable at ' + CLAMAV_HOST + ':' + CLAMAV_PORT + ')'
      });
    });
  });
}
