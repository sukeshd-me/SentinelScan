import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import apiRouter from './routes/api.js';
import { applySecurityHeaders, applyRateLimiter } from './middleware/security.js';
import { initDb, logSystemEvent } from './db/db.js';
import { startCleanupWorker, stopCleanupWorker } from './storage/cleanup.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';

// Initialize SQLite database
initDb();

// Apply Security Middleware
app.use(applySecurityHeaders);
app.use(applyRateLimiter);

// API Routes
app.use('/api', apiRouter);

// Serve static frontend assets
const publicPath = path.resolve(__dirname, '../public');
app.use(express.static(publicPath));

// Fallback to index.html for Single Page Navigation
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) {
    return next();
  }
  res.sendFile(path.join(publicPath, 'index.html'));
});

// Start scheduled cleanup worker (every 60 seconds)
startCleanupWorker(60 * 1000);

const server = app.listen(PORT, HOST, () => {
  console.log(`====================================================`);
  console.log(`  SentinelScan Platform — File Safety & Malware Analysis`);
  console.log(`  Server listening at http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
  console.log(`  Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`  Zero-Execution Guarantee: ACTIVE`);
  console.log(`====================================================`);

  logSystemEvent({
    eventType: 'SERVER_STARTED',
    message: `SentinelScan server successfully started on port ${PORT}`
  });
});

// Graceful termination handling
function shutdown(signal) {
  console.log(`\nReceived ${signal}. Shutting down SentinelScan cleanly...`);
  stopCleanupWorker();
  server.close(() => {
    console.log('HTTP server closed.');
    process.exit(0);
  });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

export default app;
