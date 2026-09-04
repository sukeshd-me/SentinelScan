import { getStorageProvider } from './storage.js';
import { getScansPendingDeletion, updateScanRecord, logSystemEvent, getScanById } from '../db/db.js';

let cleanupTimer = null;

/**
 * Execute immediate secure deletion of a scan's uploaded file and temporary artifacts
 */
export async function deleteScanFiles(scanId, reason = 'RETENTION_EXPIRED') {
  const scan = getScanById(scanId);
  if (!scan) return { success: false, error: 'Scan not found' };

  if (scan.deletion_status === 'VERIFIED') {
    return { success: true, status: 'ALREADY_DELETED' };
  }

  const storage = getStorageProvider();
  let attempts = (scan.deletion_attempts || 0) + 1;

  try {
    // Attempt deletion
    await storage.deleteFile(scanId);

    // Verify deletion
    const isGone = await storage.verifyDeletion(scanId);

    if (isGone) {
      updateScanRecord(scanId, {
        deletion_status: 'VERIFIED',
        file_deleted: 1,
        deleted_at: new Date().toISOString(),
        deletion_attempts: attempts,
        deletion_error: null,
        storage_path: null
      });
      logSystemEvent('FILE_DELETED', scanId, `File permanently deleted and verified (${reason})`);
      return { success: true, deleted: true, status: 'VERIFIED' };
    } else {
      updateScanRecord(scanId, {
        deletion_status: 'FAILED',
        deletion_attempts: attempts,
        deletion_error: 'Deletion verification failed: file or directory still exists'
      });
      logSystemEvent('DELETION_FAILED', scanId, `Deletion verification failed after attempt ${attempts}`);
      return { success: false, error: 'File still exists after deletion attempt' };
    }
  } catch (err) {
    updateScanRecord(scanId, {
      deletion_status: 'FAILED',
      deletion_attempts: attempts,
      deletion_error: err.message
    });
    logSystemEvent('DELETION_ERROR', scanId, `Error deleting file: ${err.message}`);
    return { success: false, error: err.message };
  }
}

/**
 * Cleanup reaper worker: runs periodically to find files scheduled for deletion
 */
export async function runCleanupCycle() {
  try {
    const nowIso = new Date().toISOString();
    const pendingScans = getScansPendingDeletion(nowIso);

    for (const scan of pendingScans) {
      await deleteScanFiles(scan.id, 'AUTOMATIC_REAPER');
    }
  } catch (err) {
    console.error('Error during cleanup reaper cycle:', err.message);
  }
}

/**
 * Start the background cleanup service
 */
export function startCleanupWorker(intervalMs = 60000) {
  if (cleanupTimer) return;
  // Run once on startup to clean any orphaned runs
  runCleanupCycle();
  cleanupTimer = setInterval(runCleanupCycle, intervalMs);
  if (cleanupTimer.unref) cleanupTimer.unref();
  console.log(`[SentinelScan] Automatic cleanup worker active (runs every ${intervalMs / 1000}s, 5m retention).`);
}

/**
 * Stop background cleanup service
 */
export function stopCleanupWorker() {
  if (cleanupTimer) {
    clearInterval(cleanupTimer);
    cleanupTimer = null;
  }
}

export async function executeSecureCleanup(scanId, reason = 'MANUAL') {
  return deleteScanFiles(scanId, reason);
}

export function scheduleScanCleanup(scanId, retentionMinutes = 5) {
  const scheduledTime = new Date(Date.now() + retentionMinutes * 60 * 1000).toISOString();
  updateScanRecord(scanId, {
    deletion_scheduled_at: scheduledTime,
    deletion_status: 'SCHEDULED'
  });
}
