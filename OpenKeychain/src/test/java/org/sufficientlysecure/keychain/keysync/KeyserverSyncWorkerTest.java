package org.sufficientlysecure.keychain.keysync;


import org.junit.Test;
import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;
import org.sufficientlysecure.keychain.operations.results.InputPendingResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

/**
 * Tests for KeyserverSyncWorker result-handling logic.
 *
 * Since the work-testing library ({@code androidx.work:work-testing}) is not available,
 * we cannot construct {@code WorkerParameters} to directly instantiate the Worker in tests.
 * Instead, we verify the Worker's result-mapping logic through {@link SyncResultMapper},
 * which is the single delegation point for all outcome decisions in
 * {@code KeyserverSyncWorker.handleUpdateResult()}.
 *
 * Branch coverage:
 * - Success with updated keys
 * - Success with no stale keys (empty result)
 * - Keyserver import failure (partial errors — still SUCCESS)
 * - Orbot required (pending) — RETRY
 * - Worker cancelled (stopped) — FAILURE
 * - Pending takes precedence over stopped
 *
 * Manual verification steps for Worker lifecycle:
 * 1. Enable sync in Settings, wait for periodic trigger → check logcat for "Starting key sync..."
 * 2. Call debugRunSyncNow() → verify immediate execution and SUCCESS log
 * 3. Cancel work via WorkManager → verify onStopped() is called and cancellationSignal is set
 * 4. Enable Tor proxy → verify sync uses staggered update strategy
 */
public class KeyserverSyncWorkerTest {

    // --- Success branch ---

    @Test
    public void testSuccessWithUpdatedKeys() {
        ImportKeyResult result = new ImportKeyResult(
                OperationResult.RESULT_OK | ImportKeyResult.RESULT_OK_UPDATED,
                new OperationResult.OperationLog(),
                0, 5, 0, 0, 0, new long[]{1L, 2L, 3L, 4L, 5L});

        SyncResultMapper.SyncOutcome outcome = SyncResultMapper.mapResult(result, false);
        assertEquals(SyncResultMapper.SyncOutcome.SUCCESS, outcome);
    }

    @Test
    public void testSuccessWithNewKeys() {
        ImportKeyResult result = new ImportKeyResult(
                OperationResult.RESULT_OK | ImportKeyResult.RESULT_OK_NEWKEYS,
                new OperationResult.OperationLog(),
                3, 0, 0, 0, 0, new long[]{1L, 2L, 3L});

        SyncResultMapper.SyncOutcome outcome = SyncResultMapper.mapResult(result, false);
        assertEquals(SyncResultMapper.SyncOutcome.SUCCESS, outcome);
    }

    @Test
    public void testSuccessWithNoStaleKeys() {
        // When no keys need updating, the result is an empty OK result
        ImportKeyResult result = new ImportKeyResult(
                OperationResult.RESULT_OK,
                new OperationResult.OperationLog());

        SyncResultMapper.SyncOutcome outcome = SyncResultMapper.mapResult(result, false);
        assertEquals(SyncResultMapper.SyncOutcome.SUCCESS, outcome);
    }

    // --- Keyserver import failure branch ---

    @Test
    public void testPartialFailureStillSucceeds() {
        // Some keys failed to import from keyserver, but overall sync is still SUCCESS.
        // This covers the "keyserver import failure" scenario for individual keys.
        ImportKeyResult result = new ImportKeyResult(
                OperationResult.RESULT_OK | ImportKeyResult.RESULT_OK_UPDATED | ImportKeyResult.RESULT_WITH_ERRORS,
                new OperationResult.OperationLog(),
                0, 3, 0, 2, 0, new long[]{1L, 2L, 3L});

        SyncResultMapper.SyncOutcome outcome = SyncResultMapper.mapResult(result, false);
        assertEquals("Partial keyserver failures should still be SUCCESS",
                SyncResultMapper.SyncOutcome.SUCCESS, outcome);
    }

    @Test
    public void testPartialFailureLogMessage() {
        ImportKeyResult result = new ImportKeyResult(
                OperationResult.RESULT_OK | ImportKeyResult.RESULT_WITH_ERRORS,
                new OperationResult.OperationLog(),
                0, 2, 0, 3, 0, new long[]{});

        String message = SyncResultMapper.formatLogMessage(result);
        assertEquals("Keyserver sync completed: Updated: 2, Failed: 3", message);
    }

    // --- Orbot required (pending) branch ---

    @Test
    public void testOrbotRequiredReturnsRetry() {
        // ImportOperation returns pending when Orbot is required but not running
        ImportKeyResult result = new ImportKeyResult(
                InputPendingResult.RESULT_PENDING,
                new OperationResult.OperationLog());

        SyncResultMapper.SyncOutcome outcome = SyncResultMapper.mapResult(result, false);
        assertEquals(SyncResultMapper.SyncOutcome.RETRY, outcome);
    }

    @Test
    public void testOrbotRequiredDetection() {
        ImportKeyResult pendingResult = new ImportKeyResult(
                InputPendingResult.RESULT_PENDING,
                new OperationResult.OperationLog());

        SyncResultMapper.SyncOutcome outcome = SyncResultMapper.mapResult(pendingResult, false);
        assertEquals(SyncResultMapper.SyncOutcome.RETRY, outcome);
        // Verify the helper method also detects it
        assert SyncResultMapper.isOrbotRequired(pendingResult);
    }

    // --- Worker cancelled (stopped) branch ---

    @Test
    public void testStoppedWorkerReturnsFailure() {
        ImportKeyResult result = new ImportKeyResult(
                OperationResult.RESULT_OK | ImportKeyResult.RESULT_OK_UPDATED,
                new OperationResult.OperationLog(),
                0, 5, 0, 0, 0, new long[]{});

        SyncResultMapper.SyncOutcome outcome = SyncResultMapper.mapResult(result, true);
        assertEquals(SyncResultMapper.SyncOutcome.FAILURE, outcome);
    }

    @Test
    public void testPendingTakesPrecedenceOverStopped() {
        // If the import result is pending (Orbot needed) AND the worker was stopped,
        // RETRY takes precedence — we want WorkManager to retry when Orbot becomes available.
        ImportKeyResult result = new ImportKeyResult(
                InputPendingResult.RESULT_PENDING,
                new OperationResult.OperationLog());

        SyncResultMapper.SyncOutcome outcome = SyncResultMapper.mapResult(result, true);
        assertEquals("Pending (Orbot) should take precedence over stopped",
                SyncResultMapper.SyncOutcome.RETRY, outcome);
    }

    // --- Cancellation result branch ---

    @Test
    public void testCancelledOperationReturnsFailure() {
        // When KeySyncOperation detects cancellation mid-flight, it returns RESULT_CANCELLED.
        // The worker maps this through SyncResultMapper: if not pending and not stopped → SUCCESS.
        // Note: RESULT_CANCELLED is an operation-level flag, not a WorkManager outcome.
        // If the worker itself was stopped, isStopped=true → FAILURE.
        ImportKeyResult cancelledResult = new ImportKeyResult(
                OperationResult.RESULT_CANCELLED,
                new OperationResult.OperationLog());

        // If worker was stopped → FAILURE
        SyncResultMapper.SyncOutcome outcomeStopped =
                SyncResultMapper.mapResult(cancelledResult, true);
        assertEquals(SyncResultMapper.SyncOutcome.FAILURE, outcomeStopped);

        // If worker was NOT stopped (operation cancelled internally but worker still running) → SUCCESS
        // This is a degenerate case but demonstrates the mapping boundary.
        SyncResultMapper.SyncOutcome outcomeRunning =
                SyncResultMapper.mapResult(cancelledResult, false);
        assertEquals(SyncResultMapper.SyncOutcome.SUCCESS, outcomeRunning);
    }

    // --- Log message formatting ---

    @Test
    public void testLogMessageForSuccessfulSync() {
        ImportKeyResult result = new ImportKeyResult(
                OperationResult.RESULT_OK | ImportKeyResult.RESULT_OK_UPDATED,
                new OperationResult.OperationLog(),
                0, 10, 0, 0, 0, new long[]{});

        String message = SyncResultMapper.formatLogMessage(result);
        assertEquals("Keyserver sync completed: Updated: 10, Failed: 0", message);
    }

    @Test
    public void testLogMessageForEmptyResult() {
        ImportKeyResult result = new ImportKeyResult(
                OperationResult.RESULT_OK,
                new OperationResult.OperationLog());

        String message = SyncResultMapper.formatLogMessage(result);
        assertEquals("Keyserver sync completed: Updated: 0, Failed: 0", message);
    }

    // --- Orbot detection ---

    @Test
    public void testIsOrbotRequiredForPendingResult() {
        ImportKeyResult pendingResult = new ImportKeyResult(
                InputPendingResult.RESULT_PENDING,
                new OperationResult.OperationLog());
        assert SyncResultMapper.isOrbotRequired(pendingResult);
    }

    @Test
    public void testIsOrbotNotRequiredForSuccessResult() {
        ImportKeyResult successResult = new ImportKeyResult(
                OperationResult.RESULT_OK,
                new OperationResult.OperationLog());
        assertFalse(SyncResultMapper.isOrbotRequired(successResult));
    }

    @Test
    public void testIsOrbotNotRequiredForErrorResult() {
        ImportKeyResult errorResult = new ImportKeyResult(
                OperationResult.RESULT_ERROR,
                new OperationResult.OperationLog());
        assertFalse(SyncResultMapper.isOrbotRequired(errorResult));
    }

    // --- Outcome enum completeness ---

    @Test
    public void testSyncOutcomeEnumValues() {
        SyncResultMapper.SyncOutcome[] values = SyncResultMapper.SyncOutcome.values();
        assertEquals("SyncOutcome should have exactly 3 values", 3, values.length);
        assertNotNull(SyncResultMapper.SyncOutcome.RETRY);
        assertNotNull(SyncResultMapper.SyncOutcome.FAILURE);
        assertNotNull(SyncResultMapper.SyncOutcome.SUCCESS);
    }
}
