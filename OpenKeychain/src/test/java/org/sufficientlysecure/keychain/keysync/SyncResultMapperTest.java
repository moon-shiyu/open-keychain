package org.sufficientlysecure.keychain.keysync;


import org.junit.Test;
import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;
import org.sufficientlysecure.keychain.operations.results.InputPendingResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for SyncResultMapper.
 *
 * Tests cover all branches:
 * - Success (with and without bad keys)
 * - Pending (Orbot required)
 * - Stopped/cancelled
 * - Precedence (pending over stopped)
 * - Empty result (no stale keys)
 *
 * NOTE: These tests require Android SDK for the build system.
 * If ANDROID_HOME is not set, tests cannot run locally.
 */
public class SyncResultMapperTest {

    @Test
    public void testMapResultSuccess() {
        ImportKeyResult result = new ImportKeyResult(
                OperationResult.RESULT_OK,
                new OperationResult.OperationLog(),
                0, 5, 0, 0, 0, new long[]{});

        SyncResultMapper.SyncOutcome outcome = SyncResultMapper.mapResult(result, false);
        assertEquals(SyncResultMapper.SyncOutcome.SUCCESS, outcome);
    }

    @Test
    public void testMapResultSuccessWithBadKeys() {
        // Even if some keys failed, it's still SUCCESS (not retry)
        ImportKeyResult result = new ImportKeyResult(
                OperationResult.RESULT_OK | ImportKeyResult.RESULT_WITH_ERRORS,
                new OperationResult.OperationLog(),
                0, 3, 0, 2, 0, new long[]{});

        SyncResultMapper.SyncOutcome outcome = SyncResultMapper.mapResult(result, false);
        assertEquals(SyncResultMapper.SyncOutcome.SUCCESS, outcome);
    }

    @Test
    public void testMapResultPendingOrbot() {
        // Simulate Orbot pending result
        ImportKeyResult result = new ImportKeyResult(
                InputPendingResult.RESULT_PENDING,
                new OperationResult.OperationLog());

        SyncResultMapper.SyncOutcome outcome = SyncResultMapper.mapResult(result, false);
        assertEquals(SyncResultMapper.SyncOutcome.RETRY, outcome);
    }

    @Test
    public void testMapResultStopped() {
        ImportKeyResult result = new ImportKeyResult(
                OperationResult.RESULT_OK,
                new OperationResult.OperationLog(),
                0, 5, 0, 0, 0, new long[]{});

        SyncResultMapper.SyncOutcome outcome = SyncResultMapper.mapResult(result, true);
        assertEquals(SyncResultMapper.SyncOutcome.FAILURE, outcome);
    }

    @Test
    public void testMapResultPendingTakesPrecedenceOverStopped() {
        // If both pending and stopped, RETRY takes precedence
        ImportKeyResult result = new ImportKeyResult(
                InputPendingResult.RESULT_PENDING,
                new OperationResult.OperationLog());

        SyncResultMapper.SyncOutcome outcome = SyncResultMapper.mapResult(result, true);
        assertEquals(SyncResultMapper.SyncOutcome.RETRY, outcome);
    }

    @Test
    public void testMapResultNoStaleKeys() {
        // Empty result (no keys to update) is still SUCCESS
        ImportKeyResult result = new ImportKeyResult(
                OperationResult.RESULT_OK,
                new OperationResult.OperationLog());

        SyncResultMapper.SyncOutcome outcome = SyncResultMapper.mapResult(result, false);
        assertEquals(SyncResultMapper.SyncOutcome.SUCCESS, outcome);
    }

    @Test
    public void testFormatLogMessage() {
        ImportKeyResult result = new ImportKeyResult(
                OperationResult.RESULT_OK,
                new OperationResult.OperationLog(),
                2, 5, 1, 3, 0, new long[]{});

        String message = SyncResultMapper.formatLogMessage(result);
        assertEquals("Keyserver sync completed: Updated: 5, Failed: 3", message);
    }

    @Test
    public void testFormatLogMessageZeroCounts() {
        ImportKeyResult result = new ImportKeyResult(
                OperationResult.RESULT_OK,
                new OperationResult.OperationLog());

        String message = SyncResultMapper.formatLogMessage(result);
        assertEquals("Keyserver sync completed: Updated: 0, Failed: 0", message);
    }

    @Test
    public void testIsOrbotRequiredPending() {
        ImportKeyResult result = new ImportKeyResult(
                InputPendingResult.RESULT_PENDING,
                new OperationResult.OperationLog());

        assertTrue(SyncResultMapper.isOrbotRequired(result));
    }

    @Test
    public void testIsOrbotRequiredNotPending() {
        ImportKeyResult result = new ImportKeyResult(
                OperationResult.RESULT_OK,
                new OperationResult.OperationLog());

        assertFalse(SyncResultMapper.isOrbotRequired(result));
    }
}
