/*
 * Copyright (C) 2017 Schürmann & Breitmoser GbR
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.sufficientlysecure.keychain.keysync;


import androidx.work.ListenableWorker.Result;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.keysync.KeyserverSyncResultMapper.SyncDecision;
import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;
import org.sufficientlysecure.keychain.operations.results.InputPendingResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;

/**
 * Unit tests for {@link KeyserverSyncResultMapper}, the pure decision/mapping logic extracted from
 * {@code KeyserverSyncWorker}. These exercise the historical precedence rules without instantiating
 * a {@link androidx.work.Worker}:
 *
 * <ul>
 *     <li>a pending result (Orbot required) always maps to {@link Result#retry()} – even when the
 *         worker was stopped;</li>
 *     <li>a non-pending result on a stopped worker maps to {@link Result#failure()};</li>
 *     <li>any other completed result – including a completed-with-per-key-errors import – maps to
 *         {@link Result#success()} so the periodic best-effort refresh is not pointlessly retried.</li>
 * </ul>
 */
@RunWith(KeychainTestRunner.class)
public class KeyserverSyncResultMapperTest {

    private static ImportKeyResult pendingResult() {
        // RESULT_PENDING is what InputPendingResult assigns when Orbot input is required
        return new ImportKeyResult(InputPendingResult.RESULT_PENDING, new OperationLog());
    }

    private static ImportKeyResult completedResult() {
        return new ImportKeyResult(ImportKeyResult.RESULT_OK_UPDATED, new OperationLog());
    }

    private static ImportKeyResult completedWithPerKeyErrorsResult() {
        // an overall-OK import that nevertheless had individual bad keys / lookup failures
        return new ImportKeyResult(
                ImportKeyResult.RESULT_OK_UPDATED | ImportKeyResult.RESULT_WITH_ERRORS,
                new OperationLog());
    }

    private static ImportKeyResult failedResult() {
        return new ImportKeyResult(
                OperationResult.RESULT_ERROR | ImportKeyResult.RESULT_WITH_ERRORS,
                new OperationLog());
    }

    // ---- classify() -------------------------------------------------------------------------

    @Test
    public void classify_pendingResult_notStopped_isRetry() {
        Assert.assertTrue("precondition: result must report itself pending", pendingResult().isPending());
        Assert.assertEquals(SyncDecision.RETRY, KeyserverSyncResultMapper.classify(pendingResult(), false));
    }

    @Test
    public void classify_pendingResult_takesPrecedenceOverStopped() {
        // a pending (Orbot) result must still ask for RETRY even if the worker was stopped meanwhile
        Assert.assertEquals(SyncDecision.RETRY, KeyserverSyncResultMapper.classify(pendingResult(), true));
    }

    @Test
    public void classify_stoppedNonPending_isCancelled() {
        Assert.assertEquals(SyncDecision.CANCELLED, KeyserverSyncResultMapper.classify(completedResult(), true));
    }

    @Test
    public void classify_completedNoErrors_isSuccess() {
        Assert.assertEquals(SyncDecision.SUCCESS, KeyserverSyncResultMapper.classify(completedResult(), false));
    }

    @Test
    public void classify_completedWithPerKeyErrors_isStillSuccess() {
        // per-key errors are logged but must NOT fail the WorkManager job
        ImportKeyResult result = completedWithPerKeyErrorsResult();
        Assert.assertFalse("precondition: an import-with-errors is not itself pending", result.isPending());
        Assert.assertEquals(SyncDecision.SUCCESS, KeyserverSyncResultMapper.classify(result, false));
    }

    @Test
    public void classify_overallErrorButNotStopped_isSuccess() {
        // even a hard keyserver failure does not flip the periodic job to retry/failure on its own;
        // only "pending" (RETRY) and "stopped" (CANCELLED) divert from SUCCESS
        Assert.assertEquals(SyncDecision.SUCCESS, KeyserverSyncResultMapper.classify(failedResult(), false));
    }

    // ---- toWorkerResult() -------------------------------------------------------------------

    @Test
    public void toWorkerResult_retry_mapsToRetry() {
        Assert.assertEquals(Result.retry(), KeyserverSyncResultMapper.toWorkerResult(SyncDecision.RETRY));
    }

    @Test
    public void toWorkerResult_cancelled_mapsToFailure() {
        // historical behaviour: a cancelled sync is reported as failure(), not success()
        Assert.assertEquals(Result.failure(), KeyserverSyncResultMapper.toWorkerResult(SyncDecision.CANCELLED));
    }

    @Test
    public void toWorkerResult_success_mapsToSuccess() {
        Assert.assertEquals(Result.success(), KeyserverSyncResultMapper.toWorkerResult(SyncDecision.SUCCESS));
    }
}
