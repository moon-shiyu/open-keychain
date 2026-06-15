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


import java.util.concurrent.atomic.AtomicBoolean;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.network.orbot.OrbotHelper;
import org.sufficientlysecure.keychain.operations.KeySyncOperation;
import org.sufficientlysecure.keychain.operations.KeySyncParcel;
import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.ui.OrbotRequiredDialogActivity;
import timber.log.Timber;


public class KeyserverSyncWorker extends Worker {
    private final AtomicBoolean cancellationSignal = new AtomicBoolean(false);

    public KeyserverSyncWorker(@NonNull Context context, @NonNull WorkerParameters workerParams) {
        super(context, workerParams);
    }

    @NonNull
    @Override
    public Result doWork() {
        Timber.d("Starting key sync...");
        ImportKeyResult result = runKeySync();
        return handleUpdateResult(result);
    }

    /**
     * Execute the key sync operation against stale keys.
     * Periodic background sync always uses {@code createRefreshOutdated()} (7-day threshold).
     * The "refresh all" path (manual update from UI) goes through KeychainServiceTask directly.
     *
     * Separated from {@code doWork()} to make the execution boundary explicit and testable.
     */
    @VisibleForTesting
    ImportKeyResult runKeySync() {
        KeyWritableRepository keyWritableRepository =
                KeyWritableRepository.create(getApplicationContext());
        KeySyncOperation keySync =
                new KeySyncOperation(getApplicationContext(), keyWritableRepository, null,
                        cancellationSignal);
        return keySync.execute(KeySyncParcel.createRefreshOutdated(),
                CryptoInputParcel.createCryptoInputParcel());
    }

    /**
     * Map the import result to a WorkManager Result and handle Orbot if needed.
     *
     * Decision tree:
     * - RETRY (Orbot required): attempt silent start or show notification
     * - FAILURE (worker stopped): return failure, no further action
     * - SUCCESS: log completion and return success
     *
     * Since we're returning START_REDELIVER_INTENT in onStartCommand, we need to remember to call
     * stopSelf(int) to prevent the Intent from being redelivered if our work is already done.
     *
     * @param result result of keyserver sync
     */
    private Result handleUpdateResult(ImportKeyResult result) {
        SyncResultMapper.SyncOutcome outcome = SyncResultMapper.mapResult(result, isStopped());

        switch (outcome) {
            case RETRY:
                Timber.d("Orbot required for sync but not running, attempting to start");
                handleOrbotRequired();
                return Result.retry();

            case FAILURE:
                Timber.d("Keyserver sync cancelled");
                return Result.failure();

            case SUCCESS:
            default:
                Timber.d(SyncResultMapper.formatLogMessage(result));
                return Result.success();
        }
    }

    /**
     * Handle the case where Orbot is required but not running.
     * Attempts silent start; if disabled, shows a notification.
     */
    private void handleOrbotRequired() {
        new OrbotHelper.SilentStartManager() {
            @Override
            protected void onOrbotStarted() {
            }

            @Override
            protected void onSilentStartDisabled() {
                OrbotRequiredDialogActivity.showOrbotRequiredNotification(
                        getApplicationContext());
            }
        }.startOrbotAndListen(getApplicationContext(), false);
    }

    @Override
    public void onStopped() {
        super.onStopped();
        cancellationSignal.set(true);
    }
}
