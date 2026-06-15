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
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.keysync.KeyserverSyncResultMapper.SyncDecision;
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
        ImportKeyResult result = runKeySync(getApplicationContext(), cancellationSignal);

        SyncDecision decision = KeyserverSyncResultMapper.classify(result, isStopped());
        handleSideEffects(decision, result);
        return KeyserverSyncResultMapper.toWorkerResult(decision);
    }

    /**
     * Execution context of the periodic keyserver sync: wires up the {@link KeySyncOperation}
     * (reusing {@link org.sufficientlysecure.keychain.operations.ImportOperation} and the
     * {@code KeyMetadata} bookkeeping) and runs it for the "refresh outdated keys" use case.
     */
    @NonNull
    static ImportKeyResult runKeySync(@NonNull Context appContext, @NonNull AtomicBoolean cancellationSignal) {
        KeyWritableRepository keyWritableRepository = KeyWritableRepository.create(appContext);

        Timber.d("Starting key sync…");
        KeySyncOperation keySync =
                new KeySyncOperation(appContext, keyWritableRepository, null, cancellationSignal);
        return keySync.execute(KeySyncParcel.createRefreshOutdated(),
                CryptoInputParcel.createCryptoInputParcel());
    }

    /**
     * Side-effect / logging boundary for the sync outcome. The mapping to the actual
     * {@link Result} is handled by {@link KeyserverSyncResultMapper#toWorkerResult(SyncDecision)};
     * this method only performs the Android-side effects (Orbot start / notification, logging)
     * associated with each decision.
     */
    private void handleSideEffects(@NonNull SyncDecision decision, @NonNull ImportKeyResult result) {
        switch (decision) {
            case RETRY:
                Timber.d("Orbot required for sync but not running, attempting to start");
                // result is pending due to Orbot not being started
                // try to start it silently, if disabled show notifications
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
                break;
            case CANCELLED:
                Timber.d("Keyserver sync cancelled");
                break;
            case SUCCESS:
            default:
                Timber.d("Keyserver sync completed: Updated: %d, Failed: %d", result.mUpdatedKeys,
                        result.mBadKeys);
                break;
        }
    }

    @Override
    public void onStopped() {
        super.onStopped();
        cancellationSignal.set(true);
    }
}
