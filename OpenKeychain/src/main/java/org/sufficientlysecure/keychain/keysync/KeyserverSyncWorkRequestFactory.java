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


import java.util.concurrent.TimeUnit;

import android.os.Build.VERSION_CODES;

import androidx.annotation.NonNull;
import androidx.work.Constraints;
import androidx.work.NetworkType;
import androidx.work.OneTimeWorkRequest;
import androidx.work.PeriodicWorkRequest;
import org.sufficientlysecure.keychain.util.Preferences;


/**
 * Single source of truth for the keyserver sync scheduling configuration: the periodic interval,
 * the unique work name, the legacy tag and the WorkManager constraints / requests.
 *
 * <p>This only builds the {@link androidx.work.WorkRequest}s and constraints; the actual
 * enqueue/cancel policy lives in {@link KeyserverSyncManager}. Keeping the configuration in one
 * place makes the sync policy easy to reason about without changing the unique work name, the
 * interval or the enqueue strategy.
 */
final class KeyserverSyncWorkRequestFactory {

    static final long SYNC_INTERVAL = 3;
    static final TimeUnit SYNC_INTERVAL_UNIT = TimeUnit.DAYS;

    static final String LEGACY_PERIODIC_WORK_TAG = "keyserverSync";
    static final String WORK_UNIQUE_NAME = "periodicKeyserverSync";

    private KeyserverSyncWorkRequestFactory() {
    }

    /**
     * @param sdkInt the running {@code Build.VERSION.SDK_INT}, injected so the constraint logic can
     *               be exercised independently of the device the test runs on.
     */
    @NonNull
    static Constraints buildConstraints(@NonNull Preferences prefs, int sdkInt) {
        Constraints.Builder constraints = new Constraints.Builder()
                .setRequiredNetworkType(prefs.getWifiOnlySync() ? NetworkType.UNMETERED : NetworkType.CONNECTED)
                .setRequiresBatteryNotLow(true);
        if (sdkInt >= VERSION_CODES.M) {
            constraints.setRequiresDeviceIdle(true);
        }
        return constraints.build();
    }

    @NonNull
    static PeriodicWorkRequest buildPeriodicSyncRequest(@NonNull Preferences prefs, int sdkInt) {
        return new PeriodicWorkRequest.Builder(KeyserverSyncWorker.class, SYNC_INTERVAL, SYNC_INTERVAL_UNIT)
                .setConstraints(buildConstraints(prefs, sdkInt))
                .build();
    }

    @NonNull
    static OneTimeWorkRequest buildOneTimeSyncRequest() {
        return new OneTimeWorkRequest.Builder(KeyserverSyncWorker.class).build();
    }
}
