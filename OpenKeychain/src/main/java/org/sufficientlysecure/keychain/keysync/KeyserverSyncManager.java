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


import java.util.concurrent.ExecutionException;

import android.content.Context;
import android.os.AsyncTask;
import android.os.Build.VERSION;

import androidx.annotation.WorkerThread;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkManager;
import org.sufficientlysecure.keychain.util.Preferences;
import timber.log.Timber;


public class KeyserverSyncManager {

    public static void updateKeyserverSyncScheduleAsync(Context context, boolean forceReschedule) {
        new AsyncTask<Void,Void,Void>() {
            @Override
            protected Void doInBackground(Void... voids) {
                updateKeyserverSyncSchedule(context, forceReschedule);
                return null;
            }
        }.execute();
    }

    @WorkerThread
    private static void updateKeyserverSyncSchedule(Context context, boolean forceReschedule) {
        Preferences prefs = Preferences.getPreferences(context);
        WorkManager workManager = WorkManager.getInstance(context);

        // Cancel work that was scheduled by tag, as we used to do.
        workManager.cancelAllWorkByTag(KeyserverSyncWorkRequestFactory.LEGACY_PERIODIC_WORK_TAG);

        if (!prefs.isKeyserverSyncEnabled()) {
            Timber.d("Key sync disabled");
            workManager.cancelUniqueWork(KeyserverSyncWorkRequestFactory.WORK_UNIQUE_NAME);
            return;
        }

        Timber.d("Scheduling periodic key sync");

        PeriodicWorkRequest workRequest =
                KeyserverSyncWorkRequestFactory.buildPeriodicSyncRequest(prefs, VERSION.SDK_INT);
        try {
            ExistingPeriodicWorkPolicy policy = forceReschedule
                    ? ExistingPeriodicWorkPolicy.REPLACE
                    : ExistingPeriodicWorkPolicy.KEEP;
            workManager.enqueueUniquePeriodicWork(
                    KeyserverSyncWorkRequestFactory.WORK_UNIQUE_NAME, policy, workRequest)
                    .getResult().get();
            Timber.d("Work id: %s", workRequest.getId());
            prefs.setKeyserverSyncScheduled(workRequest.getId());
        } catch (InterruptedException | ExecutionException e) {
            Timber.e(e, "Error enqueueing job!");
        }
    }

    public static void debugRunSyncNow(Context context) {
        WorkManager workManager = WorkManager.getInstance(context);
        workManager.enqueue(KeyserverSyncWorkRequestFactory.buildOneTimeSyncRequest());
    }
}
