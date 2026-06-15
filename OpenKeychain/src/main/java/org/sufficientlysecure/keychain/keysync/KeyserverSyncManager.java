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
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import android.content.Context;

import androidx.annotation.VisibleForTesting;
import androidx.annotation.WorkerThread;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkManager;
import org.sufficientlysecure.keychain.util.Preferences;
import timber.log.Timber;


public class KeyserverSyncManager {

    private static final Executor syncExecutor = Executors.newSingleThreadExecutor();

    public static void updateKeyserverSyncScheduleAsync(Context context, boolean forceReschedule) {
        syncExecutor.execute(() -> updateKeyserverSyncSchedule(context, forceReschedule));
    }

    @WorkerThread
    static void updateKeyserverSyncSchedule(Context context, boolean forceReschedule) {
        Preferences prefs = Preferences.getPreferences(context);
        WorkManager workManager = WorkManager.getInstance(context);

        // Cancel work that was scheduled by tag, as we used to do.
        workManager.cancelAllWorkByTag(SyncSchedulerConfig.getLegacyPeriodicWorkTag());

        if (!prefs.isKeyserverSyncEnabled()) {
            Timber.d("Key sync disabled");
            workManager.cancelUniqueWork(SyncSchedulerConfig.getWorkUniqueName());
            return;
        }

        Timber.d("Scheduling periodic key sync");

        PeriodicWorkRequest workRequest = SyncSchedulerConfig.buildPeriodicRequest(prefs);
        try {
            ExistingPeriodicWorkPolicy policy = SyncSchedulerConfig.resolvePolicy(forceReschedule);
            workManager.enqueueUniquePeriodicWork(SyncSchedulerConfig.getWorkUniqueName(), policy, workRequest).getResult().get();
            Timber.d("Work id: %s", workRequest.getId());
            prefs.setKeyserverSyncScheduled(workRequest.getId());
        } catch (InterruptedException | ExecutionException e) {
            Timber.e(e, "Error enqueueing job!");
        }
    }

    public static void debugRunSyncNow(Context context) {
        WorkManager.getInstance(context).enqueue(SyncSchedulerConfig.buildOneTimeRequest());
    }
}
