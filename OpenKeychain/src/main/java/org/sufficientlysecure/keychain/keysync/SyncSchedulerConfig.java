/*
 * Copyright (C) 2017 Schurmann & Breitmoser GbR
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

import android.os.Build.VERSION;
import android.os.Build.VERSION_CODES;

import androidx.work.Constraints;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.NetworkType;
import androidx.work.OneTimeWorkRequest;
import androidx.work.PeriodicWorkRequest;
import org.sufficientlysecure.keychain.util.Preferences;


/**
 * Encapsulates sync scheduling configuration: interval, unique work name, constraints, and policy.
 * This class is stateless and all methods are static to facilitate testing and reuse.
 */
public class SyncSchedulerConfig {
    /** Sync interval in days */
    static final long SYNC_INTERVAL = 3;
    static final TimeUnit SYNC_INTERVAL_UNIT = TimeUnit.DAYS;

    /** Legacy tag used before migrating to unique work name */
    static final String LEGACY_PERIODIC_WORK_TAG = "keyserverSync";

    /** Unique work name for periodic keyserver sync */
    static final String WORK_UNIQUE_NAME = "periodicKeyserverSync";

    private SyncSchedulerConfig() {
        // Utility class
    }

    /**
     * Build WorkManager constraints based on user preferences.
     * Network type depends on wifi-only setting; battery not low is always required;
     * device idle is required on Android M+.
     */
    public static Constraints buildConstraints(Preferences prefs) {
        Constraints.Builder builder = new Constraints.Builder()
                .setRequiredNetworkType(prefs.getWifiOnlySync() ? NetworkType.UNMETERED : NetworkType.CONNECTED)
                .setRequiresBatteryNotLow(true);
        if (VERSION.SDK_INT >= VERSION_CODES.M) {
            builder.setRequiresDeviceIdle(true);
        }
        return builder.build();
    }

    /**
     * Determine the enqueue policy based on whether a reschedule is forced.
     * REPLACE is used when preferences change; KEEP is used on app startup.
     */
    public static ExistingPeriodicWorkPolicy resolvePolicy(boolean forceReschedule) {
        return forceReschedule
                ? ExistingPeriodicWorkPolicy.REPLACE
                : ExistingPeriodicWorkPolicy.KEEP;
    }

    public static long getSyncInterval() {
        return SYNC_INTERVAL;
    }

    public static TimeUnit getSyncIntervalUnit() {
        return SYNC_INTERVAL_UNIT;
    }

    public static String getLegacyPeriodicWorkTag() {
        return LEGACY_PERIODIC_WORK_TAG;
    }

    public static String getWorkUniqueName() {
        return WORK_UNIQUE_NAME;
    }

    /**
     * Build a PeriodicWorkRequest for periodic keyserver sync.
     * Encapsulates worker class, interval, and constraints in one place.
     */
    public static PeriodicWorkRequest buildPeriodicRequest(Preferences prefs) {
        Constraints constraints = buildConstraints(prefs);
        return new PeriodicWorkRequest.Builder(
                KeyserverSyncWorker.class,
                SYNC_INTERVAL, SYNC_INTERVAL_UNIT)
                .setConstraints(constraints)
                .build();
    }

    /**
     * Build a OneTimeWorkRequest for immediate (debug) sync.
     */
    public static OneTimeWorkRequest buildOneTimeRequest() {
        return new OneTimeWorkRequest.Builder(KeyserverSyncWorker.class).build();
    }
}
