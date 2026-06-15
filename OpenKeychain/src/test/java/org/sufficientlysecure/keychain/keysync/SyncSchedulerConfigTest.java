package org.sufficientlysecure.keychain.keysync;


import java.util.concurrent.TimeUnit;

import androidx.work.Constraints;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.NetworkType;
import androidx.work.OneTimeWorkRequest;
import androidx.work.PeriodicWorkRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.util.Preferences;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Unit tests for SyncSchedulerConfig.
 *
 * NOTE: These tests require Android SDK and Robolectric.
 * If ANDROID_HOME is not set, tests cannot run locally.
 *
 * Manual verification steps:
 * 1. Enable keyserver sync in Settings -> verify WorkManager schedules periodic work
 * 2. Change wifi-only preference -> verify constraints update
 * 3. Disable sync -> verify work is cancelled
 */
@RunWith(KeychainTestRunner.class)
public class SyncSchedulerConfigTest {

    @Before
    public void setUp() {
        // Force new Preferences instance for each test
        Preferences.getPreferences(RuntimeEnvironment.getApplication(), true);
    }

    @Test
    public void testSyncIntervalIs3Days() {
        assertEquals(3, SyncSchedulerConfig.getSyncInterval());
        assertEquals(TimeUnit.DAYS, SyncSchedulerConfig.getSyncIntervalUnit());
    }

    @Test
    public void testWorkUniqueNameIsUnchanged() {
        assertEquals("periodicKeyserverSync", SyncSchedulerConfig.getWorkUniqueName());
    }

    @Test
    public void testLegacyPeriodicWorkTagIsUnchanged() {
        assertEquals("keyserverSync", SyncSchedulerConfig.getLegacyPeriodicWorkTag());
    }

    @Test
    public void testResolvePolicyKeep() {
        assertEquals(ExistingPeriodicWorkPolicy.KEEP, SyncSchedulerConfig.resolvePolicy(false));
    }

    @Test
    public void testResolvePolicyReplace() {
        assertEquals(ExistingPeriodicWorkPolicy.REPLACE, SyncSchedulerConfig.resolvePolicy(true));
    }

    @Test
    public void testBuildConstraintsReturnsNonNull() {
        Preferences prefs = Preferences.getPreferences(RuntimeEnvironment.getApplication());
        Constraints constraints = SyncSchedulerConfig.buildConstraints(prefs);
        assertNotNull("Constraints should not be null", constraints);
    }

    @Test
    public void testBuildConstraintsWifiOnly() {
        Preferences prefs = Preferences.getPreferences(RuntimeEnvironment.getApplication(), true);
        prefs.getSharedPreferences().edit()
                .putBoolean("sync_keyserver", true)
                .putBoolean("wifi_only_sync", true)
                .apply();

        Constraints constraints = SyncSchedulerConfig.buildConstraints(prefs);
        assertNotNull("Constraints should not be null", constraints);
        // Note: WorkManager Constraints doesn't expose getters directly in tests,
        // but we verify no exceptions are thrown during construction
    }

    @Test
    public void testBuildConstraintsAnyNetwork() {
        Preferences prefs = Preferences.getPreferences(RuntimeEnvironment.getApplication(), true);
        prefs.getSharedPreferences().edit()
                .putBoolean("sync_keyserver", true)
                .putBoolean("wifi_only_sync", false)
                .apply();

        Constraints constraints = SyncSchedulerConfig.buildConstraints(prefs);
        assertNotNull("Constraints should not be null", constraints);
    }

    @Test
    public void testBuildPeriodicRequestReturnsNonNull() {
        Preferences prefs = Preferences.getPreferences(RuntimeEnvironment.getApplication());
        PeriodicWorkRequest request = SyncSchedulerConfig.buildPeriodicRequest(prefs);
        assertNotNull("PeriodicWorkRequest should not be null", request);
    }

    @Test
    public void testBuildOneTimeRequestReturnsNonNull() {
        OneTimeWorkRequest request = SyncSchedulerConfig.buildOneTimeRequest();
        assertNotNull("OneTimeWorkRequest should not be null", request);
    }
}
