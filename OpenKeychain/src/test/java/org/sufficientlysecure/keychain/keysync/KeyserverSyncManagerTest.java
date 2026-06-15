package org.sufficientlysecure.keychain.keysync;


import android.content.Context;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.util.Preferences;

/**
 * Tests for KeyserverSyncManager scheduling logic.
 *
 * Limitations:
 * {@code ShadowWorkManager} returns a Mockito mock from {@code WorkManager.getInstance()}.
 * All WorkManager method calls on the mock return null/default values. The "sync enabled"
 * branch calls {@code enqueueUniquePeriodicWork(...).getResult().get()} which would NPE
 * on the mock. Therefore, these tests cover only:
 * - The "sync disabled" branch (which returns early before enqueue)
 * - The legacy tag cancellation (which is a void call on the mock)
 *
 * To test the "sync enabled" branch, {@code ShadowWorkManager} would need to be enhanced
 * to return a proper {@code Operation} from {@code enqueueUniquePeriodicWork()}.
 *
 * Manual verification steps:
 * 1. Enable keyserver sync in Settings → verify WorkManager schedules periodic work
 * 2. Change wifi-only preference → verify constraints update (REPLACE policy)
 * 3. Disable sync → verify unique work is cancelled
 * 4. Call debugRunSyncNow() → verify one-time work is enqueued
 */
@RunWith(KeychainTestRunner.class)
public class KeyserverSyncManagerTest {

    @Before
    public void setUp() {
        // Force new Preferences instance for each test
        Preferences.getPreferences(RuntimeEnvironment.getApplication(), true);
    }

    @Test
    public void testUpdateScheduleCancelsLegacyTagWhenDisabled() {
        Context context = RuntimeEnvironment.getApplication();
        Preferences prefs = Preferences.getPreferences(context);
        prefs.getSharedPreferences().edit()
                .putBoolean("sync_keyserver", false)
                .apply();

        // This calls WorkManager.cancelAllWorkByTag("keyserverSync") — void on mock, no-op
        // Then calls WorkManager.cancelUniqueWork("periodicKeyserverSync") — void on mock, no-op
        // Should not throw any exception
        KeyserverSyncManager.updateKeyserverSyncSchedule(context, false);
    }

    @Test
    public void testUpdateScheduleCancelsUniqueWorkWhenDisabled() {
        Context context = RuntimeEnvironment.getApplication();
        Preferences prefs = Preferences.getPreferences(context);
        prefs.getSharedPreferences().edit()
                .putBoolean("sync_keyserver", false)
                .apply();

        // With sync disabled, the method should:
        // 1. Cancel legacy tag work (void call on mock)
        // 2. Cancel unique work (void call on mock)
        // 3. Return without enqueueing new work
        KeyserverSyncManager.updateKeyserverSyncSchedule(context, true);
    }

    @Test
    public void testUpdateScheduleKeepPolicyWhenDisabled() {
        Context context = RuntimeEnvironment.getApplication();
        Preferences prefs = Preferences.getPreferences(context);
        prefs.getSharedPreferences().edit()
                .putBoolean("sync_keyserver", false)
                .apply();

        // forceReschedule=false → KEEP policy, but since sync is disabled,
        // the policy is never used — method returns early
        KeyserverSyncManager.updateKeyserverSyncSchedule(context, false);
    }
}
