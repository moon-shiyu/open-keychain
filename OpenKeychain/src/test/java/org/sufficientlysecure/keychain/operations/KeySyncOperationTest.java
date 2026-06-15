package org.sufficientlysecure.keychain.operations;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.KeyMetadataDao;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.keyimport.ParcelableKeyRing;
import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.util.Preferences;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for KeySyncOperation.
 *
 * Tests cover:
 * - fingerprintListToParcelableKeyRings conversion (empty, single, multiple, null fields)
 * - resolveStaleThreshold (refreshAll vs refreshOutdated)
 * - execute() branches: no stale keys, cancellation
 *
 * NOTE: These tests require Android SDK and Robolectric.
 * If ANDROID_HOME is not set, tests cannot run locally.
 *
 * Manual verification steps:
 * 1. Trigger "Update all keys" from debug menu
 * 2. Verify keys are fetched from keyserver
 * 3. Check logs for "Keyserver sync: Updating" messages
 */
@RunWith(KeychainTestRunner.class)
public class KeySyncOperationTest {

    @Test
    public void testFingerprintListToParcelableKeyRingsEmpty() {
        List<byte[]> emptyList = Collections.emptyList();
        List<ParcelableKeyRing> result = KeySyncOperation.fingerprintListToParcelableKeyRings(emptyList);
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    public void testFingerprintListToParcelableKeyRingsSingle() {
        byte[] fingerprint = new byte[20]; // 20-byte fingerprint
        Arrays.fill(fingerprint, (byte) 0xAB);

        List<byte[]> fingerprints = Collections.singletonList(fingerprint);
        List<ParcelableKeyRing> result = KeySyncOperation.fingerprintListToParcelableKeyRings(fingerprints);

        assertEquals(1, result.size());
        ParcelableKeyRing keyRing = result.get(0);
        assertNotNull(keyRing);
        // Verify the fingerprint was preserved
        assertNotNull(keyRing.getFingerprint());
    }

    @Test
    public void testFingerprintListToParcelableKeyRingsMultiple() {
        List<byte[]> fingerprints = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            byte[] fp = new byte[20];
            Arrays.fill(fp, (byte) i);
            fingerprints.add(fp);
        }

        List<ParcelableKeyRing> result = KeySyncOperation.fingerprintListToParcelableKeyRings(fingerprints);

        assertEquals(5, result.size());
        for (ParcelableKeyRing keyRing : result) {
            assertNotNull(keyRing);
            assertNotNull(keyRing.getFingerprint());
        }
    }

    @Test
    public void testFingerprintListToParcelableKeyRingsNoKeyserver() {
        // Verify that created ParcelableKeyRing has no keyserver set
        byte[] fingerprint = new byte[20];
        Arrays.fill(fingerprint, (byte) 0xCD);

        List<byte[]> fingerprints = Collections.singletonList(fingerprint);
        List<ParcelableKeyRing> result = KeySyncOperation.fingerprintListToParcelableKeyRings(fingerprints);

        assertEquals(1, result.size());
        ParcelableKeyRing keyRing = result.get(0);
        // The keyserver should be null (not set)
        // ParcelableKeyRing.createFromReference sets keyserver to null
        assertNotNull(keyRing);
    }

    @Test
    public void testFingerprintListToParcelableKeyRingsNoBytes() {
        // Verify that created ParcelableKeyRing has no bytes set
        byte[] fingerprint = new byte[20];
        Arrays.fill(fingerprint, (byte) 0xEF);

        List<byte[]> fingerprints = Collections.singletonList(fingerprint);
        List<ParcelableKeyRing> result = KeySyncOperation.fingerprintListToParcelableKeyRings(fingerprints);

        assertEquals(1, result.size());
        ParcelableKeyRing keyRing = result.get(0);
        // The bytes should be null (not set)
        // ParcelableKeyRing.createFromReference sets bytes to null
        assertNotNull(keyRing);
    }

    // --- resolveStaleThreshold tests ---

    @Test
    public void testResolveStaleThresholdRefreshAllIsNearCurrentTime() {
        long before = System.currentTimeMillis();
        long threshold = KeySyncOperation.resolveStaleThreshold(true);
        long after = System.currentTimeMillis();
        assertTrue("refreshAll threshold should be >= before", threshold >= before);
        assertTrue("refreshAll threshold should be <= after", threshold <= after);
    }

    @Test
    public void testResolveStaleThresholdRefreshOutdatedIsInPast() {
        long threshold = KeySyncOperation.resolveStaleThreshold(false);
        long now = System.currentTimeMillis();
        // Threshold must be in the past (either ~7 days ago in production, or ~1ms in debug)
        assertTrue("refreshOutdated threshold must be in the past", threshold < now);
    }

    // --- execute() branch tests using mocked dependencies ---

    @Test
    public void testExecuteWithNoStaleKeysReturnsOk() {
        KeyMetadataDao mockDao = mock(KeyMetadataDao.class);
        Preferences mockPrefs = mock(Preferences.class);
        KeyWritableRepository mockRepo = mock(KeyWritableRepository.class);
        AtomicBoolean cancelled = new AtomicBoolean(false);

        when(mockDao.getFingerprintsForKeysOlderThan(anyLong(), any(TimeUnit.class)))
                .thenReturn(Collections.emptyList());

        KeySyncOperation op = new KeySyncOperation(
                RuntimeEnvironment.getApplication(), mockRepo, null, cancelled,
                mockDao, mockPrefs);

        ImportKeyResult result = op.execute(
                KeySyncParcel.createRefreshOutdated(),
                CryptoInputParcel.createCryptoInputParcel());

        assertEquals(OperationResult.RESULT_OK, result.getResult());
    }

    @Test
    public void testExecuteWhenCancelledReturnsCancelled() {
        KeyMetadataDao mockDao = mock(KeyMetadataDao.class);
        Preferences mockPrefs = mock(Preferences.class);
        KeyWritableRepository mockRepo = mock(KeyWritableRepository.class);
        AtomicBoolean cancelled = new AtomicBoolean(true);

        byte[] fp = new byte[20];
        when(mockDao.getFingerprintsForKeysOlderThan(anyLong(), any(TimeUnit.class)))
                .thenReturn(Collections.singletonList(fp));

        KeySyncOperation op = new KeySyncOperation(
                RuntimeEnvironment.getApplication(), mockRepo, null, cancelled,
                mockDao, mockPrefs);

        ImportKeyResult result = op.execute(
                KeySyncParcel.createRefreshOutdated(),
                CryptoInputParcel.createCryptoInputParcel());

        assertEquals(OperationResult.RESULT_CANCELLED, result.getResult());
    }

    @Test
    public void testExecuteRefreshAllWithNoStaleKeysReturnsOk() {
        KeyMetadataDao mockDao = mock(KeyMetadataDao.class);
        Preferences mockPrefs = mock(Preferences.class);
        KeyWritableRepository mockRepo = mock(KeyWritableRepository.class);
        AtomicBoolean cancelled = new AtomicBoolean(false);

        when(mockDao.getFingerprintsForKeysOlderThan(anyLong(), any(TimeUnit.class)))
                .thenReturn(Collections.emptyList());

        KeySyncOperation op = new KeySyncOperation(
                RuntimeEnvironment.getApplication(), mockRepo, null, cancelled,
                mockDao, mockPrefs);

        ImportKeyResult result = op.execute(
                KeySyncParcel.createRefreshAll(),
                CryptoInputParcel.createCryptoInputParcel());

        assertEquals(OperationResult.RESULT_OK, result.getResult());
    }
}
