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

package org.sufficientlysecure.keychain.provider;


import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.operations.results.SaveKeyringResult;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.support.KeyringTestingHelper;

/**
 * Tests for {@link KeyRepository#loadPublicKeyRingData(long)} and
 * {@link KeyRepository#loadSecretKeyRingData(long)}.
 */
@RunWith(KeychainTestRunner.class)
public class KeyRepositoryLoadTest {

    private KeyWritableRepository repo;

    @Before
    public void setUp() throws Exception {
        ShadowLog.stream = System.out;
        repo = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
    }

    @Test
    public void testLoadPublicKeyRingData_smallKey_fromDb() throws Exception {
        // Use a small public key that will be stored as a DB BLOB (< 50KB)
        UncachedKeyRing pubKey = KeyringTestingHelper.readRingFromResource(
                "/test-keys/mailvelope_07_no_key_flags.asc");
        long masterKeyId = pubKey.getMasterKeyId();

        // Save public key
        SaveKeyringResult saveResult = repo.savePublicKeyRing(pubKey);
        Assert.assertTrue("Saving public key should succeed", saveResult.success());

        // Load and verify
        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        byte[] data = readRepo.loadPublicKeyRingData(masterKeyId);
        Assert.assertNotNull("Public key data should not be null", data);
        Assert.assertTrue("Public key data should be non-empty", data.length > 0);

        // Verify data is valid by decoding
        UncachedKeyRing decoded = UncachedKeyRing.decodeFromData(data);
        Assert.assertEquals("Decoded key should have same master key ID",
                masterKeyId, decoded.getMasterKeyId());
    }

    @Test
    public void testLoadPublicKeyRingData_notFound() throws Exception {
        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        try {
            readRepo.loadPublicKeyRingData(0x0123456789ABCDEFL);
            Assert.fail("Expected NotFoundException for non-existent public key");
        } catch (KeyRepository.NotFoundException expected) {
            // expected
        }
    }

    @Test
    public void testLoadSecretKeyRingData_afterSave() throws Exception {
        UncachedKeyRing secRing = KeyringTestingHelper.readRingFromResource(
                "/test-keys/authenticate_multisub_with_revoked.asc");
        long masterKeyId = secRing.getMasterKeyId();

        // Save secret key
        SaveKeyringResult saveResult = repo.saveSecretKeyRing(secRing);
        Assert.assertTrue("Saving secret key should succeed", saveResult.success());

        // Load and verify
        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        byte[] data = readRepo.loadSecretKeyRingData(masterKeyId);
        Assert.assertNotNull("Secret key data should not be null", data);
        Assert.assertTrue("Secret key data should be non-empty", data.length > 0);

        // Verify data is valid by decoding
        UncachedKeyRing decoded = UncachedKeyRing.decodeFromData(data);
        Assert.assertTrue("Decoded ring should be a secret key ring", decoded.isSecret());
        Assert.assertEquals("Decoded ring should have same master key ID",
                masterKeyId, decoded.getMasterKeyId());
    }

    @Test
    public void testLoadSecretKeyRingData_notFound() throws Exception {
        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        try {
            readRepo.loadSecretKeyRingData(0x0123456789ABCDEFL);
            Assert.fail("Expected NotFoundException for non-existent secret key");
        } catch (KeyRepository.NotFoundException expected) {
            // expected
        }
    }

    @Test
    public void testLoadPublicKeyRingData_matchesOriginal() throws Exception {
        // Save a key and verify the loaded data produces the same key
        UncachedKeyRing pubKey = KeyringTestingHelper.readRingFromResource(
                "/test-keys/mailvelope_07_no_key_flags.asc");
        long masterKeyId = pubKey.getMasterKeyId();

        repo.savePublicKeyRing(pubKey);

        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        byte[] loadedData = readRepo.loadPublicKeyRingData(masterKeyId);
        UncachedKeyRing loadedRing = UncachedKeyRing.decodeFromData(loadedData);

        // Compare master key IDs and fingerprints
        Assert.assertEquals("Master key ID should match",
                pubKey.getMasterKeyId(), loadedRing.getMasterKeyId());
        Assert.assertArrayEquals("Fingerprint should match",
                pubKey.getPublicKey().getFingerprint(),
                loadedRing.getPublicKey().getFingerprint());
    }

    @Test
    public void testLoadSecretKeyRingData_matchesOriginal() throws Exception {
        UncachedKeyRing secRing = KeyringTestingHelper.readRingFromResource(
                "/test-keys/authenticate_multisub_with_revoked.asc");
        long masterKeyId = secRing.getMasterKeyId();

        repo.saveSecretKeyRing(secRing);

        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        byte[] loadedData = readRepo.loadSecretKeyRingData(masterKeyId);
        UncachedKeyRing loadedRing = UncachedKeyRing.decodeFromData(loadedData);

        Assert.assertEquals("Master key ID should match",
                secRing.getMasterKeyId(), loadedRing.getMasterKeyId());
        Assert.assertArrayEquals("Fingerprint should match",
                secRing.getPublicKey().getFingerprint(),
                loadedRing.getPublicKey().getFingerprint());
    }
}
