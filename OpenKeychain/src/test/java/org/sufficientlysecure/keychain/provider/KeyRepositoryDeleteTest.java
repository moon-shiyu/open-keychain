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
 * Tests for {@link KeyWritableRepository#deleteKeyRing(long)}.
 */
@RunWith(KeychainTestRunner.class)
public class KeyRepositoryDeleteTest {

    private KeyWritableRepository repo;
    private UncachedKeyRing testKeyring;

    @Before
    public void setUp() throws Exception {
        ShadowLog.stream = System.out;
        repo = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        testKeyring = KeyringTestingHelper.readRingFromResource(
                "/test-keys/authenticate_multisub_with_revoked.asc");
    }

    @Test
    public void testDeleteExistingKeyRing() throws Exception {
        long masterKeyId = testKeyring.getMasterKeyId();

        // Pre-condition: save key and verify it exists
        SaveKeyringResult saveResult = repo.saveSecretKeyRing(testKeyring);
        Assert.assertTrue("Saving test key should succeed", saveResult.success());

        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        Assert.assertNotNull("Key should exist before delete",
                readRepo.getCanonicalizedPublicKeyRing(masterKeyId));
        Assert.assertNotNull("UnifiedKeyInfo should exist before delete",
                readRepo.getUnifiedKeyInfo(masterKeyId));

        // Act: delete the key
        boolean deleted = repo.deleteKeyRing(masterKeyId);
        Assert.assertTrue("deleteKeyRing should return true for existing key", deleted);

        // Assert: public key is gone
        try {
            readRepo.getCanonicalizedPublicKeyRing(masterKeyId);
            Assert.fail("Expected NotFoundException after deleting public key");
        } catch (KeyRepository.NotFoundException expected) {
            // expected
        }

        // Assert: secret key is gone
        try {
            readRepo.getCanonicalizedSecretKeyRing(masterKeyId);
            Assert.fail("Expected NotFoundException after deleting secret key");
        } catch (KeyRepository.NotFoundException expected) {
            // expected
        }

        // Assert: UnifiedKeyInfo is gone
        Assert.assertNull("UnifiedKeyInfo should be null after delete",
                readRepo.getUnifiedKeyInfo(masterKeyId));
    }

    @Test
    public void testDeleteNonExistentKeyRing() throws Exception {
        // Delete with a non-existent key ID
        long bogusKeyId = 0x0123456789ABCDEFL;
        boolean deleted = repo.deleteKeyRing(bogusKeyId);
        Assert.assertFalse("deleteKeyRing should return false for non-existent key", deleted);
    }

    @Test
    public void testDeleteAndReimport() throws Exception {
        long masterKeyId = testKeyring.getMasterKeyId();

        // Save key
        SaveKeyringResult saveResult = repo.saveSecretKeyRing(testKeyring);
        Assert.assertTrue("Initial save should succeed", saveResult.success());

        // Delete key
        boolean deleted = repo.deleteKeyRing(masterKeyId);
        Assert.assertTrue("Delete should succeed", deleted);

        // Re-import the same key
        KeyWritableRepository freshRepo = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        UncachedKeyRing reimportedRing = KeyringTestingHelper.readRingFromResource(
                "/test-keys/authenticate_multisub_with_revoked.asc");
        SaveKeyringResult reimportResult = freshRepo.saveSecretKeyRing(reimportedRing);
        Assert.assertTrue("Re-import after delete should succeed", reimportResult.success());

        // Verify key is accessible again
        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        Assert.assertNotNull("Public key should be accessible after re-import",
                readRepo.getCanonicalizedPublicKeyRing(masterKeyId));
        Assert.assertNotNull("Secret key should be accessible after re-import",
                readRepo.getCanonicalizedSecretKeyRing(masterKeyId));
        Assert.assertNotNull("UnifiedKeyInfo should be accessible after re-import",
                readRepo.getUnifiedKeyInfo(masterKeyId));
    }

    @Test
    public void testDeleteRemovesSubkeyMetadata() throws Exception {
        long masterKeyId = testKeyring.getMasterKeyId();

        // Save key
        repo.saveSecretKeyRing(testKeyring);

        // Verify subkeys exist
        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        Assert.assertFalse("Should have subkeys before delete",
                readRepo.getSubKeysByMasterKeyId(masterKeyId).isEmpty());

        // Delete
        repo.deleteKeyRing(masterKeyId);

        // Assert: subkeys are gone
        Assert.assertTrue("Subkeys should be removed after delete",
                readRepo.getSubKeysByMasterKeyId(masterKeyId).isEmpty());
    }

    @Test
    public void testDeleteSecretKeyDataIsCleaned() throws Exception {
        long masterKeyId = testKeyring.getMasterKeyId();

        // Save key
        repo.saveSecretKeyRing(testKeyring);

        // Verify secret data exists
        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        byte[] secretDataBeforeDelete = readRepo.loadSecretKeyRingData(masterKeyId);
        Assert.assertNotNull("Secret key data should exist before delete", secretDataBeforeDelete);

        // Delete
        repo.deleteKeyRing(masterKeyId);

        // Assert: secret data is gone
        try {
            readRepo.loadSecretKeyRingData(masterKeyId);
            Assert.fail("Expected NotFoundException for secret key data after delete");
        } catch (KeyRepository.NotFoundException expected) {
            // expected
        }
    }
}
