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


import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.model.UnifiedKeyInfo;
import org.sufficientlysecure.keychain.operations.results.SaveKeyringResult;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.support.KeyringTestingHelper;

/**
 * Tests for the merge/sync branches in {@link KeyWritableRepository#savePublicKeyRing} and
 * {@link KeyWritableRepository#saveSecretKeyRing}:
 * <ul>
 *   <li>Public-save with existing secret ring (merge-public-into-secret branch)</li>
 *   <li>Secret-save with existing public ring (merge-secret-into-public branch)</li>
 *   <li>Secret-save without existing public ring (extract-public-from-secret branch)</li>
 *   <li>Symantec fallback path through canonicalizeSecretRingWithFallback helper</li>
 *   <li>Force-refresh update preserving data</li>
 * </ul>
 */
@RunWith(KeychainTestRunner.class)
public class KeyRepositorySaveMergeTest {

    private KeyWritableRepository repo;

    @Before
    public void setUp() throws Exception {
        ShadowLog.stream = System.out;
        repo = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
    }

    /**
     * Save a secret key first, then save the corresponding public key.
     * The public-save must merge new data into the existing secret ring and
     * re-save both public and secret. Verify both are loadable afterwards.
     */
    @Test
    public void testSavePublicKeyRing_mergeWithExistingSecret() throws Exception {
        UncachedKeyRing secretRing = KeyringTestingHelper.readRingFromResource(
                "/test-keys/authenticate_multisub_with_revoked.asc");
        long masterKeyId = secretRing.getMasterKeyId();

        // Step 1: Save secret key
        SaveKeyringResult secretResult = repo.saveSecretKeyRing(secretRing);
        Assert.assertTrue("Saving secret key should succeed", secretResult.success());

        // Step 2: Extract public key from the secret ring and save it
        UncachedKeyRing publicRing = secretRing.extractPublicKeyRing();
        Assert.assertFalse("Extracted ring should be public", publicRing.isSecret());

        KeyWritableRepository freshRepo =
                KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        SaveKeyringResult publicResult = freshRepo.savePublicKeyRing(publicRing);
        Assert.assertTrue("Saving public key over existing secret should succeed",
                publicResult.success());

        // Step 3: Verify both public and secret are loadable
        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        Assert.assertNotNull("Public key should be loadable",
                readRepo.getCanonicalizedPublicKeyRing(masterKeyId));
        Assert.assertNotNull("Secret key should still be loadable after public save",
                readRepo.getCanonicalizedSecretKeyRing(masterKeyId));

        // Step 4: Verify secret key data round-trips correctly
        byte[] secretData = readRepo.loadSecretKeyRingData(masterKeyId);
        Assert.assertNotNull("Secret data should exist", secretData);
        UncachedKeyRing reloaded = UncachedKeyRing.decodeFromData(secretData);
        Assert.assertTrue("Reloaded ring should be secret", reloaded.isSecret());
        Assert.assertEquals("Master key ID should match",
                masterKeyId, reloaded.getMasterKeyId());
    }

    /**
     * Save a public key first, then save the corresponding secret key.
     * The secret-save must merge new data into the existing public ring.
     */
    @Test
    public void testSaveSecretKeyRing_mergeWithExistingPublic() throws Exception {
        UncachedKeyRing secretRing = KeyringTestingHelper.readRingFromResource(
                "/test-keys/authenticate_multisub_with_revoked.asc");
        long masterKeyId = secretRing.getMasterKeyId();

        // Step 1: Extract and save public key first
        UncachedKeyRing publicRing = secretRing.extractPublicKeyRing();
        SaveKeyringResult publicResult = repo.savePublicKeyRing(publicRing);
        Assert.assertTrue("Saving public key should succeed", publicResult.success());

        // Step 2: Now save the secret key — should merge with existing public
        KeyWritableRepository freshRepo =
                KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        UncachedKeyRing secretRing2 = KeyringTestingHelper.readRingFromResource(
                "/test-keys/authenticate_multisub_with_revoked.asc");
        SaveKeyringResult secretResult = freshRepo.saveSecretKeyRing(secretRing2);
        Assert.assertTrue("Saving secret key over existing public should succeed",
                secretResult.success());

        // Step 3: Verify both are loadable
        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        Assert.assertNotNull("Public key should be loadable",
                readRepo.getCanonicalizedPublicKeyRing(masterKeyId));
        Assert.assertNotNull("Secret key should be loadable",
                readRepo.getCanonicalizedSecretKeyRing(masterKeyId));

        // Step 4: Verify UnifiedKeyInfo shows secret available
        UnifiedKeyInfo info = readRepo.getUnifiedKeyInfo(masterKeyId);
        Assert.assertNotNull("UnifiedKeyInfo should exist", info);
        Assert.assertTrue("UnifiedKeyInfo should report secret available",
                info.has_any_secret());
    }

    /**
     * Save only a secret key (no pre-existing public ring).
     * The save pipeline should extract a public ring from the secret and save both.
     */
    @Test
    public void testSaveSecretKeyRing_extractPublicFromSecret() throws Exception {
        UncachedKeyRing secretRing = KeyringTestingHelper.readRingFromResource(
                "/test-keys/authenticate_multisub_with_revoked.asc");
        long masterKeyId = secretRing.getMasterKeyId();

        // Pre-condition: no public key exists
        KeyRepository readRepoBefore = KeyRepository.create(RuntimeEnvironment.getApplication());
        try {
            readRepoBefore.getCanonicalizedPublicKeyRing(masterKeyId);
            Assert.fail("Public key should not exist before save");
        } catch (KeyRepository.NotFoundException expected) {
            // expected
        }

        // Save secret key — should extract public ring from it
        SaveKeyringResult result = repo.saveSecretKeyRing(secretRing);
        Assert.assertTrue("Saving secret key should succeed", result.success());

        // Verify public key was extracted and is loadable
        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        Assert.assertNotNull("Public key should be extracted and loadable",
                readRepo.getCanonicalizedPublicKeyRing(masterKeyId));
        Assert.assertNotNull("Secret key should be loadable",
                readRepo.getCanonicalizedSecretKeyRing(masterKeyId));

        // Verify the extracted public key has the correct fingerprint
        byte[] publicData = readRepo.loadPublicKeyRingData(masterKeyId);
        UncachedKeyRing extractedPublic = UncachedKeyRing.decodeFromData(publicData);
        Assert.assertArrayEquals("Extracted public key fingerprint should match",
                secretRing.getPublicKey().getFingerprint(),
                extractedPublic.getPublicKey().getFingerprint());
    }

    /**
     * Save a Symantec public key, then save the Symantec secret key (which lacks self-certs).
     * The canonicalizeSecretRingWithFallback helper should merge self-certs from the public key.
     */
    @Test
    public void testSaveSecretKeyRing_symantecFallbackViaHelper() throws Exception {
        UncachedKeyRing pubkey = KeyringTestingHelper.readRingFromResource(
                "/test-keys/symantec_public.asc");
        UncachedKeyRing seckey = KeyringTestingHelper.readRingFromResource(
                "/test-keys/symantec_secret.asc");
        long masterKeyId = pubkey.getMasterKeyId();

        // Save public key first
        SaveKeyringResult publicResult = repo.savePublicKeyRing(pubkey);
        Assert.assertTrue("Public key import should succeed", publicResult.success());

        // Save secret key — should use Symantec fallback path
        KeyWritableRepository freshRepo =
                KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        SaveKeyringResult secretResult = freshRepo.saveSecretKeyRing(seckey);
        Assert.assertTrue("Secret key import after public should succeed (Symantec fallback)",
                secretResult.success());

        // Verify both are loadable
        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        Assert.assertNotNull(readRepo.getCanonicalizedPublicKeyRing(masterKeyId));
        Assert.assertNotNull(readRepo.getCanonicalizedSecretKeyRing(masterKeyId));
    }

    /**
     * Save a public key, then re-save it with forceRefresh=true.
     * The data should remain intact and the UPDATED flag should be set.
     */
    @Test
    public void testSavePublicKeyRing_forceRefreshPreservesData() throws Exception {
        UncachedKeyRing pubKey = KeyringTestingHelper.readRingFromResource(
                "/test-keys/mailvelope_07_no_key_flags.asc");
        long masterKeyId = pubKey.getMasterKeyId();

        // Save first time
        SaveKeyringResult firstSave = repo.savePublicKeyRing(pubKey);
        Assert.assertTrue("First save should succeed", firstSave.success());

        // Record subkey metadata before re-save
        KeyRepository readRepoBefore = KeyRepository.create(RuntimeEnvironment.getApplication());
        List<?> subkeysBefore = readRepoBefore.getSubKeysByMasterKeyId(masterKeyId);
        Assert.assertFalse("Should have subkeys", subkeysBefore.isEmpty());

        // Re-save with forceRefresh
        KeyWritableRepository freshRepo =
                KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        UncachedKeyRing sameKey = KeyringTestingHelper.readRingFromResource(
                "/test-keys/mailvelope_07_no_key_flags.asc");
        SaveKeyringResult secondSave = freshRepo.savePublicKeyRing(sameKey, null, true);
        Assert.assertTrue("forceRefresh re-save should succeed", secondSave.success());
        Assert.assertTrue("forceRefresh should report UPDATED", secondSave.updated());

        // Verify data is still intact
        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        List<?> subkeysAfter = readRepo.getSubKeysByMasterKeyId(masterKeyId);
        Assert.assertEquals("Subkey count should be preserved after force refresh",
                subkeysBefore.size(), subkeysAfter.size());
        Assert.assertNotNull("Public key should still be loadable",
                readRepo.getCanonicalizedPublicKeyRing(masterKeyId));
    }

    /**
     * Verify that savePublicKeyRing correctly reports SAVED_SECRET flag when
     * a secret key exists and is re-saved alongside the public key update.
     */
    @Test
    public void testSavePublicKeyRing_reportsSavedSecretFlag() throws Exception {
        UncachedKeyRing secretRing = KeyringTestingHelper.readRingFromResource(
                "/test-keys/authenticate_multisub_with_revoked.asc");

        // Save secret key first
        repo.saveSecretKeyRing(secretRing);

        // Now save public key with forceRefresh — should also re-save secret
        KeyWritableRepository freshRepo =
                KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        UncachedKeyRing publicRing = secretRing.extractPublicKeyRing();
        SaveKeyringResult result = freshRepo.savePublicKeyRing(publicRing, null, true);

        Assert.assertTrue("Save should succeed", result.success());
        Assert.assertTrue("Should report SAVED_PUBLIC",
                (result.getResult() & SaveKeyringResult.SAVED_PUBLIC) != 0);
        Assert.assertTrue("Should report SAVED_SECRET (secret was re-saved)",
                (result.getResult() & SaveKeyringResult.SAVED_SECRET) != 0);
    }

    private UncachedKeyRing readRingFromResource(String name) throws Exception {
        return UncachedKeyRing.fromStream(
                KeyRepositorySaveMergeTest.class.getResourceAsStream(name)).next();
    }
}
