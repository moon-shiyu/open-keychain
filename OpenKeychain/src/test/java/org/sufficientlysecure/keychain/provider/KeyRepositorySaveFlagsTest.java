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


import java.util.ArrayList;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogType;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogEntryParcel;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.operations.results.SaveKeyringResult;
import org.sufficientlysecure.keychain.pgp.CanonicalizedKeyRing;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.support.KeyringTestingHelper;

/**
 * Tests for {@link KeyWritableRepository#savePublicKeyRing} and
 * {@link KeyWritableRepository#saveSecretKeyRing} flag paths:
 * fingerprint validation, skipSave, forceRefresh, and type mismatch.
 */
@RunWith(KeychainTestRunner.class)
public class KeyRepositorySaveFlagsTest {

    private KeyWritableRepository repo;

    @Before
    public void setUp() throws Exception {
        ShadowLog.stream = System.out;
        repo = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
    }

    @Test
    public void testSavePublicKeyRing_fingerprint_matches() throws Exception {
        UncachedKeyRing pubKey = KeyringTestingHelper.readRingFromResource(
                "/test-keys/mailvelope_07_no_key_flags.asc");
        byte[] fingerprint = pubKey.getPublicKey().getFingerprint();

        SaveKeyringResult result = repo.savePublicKeyRing(pubKey, fingerprint);
        Assert.assertTrue("Save with correct fingerprint should succeed", result.success());

        // Verify key was actually persisted
        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        Assert.assertNotNull("Key should be persisted",
                readRepo.getCanonicalizedPublicKeyRing(pubKey.getMasterKeyId()));
    }

    @Test
    public void testSavePublicKeyRing_fingerprint_mismatch() throws Exception {
        UncachedKeyRing pubKey = KeyringTestingHelper.readRingFromResource(
                "/test-keys/mailvelope_07_no_key_flags.asc");
        long masterKeyId = pubKey.getMasterKeyId();
        byte[] wrongFingerprint = new byte[20]; // all zeros — guaranteed mismatch

        SaveKeyringResult result = repo.savePublicKeyRing(pubKey, wrongFingerprint);
        Assert.assertFalse("Save with wrong fingerprint should fail", result.success());

        // Key should NOT be persisted
        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        try {
            readRepo.getCanonicalizedPublicKeyRing(masterKeyId);
            Assert.fail("Key should not be saved after fingerprint mismatch");
        } catch (KeyRepository.NotFoundException expected) {
            // expected
        }
    }

    @Test
    public void testSavePublicKeyRing_skipSave() throws Exception {
        UncachedKeyRing pubKey = KeyringTestingHelper.readRingFromResource(
                "/test-keys/mailvelope_07_no_key_flags.asc");
        long masterKeyId = pubKey.getMasterKeyId();
        ArrayList<CanonicalizedKeyRing> canKeyRings = new ArrayList<>();

        SaveKeyringResult result = repo.savePublicKeyRing(
                pubKey, null, canKeyRings, false, true /* skipSave */);

        // skipSave should still report SAVED_PUBLIC in the result bitmask
        // (the canonicalization was done, just the DB write was skipped)
        // Note: success() checks that RESULT_ERROR bit is not set
        Assert.assertTrue("skipSave should not produce an error", result.success());

        // canKeyRings should be populated with the canonicalized key
        Assert.assertFalse("canKeyRings should be populated even with skipSave",
                canKeyRings.isEmpty());

        // Key should NOT be persisted in the database
        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        try {
            readRepo.getCanonicalizedPublicKeyRing(masterKeyId);
            Assert.fail("Key should not be persisted with skipSave=true");
        } catch (KeyRepository.NotFoundException expected) {
            // expected
        }
    }

    @Test
    public void testSavePublicKeyRing_forceRefresh_identicalKey() throws Exception {
        UncachedKeyRing pubKey = KeyringTestingHelper.readRingFromResource(
                "/test-keys/mailvelope_07_no_key_flags.asc");

        // Save first time
        SaveKeyringResult firstSave = repo.savePublicKeyRing(pubKey);
        Assert.assertTrue("First save should succeed", firstSave.success());

        // Save again with forceRefresh=true using a fresh repository
        KeyWritableRepository freshRepo = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        UncachedKeyRing sameKey = KeyringTestingHelper.readRingFromResource(
                "/test-keys/mailvelope_07_no_key_flags.asc");
        SaveKeyringResult secondSave = freshRepo.savePublicKeyRing(sameKey, null, true);
        Assert.assertTrue("forceRefresh re-save should succeed", secondSave.success());

        // With forceRefresh, even identical keys should be re-processed (UPDATED flag set)
        Assert.assertTrue("forceRefresh with identical key should report UPDATED",
                secondSave.updated());
    }

    @Test
    public void testSavePublicKeyRing_noForceRefresh_identicalKey() throws Exception {
        UncachedKeyRing pubKey = KeyringTestingHelper.readRingFromResource(
                "/test-keys/mailvelope_07_no_key_flags.asc");

        // Save first time
        SaveKeyringResult firstSave = repo.savePublicKeyRing(pubKey);
        Assert.assertTrue("First save should succeed", firstSave.success());

        // Save again with forceRefresh=false (default) using a fresh repository
        KeyWritableRepository freshRepo = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        UncachedKeyRing sameKey = KeyringTestingHelper.readRingFromResource(
                "/test-keys/mailvelope_07_no_key_flags.asc");
        SaveKeyringResult secondSave = freshRepo.savePublicKeyRing(sameKey);
        Assert.assertTrue("Re-save identical key should succeed", secondSave.success());

        // Should take the early-out path (identical encoded bytes)
        Assert.assertTrue("Identical key re-save should report UPDATED",
                secondSave.updated());

        // Check that the log contains MSG_IP_SUCCESS_IDENTICAL indicating early-out
        OperationLog log = secondSave.getLog();
        Assert.assertTrue("Log should contain early-out message for identical key",
                logContainsType(log, LogType.MSG_IP_SUCCESS_IDENTICAL));
    }

    @Test
    public void testSavePublicKeyRing_rejectSecretType() throws Exception {
        UncachedKeyRing secretRing = KeyringTestingHelper.readRingFromResource(
                "/test-keys/authenticate_multisub_with_revoked.asc");
        Assert.assertTrue("Test key should be a secret key", secretRing.isSecret());

        SaveKeyringResult result = repo.savePublicKeyRing(secretRing);
        Assert.assertFalse("savePublicKeyRing with secret ring should fail", result.success());
    }

    @Test
    public void testSaveSecretKeyRing_rejectPublicType() throws Exception {
        UncachedKeyRing publicRing = KeyringTestingHelper.readRingFromResource(
                "/test-keys/mailvelope_07_no_key_flags.asc");
        Assert.assertFalse("Test key should be a public key", publicRing.isSecret());

        SaveKeyringResult result = repo.saveSecretKeyRing(publicRing);
        Assert.assertFalse("saveSecretKeyRing with public ring should fail", result.success());
    }

    @Test
    public void testSavePublicKeyRing_updateExisting() throws Exception {
        UncachedKeyRing pubKey = KeyringTestingHelper.readRingFromResource(
                "/test-keys/mailvelope_07_no_key_flags.asc");
        long masterKeyId = pubKey.getMasterKeyId();

        // Save first time
        SaveKeyringResult firstSave = repo.savePublicKeyRing(pubKey);
        Assert.assertTrue("First save should succeed", firstSave.success());

        // Save same key again with forceRefresh — should be an update
        KeyWritableRepository freshRepo = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        UncachedKeyRing sameKey = KeyringTestingHelper.readRingFromResource(
                "/test-keys/mailvelope_07_no_key_flags.asc");
        SaveKeyringResult updateSave = freshRepo.savePublicKeyRing(sameKey, null, true);
        Assert.assertTrue("Update should succeed", updateSave.success());
        Assert.assertTrue("Update should report UPDATED flag", updateSave.updated());

        // Key should still be accessible
        KeyRepository readRepo = KeyRepository.create(RuntimeEnvironment.getApplication());
        Assert.assertNotNull("Key should still be accessible after update",
                readRepo.getCanonicalizedPublicKeyRing(masterKeyId));
    }

    /**
     * Helper to check if an OperationLog contains a specific LogType.
     */
    private boolean logContainsType(OperationLog log, LogType targetType) {
        for (LogEntryParcel entry : log) {
            if (entry.mType == targetType) {
                return true;
            }
        }
        return false;
    }
}
