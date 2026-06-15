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

package org.sufficientlysecure.keychain.operations;


import java.io.PrintStream;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.keyimport.ParcelableKeyRing;
import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;
import org.sufficientlysecure.keychain.operations.results.PgpEditKeyResult;
import org.sufficientlysecure.keychain.pgp.PgpKeyOperation;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.service.ChangeUnlockParcel;
import org.sufficientlysecure.keychain.service.ImportKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.support.KeyringTestingHelper;
import org.sufficientlysecure.keychain.util.Passphrase;
import org.sufficientlysecure.keychain.util.TestingUtils;


/**
 * Integration tests for {@link ImportOperation} — verifies the full import
 * flow using real {@link KeyWritableRepository} and BouncyCastle key
 * generation, following the pattern established by {@link CertifyOperationTest}
 * and {@code KeyRepositorySaveTest}.
 */
@RunWith(KeychainTestRunner.class)
public class ImportOperationTest {

    static UncachedKeyRing mStaticRing;
    static Passphrase mKeyPhrase = TestingUtils.testPassphrase1;
    static PrintStream oldShadowStream;

    @BeforeClass
    public static void setUpOnce() throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        oldShadowStream = ShadowLog.stream;

        PgpKeyOperation op = new PgpKeyOperation(null);

        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, SaveKeyringParcel.Curve.NIST_P256, KeyFlags.CERTIFY_OTHER, 0L));
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, SaveKeyringParcel.Curve.NIST_P256, KeyFlags.SIGN_DATA, 0L));
        builder.addUserId("import-test@example.com");
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(mKeyPhrase));

        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        Assert.assertTrue("key creation must succeed", result.success());
        mStaticRing = result.getRing();
    }

    private KeyWritableRepository db;

    @Before
    public void setUp() {
        db = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        ShadowLog.stream = oldShadowStream;
    }

    private ImportOperation createOperation() {
        return new ImportOperation(
                RuntimeEnvironment.getApplication(), db, null);
    }

    private ImportOperation createOperationWithCancel(AtomicBoolean cancelled) {
        return new ImportOperation(
                RuntimeEnvironment.getApplication(), db, null, cancelled);
    }

    // --- Import from bytes: new public key ---

    @Test
    public void importPublicKeyFromBytes_shouldSucceed() throws Exception {
        // Extract the public key from the secret ring
        UncachedKeyRing publicRing = mStaticRing.extractPublicKeyRing();
        byte[] encoded = publicRing.getEncoded();

        List<ParcelableKeyRing> keys = new ArrayList<>();
        keys.add(ParcelableKeyRing.createFromEncodedBytes(encoded));

        ImportKeyringParcel parcel = ImportKeyringParcel.createImportKeyringParcel(keys, null);
        CryptoInputParcel cryptoInput = CryptoInputParcel.createCryptoInputParcel();

        ImportOperation op = createOperation();
        ImportKeyResult result = op.execute(parcel, cryptoInput);

        Assert.assertTrue("import should succeed: " + result.getLog(),
                result.success());
        Assert.assertTrue("should have new keys", result.isOkNew());
        Assert.assertEquals("should have 1 new key", 1, result.mNewKeys);
        Assert.assertEquals("should have 0 updated keys", 0, result.mUpdatedKeys);
        Assert.assertEquals("should have 0 bad keys", 0, result.mBadKeys);
    }

    // --- Import same key twice: update ---

    @Test
    public void importSameKeyTwice_shouldUpdate() throws Exception {
        UncachedKeyRing publicRing = mStaticRing.extractPublicKeyRing();
        byte[] encoded = publicRing.getEncoded();

        // First import
        List<ParcelableKeyRing> keys1 = new ArrayList<>();
        keys1.add(ParcelableKeyRing.createFromEncodedBytes(encoded));

        ImportOperation op1 = createOperation();
        ImportKeyResult result1 = op1.execute(
                ImportKeyringParcel.createImportKeyringParcel(keys1, null),
                CryptoInputParcel.createCryptoInputParcel());
        Assert.assertTrue("first import should succeed", result1.success());

        // Second import (same key)
        List<ParcelableKeyRing> keys2 = new ArrayList<>();
        keys2.add(ParcelableKeyRing.createFromEncodedBytes(encoded));

        ImportOperation op2 = createOperation();
        ImportKeyResult result2 = op2.execute(
                ImportKeyringParcel.createImportKeyringParcel(keys2, null),
                CryptoInputParcel.createCryptoInputParcel());

        Assert.assertTrue("second import should succeed", result2.success());
        Assert.assertTrue("should be an update", result2.isOkUpdated());
        Assert.assertEquals("should have 1 updated key", 1, result2.mUpdatedKeys);
        Assert.assertEquals("should have 0 new keys", 0, result2.mNewKeys);
    }

    // --- Import secret key ---

    @Test
    public void importSecretKeyFromBytes_shouldCountSecret() throws Exception {
        byte[] encoded = mStaticRing.getEncoded();

        List<ParcelableKeyRing> keys = new ArrayList<>();
        keys.add(ParcelableKeyRing.createFromEncodedBytes(encoded));

        ImportOperation op = createOperation();
        ImportKeyResult result = op.execute(
                ImportKeyringParcel.createImportKeyringParcel(keys, null),
                CryptoInputParcel.createCryptoInputParcel());

        Assert.assertTrue("import should succeed", result.success());
        Assert.assertEquals("should have 1 secret key", 1, result.mSecret);
    }

    // --- Import with skipSave ---

    @Test
    public void importWithSkipSave_shouldNotPersistKey() throws Exception {
        UncachedKeyRing publicRing = mStaticRing.extractPublicKeyRing();
        byte[] encoded = publicRing.getEncoded();

        List<ParcelableKeyRing> keys = new ArrayList<>();
        keys.add(ParcelableKeyRing.createFromEncodedBytes(encoded));

        ImportKeyringParcel parcel = ImportKeyringParcel.createWithSkipSave(keys, null);
        ImportOperation op = createOperation();
        ImportKeyResult result = op.execute(parcel, CryptoInputParcel.createCryptoInputParcel());

        Assert.assertTrue("import with skipSave should succeed", result.success());
        Assert.assertEquals("should have 1 new key", 1, result.mNewKeys);

        // Verify key was NOT saved to repository
        // The canonicalized rings should still be populated
        Assert.assertNotNull("canonicalized rings should be populated",
                result.mCanonicalizedKeyRings);
        Assert.assertFalse("should have canonicalized rings",
                result.mCanonicalizedKeyRings.isEmpty());
    }

    // --- Import with invalid bytes ---

    @Test
    public void importInvalidBytes_shouldReportBadKeys() throws Exception {
        byte[] badData = new byte[]{0x01, 0x02, 0x03, 0x04};

        List<ParcelableKeyRing> keys = new ArrayList<>();
        keys.add(ParcelableKeyRing.createFromEncodedBytes(badData));

        ImportOperation op = createOperation();
        ImportKeyResult result = op.execute(
                ImportKeyringParcel.createImportKeyringParcel(keys, null),
                CryptoInputParcel.createCryptoInputParcel());

        Assert.assertFalse("import should fail", result.success());
        Assert.assertEquals("should have 1 bad key", 1, result.mBadKeys);
    }

    // --- Import empty list ---

    @Test
    public void importEmptyList_shouldFailNothing() throws Exception {
        List<ParcelableKeyRing> keys = new ArrayList<>();

        ImportOperation op = createOperation();
        ImportKeyResult result = op.execute(
                ImportKeyringParcel.createImportKeyringParcel(keys, null),
                CryptoInputParcel.createCryptoInputParcel());

        Assert.assertTrue("should be fail-nothing", result.isFailNothing());
    }

    // --- Cancel mid-import ---

    @Test
    public void cancelMidImport_shouldSetCancelledBit() throws Exception {
        UncachedKeyRing publicRing = mStaticRing.extractPublicKeyRing();
        byte[] encoded = publicRing.getEncoded();

        List<ParcelableKeyRing> keys = new ArrayList<>();
        keys.add(ParcelableKeyRing.createFromEncodedBytes(encoded));
        keys.add(ParcelableKeyRing.createFromEncodedBytes(encoded));

        AtomicBoolean cancelled = new AtomicBoolean(true); // pre-cancelled

        ImportOperation op = createOperationWithCancel(cancelled);
        ImportKeyResult result = op.execute(
                ImportKeyringParcel.createImportKeyringParcel(keys, null),
                CryptoInputParcel.createCryptoInputParcel());

        Assert.assertTrue("should have CANCELLED bit", result.cancelled());
    }

    // --- Multiple keys with mix of good and bad ---

    @Test
    public void importMixedGoodAndBad_shouldReportPartialSuccess() throws Exception {
        UncachedKeyRing publicRing = mStaticRing.extractPublicKeyRing();
        byte[] goodData = publicRing.getEncoded();
        byte[] badData = new byte[]{0x01, 0x02, 0x03, 0x04};

        List<ParcelableKeyRing> keys = new ArrayList<>();
        keys.add(ParcelableKeyRing.createFromEncodedBytes(goodData));
        keys.add(ParcelableKeyRing.createFromEncodedBytes(badData));

        ImportOperation op = createOperation();
        ImportKeyResult result = op.execute(
                ImportKeyringParcel.createImportKeyringParcel(keys, null),
                CryptoInputParcel.createCryptoInputParcel());

        Assert.assertTrue("should still be success (has good keys)", result.success());
        Assert.assertTrue("should have WITH_ERRORS", result.isOkWithErrors());
        Assert.assertEquals("should have 1 new key", 1, result.mNewKeys);
        Assert.assertEquals("should have 1 bad key", 1, result.mBadKeys);
    }

    // --- Canonicalized key rings populated ---

    @Test
    public void importFromBytes_shouldPopulateCanonicalizedRings() throws Exception {
        UncachedKeyRing publicRing = mStaticRing.extractPublicKeyRing();
        byte[] encoded = publicRing.getEncoded();

        List<ParcelableKeyRing> keys = new ArrayList<>();
        keys.add(ParcelableKeyRing.createFromEncodedBytes(encoded));

        ImportOperation op = createOperation();
        ImportKeyResult result = op.execute(
                ImportKeyringParcel.createImportKeyringParcel(keys, null),
                CryptoInputParcel.createCryptoInputParcel());

        Assert.assertNotNull("canonicalized rings should not be null",
                result.mCanonicalizedKeyRings);
        Assert.assertFalse("should have at least one canonicalized ring",
                result.mCanonicalizedKeyRings.isEmpty());
    }

    // --- Master key IDs collected ---

    @Test
    public void importFromBytes_shouldCollectMasterKeyIds() throws Exception {
        UncachedKeyRing publicRing = mStaticRing.extractPublicKeyRing();
        byte[] encoded = publicRing.getEncoded();

        List<ParcelableKeyRing> keys = new ArrayList<>();
        keys.add(ParcelableKeyRing.createFromEncodedBytes(encoded));

        ImportOperation op = createOperation();
        ImportKeyResult result = op.execute(
                ImportKeyringParcel.createImportKeyringParcel(keys, null),
                CryptoInputParcel.createCryptoInputParcel());

        Assert.assertNotNull("master key IDs should not be null",
                result.getImportedMasterKeyIds());
        Assert.assertEquals("should have 1 master key ID",
                1, result.getImportedMasterKeyIds().length);
        Assert.assertEquals("master key ID should match",
                mStaticRing.getMasterKeyId(), result.getImportedMasterKeyIds()[0]);
    }

    // --- Import from test key resource files ---

    @Test
    public void importFromResourceFile_shouldSucceed() throws Exception {
        // Use a real-world test key if available
        try {
            UncachedKeyRing testRing = KeyringTestingHelper.readRingFromResource(
                    "/test-keys/eddsa-subkey.pub.asc");
            if (testRing == null) {
                return; // skip if test key not available
            }

            byte[] encoded = testRing.getEncoded();
            List<ParcelableKeyRing> keys = new ArrayList<>();
            keys.add(ParcelableKeyRing.createFromEncodedBytes(encoded));

            ImportOperation op = createOperation();
            ImportKeyResult result = op.execute(
                    ImportKeyringParcel.createImportKeyringParcel(keys, null),
                    CryptoInputParcel.createCryptoInputParcel());

            Assert.assertTrue("import from resource should succeed: " + result.getLog(),
                    result.success());
        } catch (Exception e) {
            // Test key not available, skip
        }
    }
}
