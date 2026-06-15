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


import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;

import android.content.Context;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.KeyMetadataDao;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.operations.results.PgpEditKeyResult;
import org.sufficientlysecure.keychain.pgp.PgpKeyOperation;
import org.sufficientlysecure.keychain.pgp.Progressable;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.service.ChangeUnlockParcel;
import org.sufficientlysecure.keychain.service.ImportKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.util.Passphrase;
import org.sufficientlysecure.keychain.util.TestingUtils;

/**
 * Unit tests for {@link KeySyncOperation}. The actual keyserver fetch is performed by a reused
 * {@link ImportOperation}; here it is replaced by a {@link CapturingImportOperation} via the
 * package-private factory seam so the branches can be exercised without any network access.
 *
 * <p>Covered branches: a successful import, a keyserver import failure, the "no key needs
 * refreshing" case, an already-cancelled operation, and the mapping from {@link KeySyncParcel}
 * onto the {@link ImportKeyringParcel} (preferred keyserver + force-reinsert flag).
 */
@RunWith(KeychainTestRunner.class)
public class KeySyncOperationTest {

    private static UncachedKeyRing staticRing;
    private static final Passphrase keyPhrase = TestingUtils.testPassphrase1;

    private Context context;
    private KeyWritableRepository keyRepository;
    private KeyMetadataDao keyMetadataDao;

    @BeforeClass
    public static void setUpOnce() throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        PgpKeyOperation op = new PgpKeyOperation(null);

        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, SaveKeyringParcel.Curve.NIST_P256, KeyFlags.CERTIFY_OTHER, 0L));
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, SaveKeyringParcel.Curve.NIST_P256, KeyFlags.SIGN_DATA, 0L));
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDH, 0, SaveKeyringParcel.Curve.NIST_P256, KeyFlags.ENCRYPT_COMMS, 0L));
        builder.addUserId("derp");
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(keyPhrase));

        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        Assert.assertTrue("initial test key creation must succeed", result.success());
        Assert.assertNotNull("initial test key creation must succeed", result.getRing());

        staticRing = result.getRing();
    }

    @Before
    public void setUp() {
        context = RuntimeEnvironment.getApplication();
        keyRepository = KeyWritableRepository.create(context);
        keyMetadataDao = KeyMetadataDao.create(context);

        // a single public key with no metadata row => "never updated" => always stale
        keyRepository.savePublicKeyRing(staticRing.extractPublicKeyRing(), null);
        // guarantee a stale starting point regardless of test execution order
        keyMetadataDao.resetAllLastUpdatedTimes();
    }

    @Test
    public void execute_success_isPropagated() {
        ImportKeyResult canned = new ImportKeyResult(
                ImportKeyResult.RESULT_OK_UPDATED, new OperationLog(), 0, 1, 0, 0, 0, new long[]{});
        CapturingImportOperation fake = new CapturingImportOperation(context, keyRepository, canned);

        KeySyncOperation keySync = new KeySyncOperation(context, keyRepository, null,
                new AtomicBoolean(false), (c, r, p, cancelled) -> fake);

        ImportKeyResult result = keySync.execute(KeySyncParcel.createRefreshOutdated(),
                CryptoInputParcel.createCryptoInputParcel());

        Assert.assertTrue("import operation must have been invoked", fake.wasCalled);
        Assert.assertSame("operation must return the import result unchanged", canned, result);
        Assert.assertTrue("result must be a success", result.success());
        Assert.assertFalse("a completed sync must not be pending", result.isPending());
        Assert.assertFalse("stale key list must be non-empty for an outdated key",
                fake.capturedParcel.getKeyList().isEmpty());
    }

    @Test
    public void execute_keyserverImportFailure_isPropagated() {
        ImportKeyResult canned = new ImportKeyResult(
                OperationResult.RESULT_ERROR | ImportKeyResult.RESULT_WITH_ERRORS,
                new OperationLog(), 0, 0, 0, 2, 0, new long[]{});
        CapturingImportOperation fake = new CapturingImportOperation(context, keyRepository, canned);

        KeySyncOperation keySync = new KeySyncOperation(context, keyRepository, null,
                new AtomicBoolean(false), (c, r, p, cancelled) -> fake);

        ImportKeyResult result = keySync.execute(KeySyncParcel.createRefreshOutdated(),
                CryptoInputParcel.createCryptoInputParcel());

        Assert.assertTrue("import operation must have been invoked", fake.wasCalled);
        Assert.assertFalse("an import failure must surface as a non-success result", result.success());
        Assert.assertEquals("bad key count must be propagated", 2, result.mBadKeys);
    }

    @Test
    public void execute_noKeyNeedsRefreshing_passesEmptyKeyList() {
        // mark the only key as freshly updated -> it is no longer stale
        keyMetadataDao.renewKeyLastUpdatedTime(staticRing.getMasterKeyId(), true);

        ImportKeyResult canned = new ImportKeyResult(
                ImportKeyResult.RESULT_FAIL_NOTHING, new OperationLog());
        CapturingImportOperation fake = new CapturingImportOperation(context, keyRepository, canned);

        KeySyncOperation keySync = new KeySyncOperation(context, keyRepository, null,
                new AtomicBoolean(false), (c, r, p, cancelled) -> fake);

        ImportKeyResult result = keySync.execute(KeySyncParcel.createRefreshOutdated(),
                CryptoInputParcel.createCryptoInputParcel());

        Assert.assertTrue("import operation is still invoked, with an empty work list", fake.wasCalled);
        Assert.assertTrue("no stale key must be scheduled for refresh",
                fake.capturedParcel.getKeyList().isEmpty());
        Assert.assertSame(canned, result);
    }

    @Test
    public void execute_alreadyCancelled_returnsCancelledWithoutImporting() {
        AtomicBoolean cancellationSignal = new AtomicBoolean(true);
        CapturingImportOperation fake = new CapturingImportOperation(context, keyRepository,
                new ImportKeyResult(ImportKeyResult.RESULT_OK_UPDATED, new OperationLog()));

        KeySyncOperation keySync = new KeySyncOperation(context, keyRepository, null,
                cancellationSignal, (c, r, p, cancelled) -> fake);

        ImportKeyResult result = keySync.execute(KeySyncParcel.createRefreshOutdated(),
                CryptoInputParcel.createCryptoInputParcel());

        Assert.assertFalse("import must not run once cancelled", fake.wasCalled);
        Assert.assertTrue("result must be flagged cancelled", result.cancelled());
        Assert.assertEquals(OperationResult.RESULT_CANCELLED, result.getResult());
    }

    @Test
    public void execute_refreshOutdated_doesNotForceReinsert() {
        ImportKeyringParcel captured = captureImportParcelFor(KeySyncParcel.createRefreshOutdated());

        Assert.assertFalse("a periodic refresh must not force-reinsert keys", captured.isForceReinsert());
        Assert.assertNotNull("the preferred keyserver must be supplied to the import", captured.getKeyserver());
    }

    @Test
    public void execute_refreshAll_forcesReinsert() {
        ImportKeyringParcel captured = captureImportParcelFor(KeySyncParcel.createRefreshAll());

        Assert.assertTrue("a full refresh must force-reinsert keys", captured.isForceReinsert());
        Assert.assertNotNull("the preferred keyserver must be supplied to the import", captured.getKeyserver());
    }

    private ImportKeyringParcel captureImportParcelFor(KeySyncParcel input) {
        CapturingImportOperation fake = new CapturingImportOperation(context, keyRepository,
                new ImportKeyResult(ImportKeyResult.RESULT_FAIL_NOTHING, new OperationLog()));

        KeySyncOperation keySync = new KeySyncOperation(context, keyRepository, null,
                new AtomicBoolean(false), (c, r, p, cancelled) -> fake);
        keySync.execute(input, CryptoInputParcel.createCryptoInputParcel());

        Assert.assertTrue("import operation must have been invoked", fake.wasCalled);
        return fake.capturedParcel;
    }

    /**
     * Stand-in for {@link ImportOperation} that records the {@link ImportKeyringParcel} it receives
     * and returns a canned {@link ImportKeyResult} instead of talking to a keyserver.
     */
    private static class CapturingImportOperation extends ImportOperation {
        private final ImportKeyResult cannedResult;
        boolean wasCalled;
        ImportKeyringParcel capturedParcel;

        CapturingImportOperation(Context context, KeyWritableRepository repository,
                ImportKeyResult cannedResult) {
            super(context, repository, (Progressable) null, null);
            this.cannedResult = cannedResult;
        }

        @Override
        public ImportKeyResult execute(ImportKeyringParcel input, CryptoInputParcel cryptoInput) {
            wasCalled = true;
            capturedParcel = input;
            return cannedResult;
        }
    }
}
