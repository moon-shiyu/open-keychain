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
import org.sufficientlysecure.keychain.operations.importOperation.ImportKeyResolver;
import org.sufficientlysecure.keychain.operations.importOperation.ImportKeyResolver.ResolvedKey;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.pgp.PgpKeyOperation;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.operations.results.PgpEditKeyResult;
import org.sufficientlysecure.keychain.service.ChangeUnlockParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;
import org.sufficientlysecure.keychain.util.ParcelableProxy;
import org.sufficientlysecure.keychain.util.Passphrase;
import org.sufficientlysecure.keychain.util.TestingUtils;


/**
 * Tests for {@link ImportKeyResolver} — verifies key resolution from bytes
 * and error handling for fetch failures.
 *
 * <p>Note: Keyserver and Facebook fetch tests require a network-mock
 * infrastructure. These tests cover the byte-decode path and the
 * null/missing-entry paths that don't require network mocks.
 */
@RunWith(KeychainTestRunner.class)
public class ImportKeyResolverTest {

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
        builder.addUserId("test@example.com");
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(mKeyPhrase));

        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        Assert.assertTrue("key creation must succeed", result.success());
        mStaticRing = result.getRing();
    }

    @Before
    public void setUp() {
        ShadowLog.stream = oldShadowStream;
    }

    @Test
    public void resolve_fromBytes_shouldReturnKeyNotDownloaded() throws Exception {
        ImportKeyResolver resolver = new ImportKeyResolver();
        byte[] encoded = mStaticRing.getEncoded();
        ParcelableKeyRing entry = ParcelableKeyRing.createFromEncodedBytes(encoded);
        OperationLog log = new OperationLog();

        ResolvedKey resolved = resolver.resolve(entry, null,
                ParcelableProxy.getForNoProxy(), log);

        Assert.assertNotNull("key should be resolved from bytes", resolved);
        Assert.assertFalse("should not be marked as downloaded", resolved.wasDownloaded);
        Assert.assertNotNull("key should not be null", resolved.key);
    }

    @Test
    public void resolve_fromBytes_invalidData_shouldReturnNull() throws Exception {
        ImportKeyResolver resolver = new ImportKeyResolver();
        byte[] badData = new byte[]{0x01, 0x02, 0x03};
        ParcelableKeyRing entry = ParcelableKeyRing.createFromEncodedBytes(badData);
        OperationLog log = new OperationLog();

        try {
            ResolvedKey resolved = resolver.resolve(entry, null,
                    ParcelableProxy.getForNoProxy(), log);
            // If no exception, should be null (decode failure)
            Assert.assertNull("invalid bytes should not resolve", resolved);
        } catch (Exception e) {
            // IOException or PgpGeneralException from decodeFromData is also acceptable
            // as the caller wraps in try-catch
        }
    }

    @Test
    public void resolve_referenceWithoutKeyserver_shouldReturnNull() throws Exception {
        ImportKeyResolver resolver = new ImportKeyResolver();
        // Create a reference entry with no keyserver (null keyserver) and no fbUsername
        ParcelableKeyRing entry = ParcelableKeyRing.createFromReference(
                null, "0xDEADBEEF", null);
        OperationLog log = new OperationLog();

        ResolvedKey resolved = resolver.resolve(entry, null,
                ParcelableProxy.getForNoProxy(), log);

        Assert.assertNull("reference without keyserver should not resolve", resolved);
    }
}
