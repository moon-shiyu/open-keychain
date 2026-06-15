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

package org.sufficientlysecure.keychain.remote;


import android.content.Context;
import android.content.Intent;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.openintents.openpgp.util.OpenPgpApi;
import org.robolectric.RuntimeEnvironment;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;


/**
 * Verifies the {@link RemoteCryptoInputHelper} crypto-input boundary shared by the
 * sign/encrypt/decrypt and SSH-authenticate paths: the {@code seedDate} flag controls whether a
 * freshly created parcel carries a signature time, and an API-supplied passphrase is applied only
 * when present.
 */
@RunWith(KeychainTestRunner.class)
public class RemoteCryptoInputHelperTest {

    private final Context context = RuntimeEnvironment.getApplication();

    /**
     * A non-empty Intent that carries no {@code EXTRA_CALL_UUID1/2}, so the cache lookup in
     * {@link CryptoInputParcelCacheService#getCryptoInputParcel} is a guaranteed miss without
     * tripping its {@code getExtras()}-is-null path.
     */
    private static Intent intentWithoutCacheTicket() {
        Intent intent = new Intent();
        intent.putExtra("test_marker", true);
        return intent;
    }

    @Test
    public void getOrCreate_cacheMiss_seedDateTrue_setsSignatureTime() {
        CryptoInputParcel parcel =
                RemoteCryptoInputHelper.getOrCreate(context, intentWithoutCacheTicket(), true);

        assertNotNull(parcel);
        assertNotNull(parcel.getSignatureTime());
    }

    @Test
    public void getOrCreate_cacheMiss_seedDateFalse_hasNoSignatureTime() {
        CryptoInputParcel parcel =
                RemoteCryptoInputHelper.getOrCreate(context, intentWithoutCacheTicket(), false);

        assertNotNull(parcel);
        assertNull(parcel.getSignatureTime());
    }

    @Test
    public void applyPassphraseIfPresent_withPassphrase_setsPassphrase() {
        CryptoInputParcel input = CryptoInputParcel.createCryptoInputParcel();
        Intent data = new Intent();
        data.putExtra(OpenPgpApi.EXTRA_PASSPHRASE, "secret".toCharArray());

        CryptoInputParcel result = RemoteCryptoInputHelper.applyPassphraseIfPresent(input, data);

        assertNotNull(result.getPassphrase());
    }

    @Test
    public void applyPassphraseIfPresent_withoutPassphrase_isNoOp() {
        CryptoInputParcel input = CryptoInputParcel.createCryptoInputParcel();
        Intent data = new Intent();

        CryptoInputParcel result = RemoteCryptoInputHelper.applyPassphraseIfPresent(input, data);

        assertSame(input, result);
        assertNull(result.getPassphrase());
    }
}
