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


import java.util.Date;

import android.content.Context;
import android.content.Intent;

import androidx.annotation.NonNull;
import org.openintents.openpgp.util.OpenPgpApi;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.util.Passphrase;


/**
 * Helpers for obtaining the {@link CryptoInputParcel} that backs a remote API request.
 *
 * <p>A {@code CryptoInputParcel} is either retrieved from {@link CryptoInputParcelCacheService}
 * (when the request is a re-execution after user interaction — the cache ticket travels on the
 * request Intent as {@link OpenPgpApi#EXTRA_CALL_UUID1}/{@link OpenPgpApi#EXTRA_CALL_UUID2}), or a
 * fresh one is created. The behaviour matches the previous inline code; callers control whether a
 * fresh parcel is seeded with a creation {@link Date} so the two existing variants are preserved.
 */
final class RemoteCryptoInputHelper {

    private RemoteCryptoInputHelper() {
    }

    /**
     * Returns the cached {@link CryptoInputParcel} for this request, or a fresh one on a cache miss.
     *
     * @param seedDate {@code true} to seed a fresh parcel with the current {@link Date} (as the
     *                 sign/encrypt and SSH-authenticate paths do); {@code false} for an empty fresh
     *                 parcel (as the decrypt path does).
     */
    @NonNull
    static CryptoInputParcel getOrCreate(Context context, Intent data, boolean seedDate) {
        CryptoInputParcel cryptoInput = CryptoInputParcelCacheService.getCryptoInputParcel(context, data);
        if (cryptoInput == null) {
            cryptoInput = seedDate
                    ? CryptoInputParcel.createCryptoInputParcel(new Date())
                    : CryptoInputParcel.createCryptoInputParcel();
        }
        return cryptoInput;
    }

    /**
     * Overrides the passphrase in {@code cryptoInput} when the API call supplied one via
     * {@link OpenPgpApi#EXTRA_PASSPHRASE}; otherwise returns {@code cryptoInput} unchanged.
     */
    @NonNull
    static CryptoInputParcel applyPassphraseIfPresent(@NonNull CryptoInputParcel cryptoInput, Intent data) {
        if (data.hasExtra(OpenPgpApi.EXTRA_PASSPHRASE)) {
            return cryptoInput.withPassphrase(
                    new Passphrase(data.getCharArrayExtra(OpenPgpApi.EXTRA_PASSPHRASE)), null);
        }
        return cryptoInput;
    }
}
