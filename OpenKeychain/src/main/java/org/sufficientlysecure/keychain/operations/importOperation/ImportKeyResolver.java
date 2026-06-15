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

package org.sufficientlysecure.keychain.operations.importOperation;


import java.io.IOException;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import org.sufficientlysecure.keychain.keyimport.FacebookKeyserverClient;
import org.sufficientlysecure.keychain.keyimport.HkpKeyserverAddress;
import org.sufficientlysecure.keychain.keyimport.HkpKeyserverClient;
import org.sufficientlysecure.keychain.keyimport.KeyserverClient;
import org.sufficientlysecure.keychain.keyimport.KeyserverClient.QueryNotFoundException;
import org.sufficientlysecure.keychain.keyimport.ParcelableKeyRing;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogType;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.pgp.exception.PgpGeneralException;
import org.sufficientlysecure.keychain.ui.util.KeyFormattingUtils;
import org.sufficientlysecure.keychain.util.ParcelableProxy;
import timber.log.Timber;


/**
 * Resolves a {@link ParcelableKeyRing} into an {@link UncachedKeyRing} by
 * decoding embedded bytes or fetching from keyservers / Facebook.
 *
 * <p>Extracted from {@code ImportOperation} to isolate the network / decoding
 * concern from the orchestration loop.
 */
public class ImportKeyResolver {

    private FacebookKeyserverClient facebookServer;

    /**
     * Holds the result of resolving a key: the decoded key ring and whether
     * it was downloaded from the internet (as opposed to decoded from
     * embedded bytes).
     */
    public static class ResolvedKey {
        @NonNull
        public final UncachedKeyRing key;
        public final boolean wasDownloaded;

        public ResolvedKey(@NonNull UncachedKeyRing key, boolean wasDownloaded) {
            this.key = key;
            this.wasDownloaded = wasDownloaded;
        }
    }

    /**
     * Resolves a {@link ParcelableKeyRing} to an {@link UncachedKeyRing}.
     *
     * <p>If the entry contains embedded bytes, decodes them directly.
     * Otherwise, fetches from the keyserver and/or Facebook, merging if both
     * sources return keys.
     *
     * @return a {@link ResolvedKey} if the key was successfully resolved, or
     *         {@code null} if the key could not be obtained (network errors,
     *         decode failures).
     * @throws QueryNotFoundException if the key was explicitly not found on
     *         keyservers (caller should treat as "missing", not "bad").
     */
    @Nullable
    public ResolvedKey resolve(ParcelableKeyRing entry,
            HkpKeyserverAddress keyserver, @NonNull ParcelableProxy proxy,
            OperationLog log) throws QueryNotFoundException, PgpGeneralException, IOException {

        // If there is already byte data, use that
        if (entry.getBytes() != null) {
            UncachedKeyRing key = UncachedKeyRing.decodeFromData(entry.getBytes());
            if (key != null) {
                return new ResolvedKey(key, false);
            }
            return null;
        }

        // Otherwise fetch from the internet
        UncachedKeyRing key = fetchKeyFromInternet(keyserver, proxy, log, entry);
        if (key != null) {
            return new ResolvedKey(key, true);
        }
        return null;
    }

    private UncachedKeyRing fetchKeyFromInternet(HkpKeyserverAddress hkpKeyserver,
            @NonNull ParcelableProxy proxy, OperationLog log,
            ParcelableKeyRing entry)
            throws PgpGeneralException, IOException, QueryNotFoundException {
        QueryNotFoundException queryNotFoundException = null;
        UncachedKeyRing key = null;

        boolean canFetchFromKeyservers =
                hkpKeyserver != null && (entry.getKeyIdHex() != null || entry.getExpectedFingerprint() != null);
        if (canFetchFromKeyservers) {
            UncachedKeyRing keyserverKey = null;
            try {
                keyserverKey = fetchKeyFromKeyserver(hkpKeyserver, proxy, log, entry);
            } catch (QueryNotFoundException e) {
                queryNotFoundException = e;
            }

            if (keyserverKey != null) {
                key = keyserverKey;
            }
        }

        boolean hasFacebookName = entry.getFbUsername() != null;
        if (hasFacebookName) {
            UncachedKeyRing facebookKey = fetchKeyFromFacebook(proxy, log, entry);
            if (facebookKey != null) {
                key = mergeKeysOrUseEither(log, 3, key, facebookKey);
            }
        }

        if (key == null && queryNotFoundException != null) {
            throw queryNotFoundException;
        }

        return key;
    }

    @Nullable
    private UncachedKeyRing fetchKeyFromKeyserver(HkpKeyserverAddress hkpKeyserver,
            @NonNull ParcelableProxy proxy, OperationLog log,
            ParcelableKeyRing entry)
            throws PgpGeneralException, IOException, KeyserverClient.QueryNotFoundException {
        try {
            byte[] data;
            log.add(LogType.MSG_IMPORT_KEYSERVER, 1, hkpKeyserver);

            HkpKeyserverClient keyserverInteractor = createHkpKeyserverClient(hkpKeyserver);

            // Download by fingerprint, or keyId - whichever is available
            if (entry.getExpectedFingerprint() != null) {
                String fingerprintHex = KeyFormattingUtils.convertFingerprintToHex(entry.getExpectedFingerprint());
                log.add(LogType.MSG_IMPORT_FETCH_KEYSERVER, 2, "0x" +
                        fingerprintHex.substring(24));
                data = keyserverInteractor.get("0x" + fingerprintHex, proxy).getBytes();
            } else {
                log.add(LogType.MSG_IMPORT_FETCH_KEYSERVER, 2, entry.getKeyIdHex());
                data = keyserverInteractor.get(entry.getKeyIdHex(), proxy).getBytes();
            }
            UncachedKeyRing keyserverKey = UncachedKeyRing.decodeFromData(data);
            if (keyserverKey != null) {
                log.add(LogType.MSG_IMPORT_FETCH_KEYSERVER_OK, 3);
            } else {
                log.add(LogType.MSG_IMPORT_FETCH_ERROR_DECODE, 3);
            }

            return keyserverKey;
        } catch (KeyserverClient.QueryNotFoundException e) {
            throw e;
        } catch (KeyserverClient.QueryFailedException e) {
            Timber.d(e, "query failed");
            log.add(LogType.MSG_IMPORT_FETCH_ERROR_KEYSERVER, 3, e.getMessage());
            return null;
        }
    }

    private UncachedKeyRing fetchKeyFromFacebook(@NonNull ParcelableProxy proxy,
            OperationLog log, ParcelableKeyRing entry)
            throws PgpGeneralException, IOException {
        if (facebookServer == null) {
            facebookServer = FacebookKeyserverClient.getInstance();
        }

        try {
            log.add(LogType.MSG_IMPORT_FETCH_FACEBOOK, 2, entry.getFbUsername());
            byte[] data = facebookServer.get(entry.getFbUsername(), proxy).getBytes();
            UncachedKeyRing facebookKey = UncachedKeyRing.decodeFromData(data);

            if (facebookKey != null) {
                log.add(LogType.MSG_IMPORT_FETCH_KEYSERVER_OK, 3);
            } else {
                log.add(LogType.MSG_IMPORT_FETCH_ERROR_DECODE, 3);
            }

            return facebookKey;
        } catch (KeyserverClient.QueryFailedException e) {
            // download failed, too bad. just proceed
            Timber.e(e, "query failed");
            log.add(LogType.MSG_IMPORT_FETCH_ERROR_KEYSERVER, 3, e.getMessage());
            return null;
        }
    }

    @Nullable
    private UncachedKeyRing mergeKeysOrUseEither(OperationLog log, int indent,
            UncachedKeyRing firstKey, UncachedKeyRing otherKey) {
        if (firstKey == null) {
            return otherKey;
        }

        log.add(LogType.MSG_IMPORT_MERGE, indent);
        UncachedKeyRing mergedKey = firstKey.merge(otherKey, log, indent + 1);

        if (mergedKey != null) {
            return mergedKey;
        } else {
            log.add(LogType.MSG_IMPORT_MERGE_ERROR, indent + 1);
            return firstKey;
        }
    }

    /**
     * Factory method for creating HkpKeyserverClient instances. Package-private
     * to allow test subclasses to override.
     */
    HkpKeyserverClient createHkpKeyserverClient(HkpKeyserverAddress hkpKeyserver) {
        return HkpKeyserverClient.fromHkpKeyserverAddress(hkpKeyserver);
    }
}
