/*
 * Copyright (C) 2017 Schurmann & Breitmoser GbR
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


import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;

import org.sufficientlysecure.keychain.Constants;
import org.sufficientlysecure.keychain.daos.KeyMetadataDao;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.keyimport.ParcelableKeyRing;
import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult;
import org.sufficientlysecure.keychain.pgp.Progressable;
import org.sufficientlysecure.keychain.service.ImportKeyringParcel;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.ui.util.KeyFormattingUtils;
import org.sufficientlysecure.keychain.util.Preferences;
import timber.log.Timber;


public class KeySyncOperation extends BaseReadWriteOperation<KeySyncParcel> {
    // time since last update after which a key should be updated again, in ms
    private static final long KEY_STALE_THRESHOLD_MILLIS =
            Constants.DEBUG_KEYSERVER_SYNC ? 1 : TimeUnit.DAYS.toMillis(7);
    // Time taken by Orbot before a new circuit is created
    private static final int ORBOT_CIRCUIT_TIMEOUT_SECONDS =
            Constants.DEBUG_KEYSERVER_SYNC ? 2 : (int) TimeUnit.MINUTES.toSeconds(10);

    private final KeyMetadataDao keyMetadataDao;
    private final Preferences preferences;

    public KeySyncOperation(Context context, KeyWritableRepository databaseInteractor,
            Progressable progressable, AtomicBoolean cancellationSignal) {
        this(context, databaseInteractor, progressable, cancellationSignal,
                KeyMetadataDao.create(context), Preferences.getPreferences(context));
    }

    @VisibleForTesting
    KeySyncOperation(Context context, KeyWritableRepository databaseInteractor,
            Progressable progressable, AtomicBoolean cancellationSignal,
            KeyMetadataDao keyMetadataDao, Preferences preferences) {
        super(context, databaseInteractor, progressable, cancellationSignal);

        this.keyMetadataDao = keyMetadataDao;
        this.preferences = preferences;
    }

    @NonNull
    @Override
    public ImportKeyResult execute(KeySyncParcel input, CryptoInputParcel cryptoInputParcel) {
        long staleKeyThreshold = resolveStaleThreshold(input.getRefreshAll());
        List<byte[]> staleKeyFingerprints =
                keyMetadataDao.getFingerprintsForKeysOlderThan(staleKeyThreshold, TimeUnit.MILLISECONDS);

        Timber.d("Keyserver sync: found %d stale keys", staleKeyFingerprints.size());

        List<ParcelableKeyRing> staleKeyParcelableKeyRings =
                fingerprintListToParcelableKeyRings(staleKeyFingerprints);

        if (checkCancelled()) {
            return new ImportKeyResult(OperationResult.RESULT_CANCELLED, new OperationResult.OperationLog());
        }

        if (staleKeyParcelableKeyRings.isEmpty()) {
            Timber.d("Keyserver sync: no stale keys to refresh");
            return new ImportKeyResult(OperationResult.RESULT_OK, new OperationResult.OperationLog());
        }

        boolean reinsertAll = input.getRefreshAll();

        if (shouldUseStaggeredUpdate(reinsertAll)) {
            return staggeredUpdate(staleKeyParcelableKeyRings, cryptoInputParcel);
        } else {
            return directUpdate(staleKeyParcelableKeyRings, cryptoInputParcel, reinsertAll);
        }
    }

    /**
     * Compute the stale-key timestamp threshold.
     *
     * @param refreshAll if true, all keys are considered stale (threshold = now)
     * @return epoch millis; keys last updated before this time are considered stale
     */
    @VisibleForTesting
    static long resolveStaleThreshold(boolean refreshAll) {
        long staleKeyThresholdMs = refreshAll ? 0 : KEY_STALE_THRESHOLD_MILLIS;
        return System.currentTimeMillis() - staleKeyThresholdMs;
    }

    /**
     * Decide whether to use staggered (parcimonie-style) update for Tor privacy.
     * Staggered updates are only used for periodic refresh (not refreshAll) when Tor is enabled.
     */
    @VisibleForTesting
    boolean shouldUseStaggeredUpdate(boolean refreshAll) {
        return !refreshAll && preferences.getParcelableProxy().isTorEnabled();
    }

    /**
     * Build an ImportKeyringParcel for the given key list using the preferred keyserver.
     */
    private ImportKeyringParcel buildImportInput(List<ParcelableKeyRing> keyList, boolean forceReinsert) {
        return ImportKeyringParcel.createImportKeyringParcel(
                keyList, preferences.getPreferredKeyserver(), forceReinsert);
    }

    /**
     * Convert a list of raw fingerprints to ParcelableKeyRing objects suitable for import.
     * Each ParcelableKeyRing is created with only the fingerprint set (no keyserver or bytes).
     */
    @VisibleForTesting
    static List<ParcelableKeyRing> fingerprintListToParcelableKeyRings(List<byte[]> staleKeyFingerprints) {
        ArrayList<ParcelableKeyRing> result = new ArrayList<>(staleKeyFingerprints.size());
        for (byte[] fingerprint : staleKeyFingerprints) {
            Timber.d("Keyserver sync: Updating %s", KeyFormattingUtils.beautifyKeyId(fingerprint));
            result.add(ParcelableKeyRing.createFromReference(fingerprint, null, null));
        }
        return result;
    }

    private ImportKeyResult directUpdate(List<ParcelableKeyRing> keyList, CryptoInputParcel cryptoInputParcel,
            boolean reinsertAll) {
        Timber.d("Starting normal update");
        ImportOperation importOp = new ImportOperation(mContext, mKeyWritableRepository, mProgressable, mCancelled);
        return importOp.execute(
                buildImportInput(keyList, reinsertAll),
                cryptoInputParcel
        );
    }


    /**
     * will perform a staggered update of user's keys using delays to ensure new Tor circuits, as
     * performed by parcimonie. Relevant issue and method at:
     * https://github.com/open-keychain/open-keychain/issues/1337
     *
     * @return result of the sync
     */
    private ImportKeyResult staggeredUpdate(List<ParcelableKeyRing> keyList,
            CryptoInputParcel cryptoInputParcel) {
        Timber.d("Starting staggered update");
        // final int WEEK_IN_SECONDS = (int) TimeUnit.DAYS.toSeconds(7);
        // we are limiting our randomness to ORBOT_CIRCUIT_TIMEOUT_SECONDS for now
        final int WEEK_IN_SECONDS = 0;

        ImportOperation.KeyImportAccumulator accumulator
                = new ImportOperation.KeyImportAccumulator(keyList.size(), null);

        // so that the first key can be updated without waiting. This is so that there isn't a
        // large gap between a "Start Orbot" notification and the next key update
        boolean first = true;

        for (ParcelableKeyRing keyRing : keyList) {
            int waitTime;
            int staggeredTime = new Random().nextInt(1 + 2 * (WEEK_IN_SECONDS / keyList.size()));
            if (staggeredTime >= ORBOT_CIRCUIT_TIMEOUT_SECONDS) {
                waitTime = staggeredTime;
            } else {
                waitTime = ORBOT_CIRCUIT_TIMEOUT_SECONDS
                        + new Random().nextInt(1 + ORBOT_CIRCUIT_TIMEOUT_SECONDS);
            }

            if (first) {
                waitTime = 0;
                first = false;
            }

            Timber.d("Updating key with a wait time of %d seconds", waitTime);
            try {
                Thread.sleep(waitTime * 1000L);
            } catch (InterruptedException e) {
                Timber.e(e, "Exception during sleep between key updates");
                // skip this one
                continue;
            }
            ArrayList<ParcelableKeyRing> keyWrapper = new ArrayList<>();
            keyWrapper.add(keyRing);
            if (checkCancelled()) {
                return new ImportKeyResult(ImportKeyResult.RESULT_CANCELLED,
                new OperationResult.OperationLog());
            }
            ImportKeyResult result =
                    new ImportOperation(mContext, mKeyWritableRepository, null, mCancelled)
                            .execute(
                                    buildImportInput(keyWrapper, false),
                                    cryptoInputParcel
                            );
            if (result.isPending()) {
                return result;
            }
            accumulator.accumulateKeyImport(result);
        }
        return accumulator.getConsolidatedResult();
    }

}
