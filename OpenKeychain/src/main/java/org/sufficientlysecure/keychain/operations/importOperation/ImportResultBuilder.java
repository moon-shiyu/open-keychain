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


import java.util.ArrayList;

import org.sufficientlysecure.keychain.daos.KeyMetadataDao;
import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogType;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.pgp.CanonicalizedKeyRing;
import org.sufficientlysecure.keychain.ui.util.KeyFormattingUtils;


/**
 * Accumulates import counters and computes the result-type bitmask for
 * {@link ImportKeyResult}. This is the single source of truth for the
 * bitmask logic that was previously duplicated between the serial import
 * loop and {@link org.sufficientlysecure.keychain.operations.ImportOperation.KeyImportAccumulator}.
 *
 * <p>Two usage modes:
 * <ul>
 *   <li><b>Direct recording</b> — the serial import loop calls
 *       {@link #recordNewKey}, {@link #recordUpdatedKey}, {@link #recordBadKey},
 *       {@link #recordMissingKey} as it processes each key.</li>
 *   <li><b>Accumulation</b> — the multi-threaded accumulator calls
 *       {@link #accumulateFrom(ImportKeyResult)} to sum counters from
 *       individual per-key results.</li>
 * </ul>
 *
 * <p>The {@code addSummaryLogEntries} flag controls whether
 * {@link #addFinalLog} emits {@code MSG_IMPORT_SUCCESS} /
 * {@code MSG_IMPORT_PARTIAL} / {@code MSG_IMPORT_ERROR} entries. The serial
 * path emits these; the accumulator does not because each sub-result already
 * carries its own summary.
 */
public class ImportResultBuilder {

    private final boolean addSummaryLogEntries;

    private int newKeys = 0;
    private int updatedKeys = 0;
    private int missingKeys = 0;
    private int badKeys = 0;
    private int secretCount = 0;

    /**
     * Master key IDs of newly imported secret keys. Only populated in the
     * serial (direct recording) path — used for trust DB consolidation.
     */
    private final ArrayList<Long> secretMasterKeyIds = new ArrayList<>();
    private final ArrayList<Long> importedMasterKeyIds = new ArrayList<>();
    private final ArrayList<CanonicalizedKeyRing> canonicalizedKeyRings = new ArrayList<>();

    /**
     * @param addSummaryLogEntries {@code true} for the serial path (emits
     *        MSG_IMPORT_SUCCESS/PARTIAL/ERROR); {@code false} for the
     *        multi-threaded accumulator (each sub-result already has its own).
     */
    public ImportResultBuilder(boolean addSummaryLogEntries) {
        this.addSummaryLogEntries = addSummaryLogEntries;
    }

    // --- Direct recording methods (serial path) ---

    /** Records a newly imported key (not an update of an existing one). */
    public void recordNewKey(long masterKeyId, boolean isSecret) {
        newKeys += 1;
        if (isSecret) {
            secretCount += 1;
            secretMasterKeyIds.add(masterKeyId);
        }
        importedMasterKeyIds.add(masterKeyId);
    }

    /** Records an update to an already-existing key. */
    public void recordUpdatedKey(long masterKeyId) {
        updatedKeys += 1;
        importedMasterKeyIds.add(masterKeyId);
    }

    /** Records a key that failed to import (corrupt, invalid, fetch error, etc.). */
    public void recordBadKey() {
        badKeys += 1;
    }

    /**
     * Records a key that was not found on keyservers.
     * Also renews the key's last-updated timestamp in the metadata DAO
     * if a fingerprint is available.
     */
    public void recordMissingKey(byte[] fingerprintHex, KeyMetadataDao dao) {
        missingKeys += 1;
        if (fingerprintHex != null && dao != null) {
            dao.renewKeyLastUpdatedTime(
                    KeyFormattingUtils.getKeyIdFromFingerprint(fingerprintHex), false);
        }
    }

    // --- Accumulation method (multi-threaded path) ---

    /**
     * Sums all counters and master-key IDs from a completed per-key
     * {@link ImportKeyResult} into this builder's running totals.
     */
    public void accumulateFrom(ImportKeyResult result) {
        newKeys += result.mNewKeys;
        updatedKeys += result.mUpdatedKeys;
        missingKeys += result.mMissingKeys;
        badKeys += result.mBadKeys;
        secretCount += result.mSecret;
        for (long masterKeyId : result.getImportedMasterKeyIds()) {
            importedMasterKeyIds.add(masterKeyId);
        }
        if (result.mCanonicalizedKeyRings != null) {
            canonicalizedKeyRings.addAll(result.mCanonicalizedKeyRings);
        }
    }

    // --- Log helpers ---

    /** Adds the initial MSG_IMPORT log entry at indent 0. */
    public void addImportStartLog(OperationLog log, int numKeys) {
        log.add(LogType.MSG_IMPORT, 0, numKeys);
    }

    /**
     * Adds the final summary log entry. For the serial path, this emits
     * MSG_IMPORT_SUCCESS, MSG_IMPORT_PARTIAL, or MSG_IMPORT_ERROR. For the
     * accumulator path, this is a no-op.
     *
     * @param cancelled whether the operation was cancelled
     */
    public void addFinalLog(OperationLog log, boolean cancelled) {
        if (!cancelled && addSummaryLogEntries) {
            if ((newKeys > 0 || updatedKeys > 0) && badKeys > 0) {
                log.add(LogType.MSG_IMPORT_PARTIAL, 1);
            } else if (newKeys > 0 || updatedKeys > 0) {
                log.add(LogType.MSG_IMPORT_SUCCESS, 1);
            } else {
                log.add(LogType.MSG_IMPORT_ERROR, 1);
            }
        }
    }

    // --- Accessors for orchestration ---

    /** Returns the list of master key IDs of newly imported secret keys (for trust DB consolidation). */
    public ArrayList<Long> getSecretMasterKeyIds() {
        return secretMasterKeyIds;
    }

    /**
     * Returns the mutable list of canonicalized key rings. The save methods
     * populate this list as a side effect, so the orchestrator passes this
     * reference to the saver.
     */
    public ArrayList<CanonicalizedKeyRing> getCanonicalizedKeyRings() {
        return canonicalizedKeyRings;
    }

    /** Returns the total number of secret keys (new imports). */
    public int getSecretCount() {
        return secretCount;
    }

    public boolean hasAnyGoodKeys() {
        return newKeys > 0 || updatedKeys > 0;
    }

    // --- Build ---

    /**
     * Computes the result-type bitmask and constructs an {@link ImportKeyResult}.
     *
     * @param resultTypeExtra extra bits to OR into the result type before
     *        bitmask computation (typically {@code RESULT_CANCELLED} if the
     *        operation was cancelled, or 0).
     * @param log the operation log to include in the result.
     * @return the fully constructed {@link ImportKeyResult}.
     */
    public ImportKeyResult build(int resultTypeExtra, OperationLog log) {
        int resultType = computeResultType(resultTypeExtra, log);

        long[] importedMasterKeyIdsArray = new long[importedMasterKeyIds.size()];
        for (int i = 0; i < importedMasterKeyIds.size(); ++i) {
            importedMasterKeyIdsArray[i] = importedMasterKeyIds.get(i);
        }

        ImportKeyResult result = new ImportKeyResult(
                resultType, log,
                newKeys, updatedKeys, missingKeys, badKeys,
                getSecretCount(), importedMasterKeyIdsArray);

        result.setCanonicalizedKeyRings(canonicalizedKeyRings);
        return result;
    }

    /**
     * Centralized bitmask computation. This is the single source of truth
     * for the result-type flags on {@link ImportKeyResult}.
     */
    private int computeResultType(int resultTypeExtra, OperationLog log) {
        int resultType = resultTypeExtra;

        boolean wasCancelled = (resultTypeExtra & ImportKeyResult.RESULT_CANCELLED)
                == ImportKeyResult.RESULT_CANCELLED;

        // special return case: no new keys at all
        if (badKeys == 0 && newKeys == 0 && updatedKeys == 0 && !wasCancelled) {
            // if keys merely aren't on keyservers, it's just a warning
            resultType = ImportKeyResult.RESULT_FAIL_NOTHING;
        } else {
            if (newKeys > 0) {
                resultType |= ImportKeyResult.RESULT_OK_NEWKEYS;
            }
            if (updatedKeys > 0) {
                resultType |= ImportKeyResult.RESULT_OK_UPDATED;
            }
            if (badKeys > 0) {
                resultType |= ImportKeyResult.RESULT_WITH_ERRORS;
                if (newKeys == 0 && updatedKeys == 0) {
                    resultType |= ImportKeyResult.RESULT_ERROR;
                }
            }
            if (log.containsWarnings()) {
                resultType |= ImportKeyResult.RESULT_WARNINGS;
            }
        }

        return resultType;
    }
}
