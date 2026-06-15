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


import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.daos.KeyMetadataDao;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.keyimport.FacebookKeyserverClient;
import org.sufficientlysecure.keychain.keyimport.HkpKeyserverAddress;
import org.sufficientlysecure.keychain.keyimport.HkpKeyserverClient;
import org.sufficientlysecure.keychain.keyimport.KeyserverClient;
import org.sufficientlysecure.keychain.keyimport.KeyserverClient.QueryNotFoundException;
import org.sufficientlysecure.keychain.keyimport.ParcelableKeyRing;
import org.sufficientlysecure.keychain.network.orbot.OrbotHelper;
import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogType;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.operations.results.SaveKeyringResult;
import org.sufficientlysecure.keychain.operations.results.UpdateTrustResult;
import org.sufficientlysecure.keychain.pgp.CanonicalizedKeyRing;
import org.sufficientlysecure.keychain.pgp.Progressable;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.pgp.exception.PgpGeneralException;
import org.sufficientlysecure.keychain.service.ImportKeyringParcel;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.service.input.RequiredInputParcel;
import org.sufficientlysecure.keychain.ui.util.KeyFormattingUtils;
import org.sufficientlysecure.keychain.util.IteratorWithSize;
import org.sufficientlysecure.keychain.util.ParcelableFileCache;
import org.sufficientlysecure.keychain.util.ParcelableProxy;
import org.sufficientlysecure.keychain.util.Preferences;
import org.sufficientlysecure.keychain.util.ProgressScaler;
import timber.log.Timber;


/**
 * An operation class which implements high level import
 * operations.
 * This class receives a source and/or destination of keys as input and performs
 * all steps for this import.
 * For the import operation, the only valid source is an Iterator of
 * ParcelableKeyRing, each of which must contain either a single
 * keyring encoded as bytes, or a unique reference to a keyring on keyservers.
 * It is important to note that public keys should generally be imported before
 * secret keys, because some implementations (notably Symantec PGP Desktop) do
 * not include self certificates for user ids in the secret keyring. The import
 * method here will generally import keyrings in the order given by the
 * iterator, so this should be ensured beforehand.
 */
public class ImportOperation extends BaseReadWriteOperation<ImportKeyringParcel> {

    private static final int MAX_THREADS = 10;

    public static final String CACHE_FILE_NAME = "key_import.pcl";

    private final KeyMetadataDao keyMetadataDao;

    private FacebookKeyserverClient facebookServer;

    public ImportOperation(Context context, KeyWritableRepository databaseInteractor, Progressable progressable) {
        super(context, databaseInteractor, progressable);

        this.keyMetadataDao = KeyMetadataDao.create(context);
    }

    public ImportOperation(Context context, KeyWritableRepository databaseInteractor,
                           Progressable progressable, AtomicBoolean cancelled) {
        super(context, databaseInteractor, progressable, cancelled);

        this.keyMetadataDao = KeyMetadataDao.create(context);
    }

    // Overloaded functions for using progressable supplied in constructor during import
    public ImportKeyResult serialKeyRingImport(Iterator<ParcelableKeyRing> entries, int num,
            HkpKeyserverAddress keyserver, ParcelableProxy proxy, boolean skipSave, boolean forceReinsert) {
        return serialKeyRingImport(entries, num, keyserver, mProgressable, proxy, skipSave, forceReinsert);
    }

    @NonNull
    private ImportKeyResult serialKeyRingImport(ParcelableFileCache<ParcelableKeyRing> cache,
            HkpKeyserverAddress keyserver, ParcelableProxy proxy, boolean skipSave, boolean forceReinsert) {

        // get entries from cached file
        try {
            IteratorWithSize<ParcelableKeyRing> it = cache.readCache();
            int numEntries = it.getSize();

            return serialKeyRingImport(it, numEntries, keyserver, mProgressable, proxy, skipSave, forceReinsert);
        } catch (IOException e) {

            // Special treatment here, we need a lot
            OperationLog log = new OperationLog();
            log.add(LogType.MSG_IMPORT, 0, 0);
            log.add(LogType.MSG_IMPORT_ERROR_IO, 0, 0);

            return new ImportKeyResult(ImportKeyResult.RESULT_ERROR, log);
        }

    }

    /**
     * @param entries      keys to import
     * @param numTotalKeys          number of keys to import
     * @param hkpKeyserver contains uri of keyserver to import from, if it is an import from cloud
     * @param progressable Allows multi-threaded import to supply a progressable that ignores the
     *                     progress of a single key being imported
     */
    @NonNull
    private ImportKeyResult serialKeyRingImport(Iterator<ParcelableKeyRing> entries, int numTotalKeys,
            HkpKeyserverAddress hkpKeyserver, Progressable progressable, @NonNull ParcelableProxy proxy,
            boolean skipSave, boolean forceReinsert) {
        if (progressable != null) {
            progressable.setProgress(R.string.progress_importing, 0, 100);
        }

        OperationLog log = new OperationLog();
        log.add(LogType.MSG_IMPORT, 0, numTotalKeys);

        // If there aren't even any keys, do nothing here.
        if (entries == null || !entries.hasNext()) {
            return new ImportKeyResult(ImportKeyResult.RESULT_FAIL_NOTHING, log);
        }

        int newKeys = 0, updatedKeys = 0, missingKeys = 0, badKeys = 0;
        ArrayList<Long> secretMasterKeyIds = new ArrayList<>();
        ArrayList<Long> importedMasterKeyIds = new ArrayList<>();

        ArrayList<CanonicalizedKeyRing> canKeyRings = new ArrayList<>();

        boolean cancelled = false;
        int keyImportsFinished = 0;

        // iterate over all entries
        while (entries.hasNext()) {
            ParcelableKeyRing entry = entries.next();

            // Has this action been cancelled? If so, don't proceed any further
            if (checkCancelled()) {
                cancelled = true;
                break;
            }

            try {
                KeyResolution resolution = resolveKeyRing(entry, hkpKeyserver, proxy, log);

                // Note: missing/bad entries intentionally "continue" here, skipping the progress
                // update below. This preserves the original behaviour where only saved keys (and
                // keys that threw while being processed) advance the progress counter.
                if (resolution.status == KeyResolution.Status.MISSING) {
                    missingKeys += 1;
                    continue;
                }
                if (resolution.status == KeyResolution.Status.BAD) {
                    badKeys += 1;
                    continue;
                }

                UncachedKeyRing key = resolution.key;
                SaveKeyringResult result =
                        saveResolvedKeyRing(key, entry, canKeyRings, skipSave, forceReinsert);
                if (!result.success()) {
                    badKeys += 1;
                } else {
                    if (result.updated()) {
                        updatedKeys += 1;
                        importedMasterKeyIds.add(key.getMasterKeyId());
                    } else {
                        newKeys += 1;
                        if (key.isSecret()) {
                            secretMasterKeyIds.add(key.getMasterKeyId());
                        }
                        importedMasterKeyIds.add(key.getMasterKeyId());
                    }

                    if (!skipSave && resolution.wasDownloaded) {
                        keyMetadataDao.renewKeyLastUpdatedTime(key.getMasterKeyId(), true);
                    }
                }

                log.add(result, 2);
            } catch (IOException | PgpGeneralException e) {
                Timber.e(e, "Encountered bad key on import!");
                ++badKeys;
            }

            // update progress
            keyImportsFinished += 1;
            progressable.setProgress(keyImportsFinished, numTotalKeys);
        }

        // Special: consolidate on secret key import (cannot be cancelled!)
        // synchronized on mProviderHelper to prevent
        // https://github.com/open-keychain/open-keychain/issues/1221 since a consolidate deletes
        // and re-inserts keys, which could conflict with a parallel db key update
        if (!skipSave && !secretMasterKeyIds.isEmpty()) {
            setPreventCancel();
            synchronized (mKeyRepository) {
                UpdateTrustResult result = mKeyWritableRepository.updateTrustDb(secretMasterKeyIds, progressable);
                log.add(result, 1);
            }
        }

        return buildSerialImportResult(log, newKeys, updatedKeys, missingKeys, badKeys,
                secretMasterKeyIds, importedMasterKeyIds, canKeyRings, cancelled);
    }

    /**
     * Resolves a single import candidate into a keyring to save, classifying entries that cannot be
     * imported. Decodes inline byte data, or fetches from keyserver/Facebook when only a reference is
     * given. Logs the same messages and performs the same {@code renewKeyLastUpdatedTime} side effect
     * as before; counting and loop control (continue) remain the caller's responsibility.
     */
    @NonNull
    private KeyResolution resolveKeyRing(ParcelableKeyRing entry, HkpKeyserverAddress hkpKeyserver,
            @NonNull ParcelableProxy proxy, OperationLog log) throws IOException, PgpGeneralException {
        // If there is already byte data, use that
        if (entry.getBytes() != null) {
            UncachedKeyRing key = UncachedKeyRing.decodeFromData(entry.getBytes());
            if (key == null) {
                log.add(LogType.MSG_IMPORT_FETCH_ERROR, 2);
                return KeyResolution.bad();
            }
            return KeyResolution.resolved(key, false);
        }

        UncachedKeyRing key;
        try {
            key = fetchKeyFromInternet(hkpKeyserver, proxy, log, entry, null);
        } catch (QueryNotFoundException e) {
            // note that this does NOT fire on network errors! those will be logged inline and return in null
            log.add(LogType.MSG_IMPORT_FETCH_ERROR_NOT_FOUND, 2);

            byte[] fingerprintHex = entry.getExpectedFingerprint();
            if (fingerprintHex != null) {
                keyMetadataDao.renewKeyLastUpdatedTime(
                        KeyFormattingUtils.getKeyIdFromFingerprint(fingerprintHex), false);
            }
            return KeyResolution.missing();
        }

        if (key != null) {
            if (key.isSecret()) {
                log.add(LogType.MSG_IMPORT_FETCH_ERROR_KEYSERVER_SECRET, 2);
                return KeyResolution.bad();
            }
            return KeyResolution.resolved(key, true);
        }

        log.add(LogType.MSG_IMPORT_FETCH_ERROR, 2);
        return KeyResolution.bad();
    }

    /**
     * Persists a resolved keyring. Encapsulates the synchronized save boundary so the import loop does
     * not need to reason about repository locking.
     */
    private SaveKeyringResult saveResolvedKeyRing(UncachedKeyRing key, ParcelableKeyRing entry,
            ArrayList<CanonicalizedKeyRing> canKeyRings, boolean skipSave, boolean forceReinsert) {
        // synchronizing prevents https://github.com/open-keychain/open-keychain/issues/1221
        // and https://github.com/open-keychain/open-keychain/issues/1480
        synchronized (mKeyRepository) {
            mKeyRepository.clearLog();
            if (key.isSecret()) {
                return mKeyWritableRepository.saveSecretKeyRing(key, canKeyRings, skipSave);
            } else {
                return mKeyWritableRepository.savePublicKeyRing(key, entry.getExpectedFingerprint(),
                        canKeyRings, forceReinsert, skipSave);
            }
        }
    }

    /**
     * Builds the {@link ImportKeyResult} for a single serial import pass, deriving the result type from
     * the accumulated counts and log and appending the final summary log entry.
     */
    @NonNull
    private ImportKeyResult buildSerialImportResult(OperationLog log, int newKeys, int updatedKeys,
            int missingKeys, int badKeys, List<Long> secretMasterKeyIds, List<Long> importedMasterKeyIds,
            ArrayList<CanonicalizedKeyRing> canKeyRings, boolean cancelled) {
        long[] importedMasterKeyIdsArray = toMasterKeyIdArray(importedMasterKeyIds);

        int resultType = 0;
        if (cancelled) {
            log.add(LogType.MSG_OPERATION_CANCELLED, 1);
            resultType |= ImportKeyResult.RESULT_CANCELLED;
        }

        // special return case: no new keys at all
        if (badKeys == 0 && newKeys == 0 && updatedKeys == 0) {
            // if keys merely aren't on keyservers, it's just a warning
            resultType = ImportKeyResult.RESULT_FAIL_NOTHING;
        } else {
            resultType = addCountResultFlags(resultType, newKeys, updatedKeys, badKeys, log.containsWarnings());
        }

        if (!cancelled) {
            // Final log entry, it's easier to do this individually
            if ((newKeys > 0 || updatedKeys > 0) && badKeys > 0) {
                log.add(LogType.MSG_IMPORT_PARTIAL, 1);
            } else if (newKeys > 0 || updatedKeys > 0) {
                log.add(LogType.MSG_IMPORT_SUCCESS, 1);
            } else {
                log.add(LogType.MSG_IMPORT_ERROR, 1);
            }
        }

        ImportKeyResult result = new ImportKeyResult(
                resultType, log, newKeys, updatedKeys, missingKeys, badKeys, secretMasterKeyIds.size(),
                importedMasterKeyIdsArray);

        result.setCanonicalizedKeyRings(canKeyRings);
        return result;
    }

    /**
     * Applies the result-type flags derived purely from import counts (and whether the log contains
     * warnings). Shared by the serial import pass and {@link KeyImportAccumulator} so the two stay in
     * sync. Note: the {@code RESULT_FAIL_NOTHING}/{@code RESULT_CANCELLED} handling is intentionally
     * NOT shared, as the two call sites differ for the empty+cancelled case.
     */
    private static int addCountResultFlags(int resultType, int newKeys, int updatedKeys, int badKeys,
            boolean hasWarnings) {
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
        if (hasWarnings) {
            resultType |= ImportKeyResult.RESULT_WARNINGS;
        }
        return resultType;
    }

    private static long[] toMasterKeyIdArray(List<Long> masterKeyIds) {
        long[] array = new long[masterKeyIds.size()];
        for (int i = 0; i < array.length; i++) {
            array[i] = masterKeyIds.get(i);
        }
        return array;
    }

    /**
     * Outcome of resolving a single import candidate: either a keyring ready to be saved
     * ({@code RESOLVED}), a key that was not found on a keyserver ({@code MISSING}), or an entry that
     * could not be used ({@code BAD}).
     */
    private static final class KeyResolution {
        enum Status { RESOLVED, MISSING, BAD }

        final Status status;
        final UncachedKeyRing key;
        final boolean wasDownloaded;

        private KeyResolution(Status status, UncachedKeyRing key, boolean wasDownloaded) {
            this.status = status;
            this.key = key;
            this.wasDownloaded = wasDownloaded;
        }

        static KeyResolution resolved(UncachedKeyRing key, boolean wasDownloaded) {
            return new KeyResolution(Status.RESOLVED, key, wasDownloaded);
        }

        static KeyResolution missing() {
            return new KeyResolution(Status.MISSING, null, false);
        }

        static KeyResolution bad() {
            return new KeyResolution(Status.BAD, null, false);
        }
    }

    private UncachedKeyRing fetchKeyFromInternet(HkpKeyserverAddress hkpKeyserver, @NonNull ParcelableProxy proxy,
            OperationLog log, ParcelableKeyRing entry, UncachedKeyRing key)
            throws PgpGeneralException, IOException, QueryNotFoundException {
        QueryNotFoundException queryNotFoundException = null;

        boolean canFetchFromKeyservers =
                hkpKeyserver != null && (entry.getKeyIdHex() != null || entry.getExpectedFingerprint()!= null);
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
    private UncachedKeyRing fetchKeyFromKeyserver(HkpKeyserverAddress hkpKeyserver, @NonNull ParcelableProxy proxy,
            OperationLog log, ParcelableKeyRing entry) throws PgpGeneralException, IOException, KeyserverClient.QueryNotFoundException {
        try {
            byte[] data;
            log.add(LogType.MSG_IMPORT_KEYSERVER, 1, hkpKeyserver);

            HkpKeyserverClient keyserverInteractor = HkpKeyserverClient.fromHkpKeyserverAddress(hkpKeyserver);

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

    private UncachedKeyRing fetchKeyFromFacebook(@NonNull ParcelableProxy proxy, OperationLog log, ParcelableKeyRing entry)
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
        UncachedKeyRing mergedKey = firstKey.merge(otherKey, log, indent +1);

        if (mergedKey != null) {
            return mergedKey;
        } else {
            log.add(LogType.MSG_IMPORT_MERGE_ERROR, indent +1);
            return firstKey;
        }
    }

    @NonNull
    @Override
    public ImportKeyResult execute(ImportKeyringParcel importInput, CryptoInputParcel cryptoInput) {
        List<ParcelableKeyRing> keyList = importInput.getKeyList();
        HkpKeyserverAddress keyServer = importInput.getKeyserver();
        boolean skipSave = importInput.isSkipSave();
        boolean forceReinsert = importInput.isForceReinsert();

        ImportKeyResult result;
        if (keyList == null) {// import from file, do serially
            ParcelableFileCache<ParcelableKeyRing> cache =
                    new ParcelableFileCache<>(mContext, CACHE_FILE_NAME);
            result = serialKeyRingImport(cache, null, null, skipSave, forceReinsert);
        } else {
            ParcelableProxy proxy;
            if (cryptoInput.getParcelableProxy() == null) {
                // explicit proxy not set
                if (!OrbotHelper.isOrbotInRequiredState(mContext)) {
                    // show dialog to enable/install dialog
                    return new ImportKeyResult(null,
                            RequiredInputParcel.createOrbotRequiredOperation(), cryptoInput);
                }
                proxy = Preferences.getPreferences(mContext).getParcelableProxy();
            } else {
                proxy = cryptoInput.getParcelableProxy();
            }

            result = multiThreadedKeyImport(keyList, keyServer, proxy, skipSave, forceReinsert);
        }
        return result;
    }

    @NonNull
    private ImportKeyResult multiThreadedKeyImport(List<ParcelableKeyRing> keyList, HkpKeyserverAddress keyServer,
            ParcelableProxy proxy, boolean skipSave, boolean forceReinsert) {
        Timber.d("Multi-threaded key import starting");

        final Iterator<ParcelableKeyRing> keyListIterator = keyList.iterator();
        final int totKeys = keyList.size();

        ExecutorService importExecutor = new ThreadPoolExecutor(0, MAX_THREADS, 30L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<Runnable>());
        ExecutorCompletionService<ImportKeyResult> importCompletionService =
                new ExecutorCompletionService<>(importExecutor);

        while (keyListIterator.hasNext()) { // submit all key rings to be imported

            final ParcelableKeyRing pkRing = keyListIterator.next();

            Callable<ImportKeyResult> importOperationCallable = new Callable<ImportKeyResult>
                    () {

                @Override
                public ImportKeyResult call() {
                    if (checkCancelled()) {
                        return null;
                    }

                    ArrayList<ParcelableKeyRing> list = new ArrayList<>();
                    list.add(pkRing);
                    ProgressScaler ignoreProgressable = new ProgressScaler();

                    return serialKeyRingImport(list.iterator(), 1, keyServer, ignoreProgressable,
                            proxy, skipSave, forceReinsert);
                }
            };

            importCompletionService.submit(importOperationCallable);
        }

        KeyImportAccumulator accumulator = new KeyImportAccumulator(totKeys, mProgressable);
        while (!accumulator.isImportFinished()) { // accumulate the results of each import
            try {
                accumulator.accumulateKeyImport(importCompletionService.take().get());
            } catch (InterruptedException | ExecutionException e) {
                Timber.e(e, "A key could not be imported during multi-threaded " +
                        "import");
                // do nothing?
                if (e instanceof ExecutionException) {
                    // Since serialKeyRingImport does not throw any exceptions, this is what
                    // would have happened if
                    // we were importing the key on this thread
                    throw new RuntimeException(e);
                }
            }
        }
        return accumulator.getConsolidatedResult();
    }

    /**
     * Used to accumulate the results of individual key imports
     */
    public static class KeyImportAccumulator {
        private OperationResult.OperationLog mImportLog = new OperationResult.OperationLog();
        private Progressable mProgressable;
        private int mTotalKeys;
        private int mImportedKeys = 0;
        private ArrayList<Long> mImportedMasterKeyIds = new ArrayList<>();
        private int mBadKeys = 0;
        private int mNewKeys = 0;
        private int mUpdatedKeys = 0;
        private int mMissingKeys = 0;
        private int mSecret = 0;
        private int mResultType = 0;
        private boolean mHasCancelledResult;

        ArrayList<CanonicalizedKeyRing> mCanonicalizedKeyRings;

        /**
         * Accumulates keyring imports and updates the progressable whenever a new key is imported.
         * Also sets the progress to 0 on instantiation.
         *
         * @param totalKeys            total number of keys to be imported
         * @param externalProgressable the external progressable to be updated every time a key
         *                             is imported
         */
        public KeyImportAccumulator(int totalKeys, Progressable externalProgressable) {
            mTotalKeys = totalKeys;
            mProgressable = externalProgressable;
            if (mProgressable != null) {
                mProgressable.setProgress(0, totalKeys);
            }

            mCanonicalizedKeyRings = new ArrayList<>();
        }

        public void accumulateKeyImport(ImportKeyResult result) {
            mImportedKeys++;

            if (result == null) {
                return;
            }

            if (mProgressable != null) {
                mProgressable.setProgress(mImportedKeys, mTotalKeys);
            }

            boolean notCancelledOrFirstCancelled = !result.cancelled() || !mHasCancelledResult;
            if (notCancelledOrFirstCancelled) {
                mImportLog.addAll(result.getLog().toList()); //accumulates log
                if (result.cancelled()) {
                    mHasCancelledResult = true;
                }
            }

            mBadKeys += result.mBadKeys;
            mNewKeys += result.mNewKeys;
            mUpdatedKeys += result.mUpdatedKeys;
            mMissingKeys += result.mMissingKeys;
            mSecret += result.mSecret;

            long[] masterKeyIds = result.getImportedMasterKeyIds();
            for (long masterKeyId : masterKeyIds) {
                mImportedMasterKeyIds.add(masterKeyId);
            }

            mCanonicalizedKeyRings.addAll(result.mCanonicalizedKeyRings);

            // if any key import has been cancelled, set result type to cancelled
            // resultType is added to in getConsolidatedKayImport to account for remaining factors
            mResultType |= result.getResult() & ImportKeyResult.RESULT_CANCELLED;
        }

        /**
         * returns accumulated result of all imports so far
         */
        public ImportKeyResult getConsolidatedResult() {

            // adding required information to mResultType
            // special case,no keys requested for import
            if (mBadKeys == 0 && mNewKeys == 0 && mUpdatedKeys == 0
                    && (mResultType & ImportKeyResult.RESULT_CANCELLED)
                    != ImportKeyResult.RESULT_CANCELLED) {
                mResultType = ImportKeyResult.RESULT_FAIL_NOTHING;
            } else {
                mResultType = addCountResultFlags(mResultType, mNewKeys, mUpdatedKeys, mBadKeys,
                        mImportLog.containsWarnings());
            }

            long[] masterKeyIds = toMasterKeyIdArray(mImportedMasterKeyIds);

            ImportKeyResult result = new ImportKeyResult(mResultType, mImportLog, mNewKeys,
                    mUpdatedKeys, mMissingKeys, mBadKeys, mSecret, masterKeyIds);

            result.setCanonicalizedKeyRings(mCanonicalizedKeyRings);
            return result;
        }

        boolean isImportFinished() {
            return mTotalKeys == mImportedKeys;
        }
    }

}
