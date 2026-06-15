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
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.daos.KeyMetadataDao;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.keyimport.HkpKeyserverAddress;
import org.sufficientlysecure.keychain.keyimport.KeyserverClient.QueryNotFoundException;
import org.sufficientlysecure.keychain.keyimport.ParcelableKeyRing;
import org.sufficientlysecure.keychain.network.orbot.OrbotHelper;
import org.sufficientlysecure.keychain.operations.importOperation.ImportKeyResolver;
import org.sufficientlysecure.keychain.operations.importOperation.ImportKeySaver;
import org.sufficientlysecure.keychain.operations.importOperation.ImportResultBuilder;
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
     * Core serial import loop. Processes each key one at a time:
     * resolve → save → track outcome.
     *
     * @param entries      keys to import
     * @param numTotalKeys number of keys to import
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

        ImportResultBuilder builder = new ImportResultBuilder(true);
        ImportKeyResolver resolver = new ImportKeyResolver();
        ImportKeySaver saver = new ImportKeySaver(mKeyRepository, mKeyWritableRepository);

        ArrayList<CanonicalizedKeyRing> canKeyRings = builder.getCanonicalizedKeyRings();

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
                // --- Step 1: Resolve the key (decode bytes or fetch from internet) ---
                ImportKeyResolver.ResolvedKey resolved;
                try {
                    resolved = resolver.resolve(entry, hkpKeyserver, proxy, log);
                } catch (QueryNotFoundException e) {
                    // note that this does NOT fire on network errors! those will be logged inline and return in null
                    log.add(LogType.MSG_IMPORT_FETCH_ERROR_NOT_FOUND, 2);
                    builder.recordMissingKey(entry.getExpectedFingerprint(), keyMetadataDao);
                    keyImportsFinished += 1;
                    progressable.setProgress(keyImportsFinished, numTotalKeys);
                    continue;
                }

                if (resolved == null) {
                    log.add(LogType.MSG_IMPORT_FETCH_ERROR, 2);
                    builder.recordBadKey();
                    keyImportsFinished += 1;
                    progressable.setProgress(keyImportsFinished, numTotalKeys);
                    continue;
                }

                UncachedKeyRing key = resolved.key;

                // Reject secret keys downloaded from keyservers
                if (resolved.wasDownloaded && key.isSecret()) {
                    log.add(LogType.MSG_IMPORT_FETCH_ERROR_KEYSERVER_SECRET, 2);
                    builder.recordBadKey();
                    keyImportsFinished += 1;
                    progressable.setProgress(keyImportsFinished, numTotalKeys);
                    continue;
                }

                // --- Step 2: Save the key (synchronized) ---
                SaveKeyringResult result = saver.save(key, entry.getExpectedFingerprint(),
                        canKeyRings, skipSave, forceReinsert);

                // --- Step 3: Track the outcome ---
                if (!result.success()) {
                    builder.recordBadKey();
                } else {
                    if (result.updated()) {
                        builder.recordUpdatedKey(key.getMasterKeyId());
                    } else {
                        builder.recordNewKey(key.getMasterKeyId(), key.isSecret());
                    }

                    if (!skipSave && resolved.wasDownloaded) {
                        keyMetadataDao.renewKeyLastUpdatedTime(key.getMasterKeyId(), true);
                    }
                }

                log.add(result, 2);
            } catch (IOException | PgpGeneralException e) {
                Timber.e(e, "Encountered bad key on import!");
                builder.recordBadKey();
            }

            // update progress
            keyImportsFinished += 1;
            progressable.setProgress(keyImportsFinished, numTotalKeys);
        }

        // Special: consolidate on secret key import (cannot be cancelled!)
        // synchronized on mProviderHelper to prevent
        // https://github.com/open-keychain/open-keychain/issues/1221 since a consolidate deletes
        // and re-inserts keys, which could conflict with a parallel db key update
        if (!skipSave && !builder.getSecretMasterKeyIds().isEmpty()) {
            setPreventCancel();
            synchronized (mKeyRepository) {
                UpdateTrustResult result = mKeyWritableRepository.updateTrustDb(
                        builder.getSecretMasterKeyIds(), progressable);
                log.add(result, 1);
            }
        }

        // Cancellation
        int resultTypeExtra = 0;
        if (cancelled) {
            log.add(LogType.MSG_OPERATION_CANCELLED, 1);
            resultTypeExtra |= ImportKeyResult.RESULT_CANCELLED;
        }

        // Final summary log
        builder.addFinalLog(log, cancelled);

        return builder.build(resultTypeExtra, log);
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
     * Used to accumulate the results of individual key imports.
     * Delegates counter tracking and bitmask computation to
     * {@link ImportResultBuilder} to keep this logic in a single place.
     */
    public static class KeyImportAccumulator {
        private final OperationResult.OperationLog mImportLog = new OperationResult.OperationLog();
        private final ImportResultBuilder builder;
        private final Progressable mProgressable;
        private final int mTotalKeys;
        private int mImportedKeys = 0;
        private boolean mHasCancelledResult;

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

            builder = new ImportResultBuilder(false);
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

            builder.accumulateFrom(result);

            // if any key import has been cancelled, set result type to cancelled
            // resultType is added to in getConsolidatedResult to account for remaining factors
        }

        /**
         * returns accumulated result of all imports so far
         */
        public ImportKeyResult getConsolidatedResult() {
            int resultTypeExtra = 0;
            // Propagate cancellation bit from accumulated results
            if (mHasCancelledResult) {
                resultTypeExtra |= ImportKeyResult.RESULT_CANCELLED;
            }

            return builder.build(resultTypeExtra, mImportLog);
        }

        boolean isImportFinished() {
            return mTotalKeys == mImportedKeys;
        }
    }

}
