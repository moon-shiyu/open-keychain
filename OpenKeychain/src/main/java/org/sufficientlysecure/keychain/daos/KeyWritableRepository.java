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

package org.sufficientlysecure.keychain.daos;


import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.collection.LongSparseArray;
import androidx.sqlite.db.SupportSQLiteDatabase;
import org.openintents.openpgp.util.OpenPgpUtils;
import org.sufficientlysecure.keychain.Certs;
import org.sufficientlysecure.keychain.Key_signatures;
import org.sufficientlysecure.keychain.KeychainDatabase;
import org.sufficientlysecure.keychain.Keyrings_public;
import org.sufficientlysecure.keychain.Keys;
import org.sufficientlysecure.keychain.KeysQueries;
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.User_packets;
import org.sufficientlysecure.keychain.UtilQueries;
import org.sufficientlysecure.keychain.daos.DatabaseBatchInteractor.BatchOp;
import org.sufficientlysecure.keychain.model.UnifiedKeyInfo;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogType;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.operations.results.SaveKeyringResult;
import org.sufficientlysecure.keychain.operations.results.UpdateTrustResult;
import org.sufficientlysecure.keychain.pgp.CanonicalizedKeyRing;
import org.sufficientlysecure.keychain.pgp.CanonicalizedKeyRing.VerificationStatus;
import org.sufficientlysecure.keychain.pgp.CanonicalizedPublicKey;
import org.sufficientlysecure.keychain.pgp.CanonicalizedPublicKeyRing;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKey;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKey.SecretKeyType;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKeyRing;
import org.sufficientlysecure.keychain.pgp.KeyRing;
import org.sufficientlysecure.keychain.pgp.Progressable;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.pgp.UncachedPublicKey;
import org.sufficientlysecure.keychain.pgp.WrappedSignature;
import org.sufficientlysecure.keychain.pgp.WrappedUserAttribute;
import org.sufficientlysecure.keychain.pgp.exception.PgpGeneralException;
import org.sufficientlysecure.keychain.ui.util.KeyFormattingUtils;
import org.sufficientlysecure.keychain.util.IterableIterator;
import org.sufficientlysecure.keychain.util.Preferences;
import org.sufficientlysecure.keychain.util.Utf8Util;
import timber.log.Timber;


/**
 * This class contains high level methods for database access. Despite its
 * name, it is not only a helper but actually the main interface for all
 * synchronous database operations.
 * <p/>
 * Operations in this class write logs. These can be obtained from the
 * OperationResultParcel return values directly, but are also accumulated over
 * the lifetime of the executing ProviderHelper object unless the resetLog()
 * method is called to start a new one specifically.
 */
public class KeyWritableRepository extends KeyRepository {
    private static final int MAX_CACHED_KEY_SIZE = 1024 * 50;

    private final Context context;
    private final DatabaseNotifyManager databaseNotifyManager;
    private AutocryptPeerDao autocryptPeerDao;
    private DatabaseBatchInteractor databaseBatchInteractor;

    public static KeyWritableRepository create(Context context) {
        LocalPublicKeyStorage localPublicKeyStorage = LocalPublicKeyStorage.getInstance(context);
        LocalSecretKeyStorage localSecretKeyStorage = LocalSecretKeyStorage.getInstance(context);
        DatabaseNotifyManager databaseNotifyManager = DatabaseNotifyManager.create(context);
        AutocryptPeerDao autocryptPeerDao = AutocryptPeerDao.getInstance(context);
        KeychainDatabase database = KeychainDatabase.getInstance(context);

        return new KeyWritableRepository(context, database,
                localPublicKeyStorage, localSecretKeyStorage, databaseNotifyManager, autocryptPeerDao);
        }

    private KeyWritableRepository(Context context,
            KeychainDatabase database, LocalPublicKeyStorage localPublicKeyStorage,
            LocalSecretKeyStorage localSecretKeyStorage,
            DatabaseNotifyManager databaseNotifyManager, AutocryptPeerDao autocryptPeerDao) {
        this(context, database, localPublicKeyStorage, localSecretKeyStorage, databaseNotifyManager, new OperationLog(), 0,
                autocryptPeerDao);
    }

    private KeyWritableRepository(Context context, KeychainDatabase database,
            LocalPublicKeyStorage localPublicKeyStorage,
            LocalSecretKeyStorage localSecretKeyStorage, DatabaseNotifyManager databaseNotifyManager,
            OperationLog log, int indent, AutocryptPeerDao autocryptPeerDao) {
        super(database, databaseNotifyManager, localPublicKeyStorage, localSecretKeyStorage, log, indent);

        this.context = context;
        this.databaseNotifyManager = databaseNotifyManager;
        this.autocryptPeerDao = autocryptPeerDao;
        this.databaseBatchInteractor = new DatabaseBatchInteractor(getDatabase());
    }

    private LongSparseArray<CanonicalizedPublicKey> getTrustedMasterKeys() {
        LongSparseArray<CanonicalizedPublicKey> result = new LongSparseArray<>();

        List<UnifiedKeyInfo> unifiedKeyInfoWithSecret = getAllUnifiedKeyInfoWithSecret();
        for (UnifiedKeyInfo unifiedKeyInfo : unifiedKeyInfoWithSecret) {
            try {
                byte[] blob = loadPublicKeyRingData(unifiedKeyInfo.master_key_id());
                if (blob != null) {
                    result.put(unifiedKeyInfo.master_key_id(),
                            new CanonicalizedPublicKeyRing(blob, unifiedKeyInfo.verified()).getPublicKey());
                }
            } catch (NotFoundException e) {
                throw new IllegalStateException("Error reading secret key data, this should not happen!", e);
            }
        }

        return result;
    }

    // bits, in order: CESA. make SURE these are correct, we will get bad log entries otherwise!!
    private static final LogType LOG_TYPES_FLAG_MASTER[] = new LogType[]{
            LogType.MSG_IP_MASTER_FLAGS_XXXX, LogType.MSG_IP_MASTER_FLAGS_CXXX,
            LogType.MSG_IP_MASTER_FLAGS_XEXX, LogType.MSG_IP_MASTER_FLAGS_CEXX,
            LogType.MSG_IP_MASTER_FLAGS_XXSX, LogType.MSG_IP_MASTER_FLAGS_CXSX,
            LogType.MSG_IP_MASTER_FLAGS_XESX, LogType.MSG_IP_MASTER_FLAGS_CESX,
            LogType.MSG_IP_MASTER_FLAGS_XXXA, LogType.MSG_IP_MASTER_FLAGS_CXXA,
            LogType.MSG_IP_MASTER_FLAGS_XEXA, LogType.MSG_IP_MASTER_FLAGS_CEXA,
            LogType.MSG_IP_MASTER_FLAGS_XXSA, LogType.MSG_IP_MASTER_FLAGS_CXSA,
            LogType.MSG_IP_MASTER_FLAGS_XESA, LogType.MSG_IP_MASTER_FLAGS_CESA
    };

    // same as above, but for subkeys
    private static final LogType LOG_TYPES_FLAG_SUBKEY[] = new LogType[]{
            LogType.MSG_IP_SUBKEY_FLAGS_XXXX, LogType.MSG_IP_SUBKEY_FLAGS_CXXX,
            LogType.MSG_IP_SUBKEY_FLAGS_XEXX, LogType.MSG_IP_SUBKEY_FLAGS_CEXX,
            LogType.MSG_IP_SUBKEY_FLAGS_XXSX, LogType.MSG_IP_SUBKEY_FLAGS_CXSX,
            LogType.MSG_IP_SUBKEY_FLAGS_XESX, LogType.MSG_IP_SUBKEY_FLAGS_CESX,
            LogType.MSG_IP_SUBKEY_FLAGS_XXXA, LogType.MSG_IP_SUBKEY_FLAGS_CXXA,
            LogType.MSG_IP_SUBKEY_FLAGS_XEXA, LogType.MSG_IP_SUBKEY_FLAGS_CEXA,
            LogType.MSG_IP_SUBKEY_FLAGS_XXSA, LogType.MSG_IP_SUBKEY_FLAGS_CXSA,
            LogType.MSG_IP_SUBKEY_FLAGS_XESA, LogType.MSG_IP_SUBKEY_FLAGS_CESA
    };

    // ============================================================================================
    // Signature verification helpers (shared between user IDs and user attributes)
    // ============================================================================================

    @FunctionalInterface
    private interface SignatureVerifier {
        boolean verify(WrappedSignature cert, UncachedPublicKey masterKey) throws PgpGeneralException;
    }

    private static class CertLogTypes {
        final LogType badCert;
        final LogType goodRevoke;
        final LogType goodCert;
        final LogType oldCert;
        final LogType nonRevokeCert;
        final LogType newCert;
        final LogType certError;

        CertLogTypes(LogType badCert, LogType goodRevoke, LogType goodCert,
                LogType oldCert, LogType nonRevokeCert, LogType newCert, LogType certError) {
            this.badCert = badCert;
            this.goodRevoke = goodRevoke;
            this.goodCert = goodCert;
            this.oldCert = oldCert;
            this.nonRevokeCert = nonRevokeCert;
            this.newCert = newCert;
            this.certError = certError;
        }
    }

    private static final CertLogTypes UID_CERT_LOG_TYPES = new CertLogTypes(
            LogType.MSG_IP_UID_CERT_BAD,
            LogType.MSG_IP_UID_CERT_GOOD_REVOKE,
            LogType.MSG_IP_UID_CERT_GOOD,
            LogType.MSG_IP_UID_CERT_OLD,
            LogType.MSG_IP_UID_CERT_NONREVOKE,
            LogType.MSG_IP_UID_CERT_NEW,
            LogType.MSG_IP_UID_CERT_ERROR
    );

    private static final CertLogTypes UAT_CERT_LOG_TYPES = new CertLogTypes(
            LogType.MSG_IP_UAT_CERT_BAD,
            LogType.MSG_IP_UAT_CERT_GOOD_REVOKE,
            LogType.MSG_IP_UAT_CERT_GOOD,
            LogType.MSG_IP_UAT_CERT_OLD,
            LogType.MSG_IP_UAT_CERT_NONREVOKE,
            LogType.MSG_IP_UAT_CERT_NEW,
            LogType.MSG_IP_UAT_CERT_ERROR
    );

    /**
     * Verifies a single third-party certificate against a trusted key.
     * Handles cert comparison (newer/older/non-revokable) and logging.
     * Updates item.trustedCerts if this cert should replace a previous one.
     */
    private void verifyTrustedCert(WrappedSignature cert, CanonicalizedPublicKey trustedKey,
            UncachedPublicKey masterKey, UserPacketItem item,
            SignatureVerifier verifier, CertLogTypes logTypes) {
        try {
            cert.init(trustedKey);
            if (!verifier.verify(cert, masterKey)) {
                log(logTypes.badCert);
                return;
            }

            log(cert.isRevocation() ? logTypes.goodRevoke : logTypes.goodCert,
                    KeyFormattingUtils.convertKeyIdToHexShort(trustedKey.getKeyId()));

            WrappedSignature prev = item.trustedCerts.get(cert.getKeyId());
            if (prev != null) {
                if (prev.getCreationTime().after(cert.getCreationTime())) {
                    log(logTypes.oldCert);
                    return;
                }
                if (!prev.isRevocation() && !prev.isRevokable()) {
                    log(logTypes.nonRevokeCert);
                    return;
                }
                log(logTypes.newCert);
            }
            item.trustedCerts.put(cert.getKeyId(), cert);

        } catch (PgpGeneralException e) {
            log(logTypes.certError, KeyFormattingUtils.convertKeyIdToHex(cert.getKeyId()));
        }
    }

    // ============================================================================================
    // saveCanonicalizedPublicKeyRing — public keyring persistence
    // ============================================================================================

    /**
     * Saves a canonicalized public keyring into the database.
     * <p/>
     * This method will delete all previous data for this masterKeyId from the database prior
     * to inserting. All public data is effectively re-inserted, secret keyrings are left deleted
     * and need to be saved externally to be preserved past the operation.
     */
    private int saveCanonicalizedPublicKeyRing(CanonicalizedPublicKeyRing keyRing, boolean selfCertsAreTrusted) {

        int result = SaveKeyringResult.SAVED_PUBLIC;
        long masterKeyId = keyRing.getMasterKeyId();
        UncachedPublicKey masterKey = keyRing.getPublicKey();

        log(LogType.MSG_IP_PREPARE);
        mIndent += 1;

        byte[] encodedKeyRing;
        try {
            encodedKeyRing = keyRing.getEncoded();
        } catch (IOException e) {
            log(LogType.MSG_IP_ENCODE_FAIL);
            return SaveKeyringResult.RESULT_ERROR;
        }

        ArrayList<BatchOp> operations = new ArrayList<>();

        try {
            log(LogType.MSG_IP_INSERT_KEYRING);

            byte[] encodedRingIfDbCachable = encodedKeyRing.length < MAX_CACHED_KEY_SIZE ? encodedKeyRing : null;
            Keyrings_public keyRingPublic = new Keyrings_public(masterKeyId, encodedRingIfDbCachable);
            operations.add(DatabaseBatchInteractor.createInsertKeyRingPublic(keyRingPublic));

            buildSubkeyBatchOperations(keyRing, masterKeyId, operations);

            LongSparseArray<CanonicalizedPublicKey> trustedKeys = getTrustedMasterKeys();
            List<UserPacketItem> uids = new ArrayList<>();

            classifyAndVerifyUserIds(masterKey, masterKeyId, trustedKeys, uids, operations);
            classifyAndVerifyUserAttributes(masterKey, masterKeyId, trustedKeys, uids);

            buildUserPacketBatchOperations(masterKeyId, uids, selfCertsAreTrusted, operations);

        } catch (IOException e) {
            log(LogType.MSG_IP_ERROR_IO_EXC);
            Timber.e(e, "IOException during import");
            return SaveKeyringResult.RESULT_ERROR;
        } finally {
            mIndent -= 1;
        }

        return executeSavePublicTransaction(masterKeyId, operations, encodedKeyRing, result);
    }

    /**
     * Iterates all public keys in the ring, logs key metadata (flags, expiry),
     * and appends insert operations for each subkey to the operations list.
     */
    private void buildSubkeyBatchOperations(CanonicalizedPublicKeyRing keyRing,
            long masterKeyId, ArrayList<BatchOp> operations) {
        log(LogType.MSG_IP_INSERT_SUBKEYS);
        mIndent += 1;
        int rank = 0;
        for (CanonicalizedPublicKey key : keyRing.publicKeyIterator()) {
            long keyId = key.getKeyId();
            log(keyId == masterKeyId ? LogType.MSG_IP_MASTER : LogType.MSG_IP_SUBKEY,
                    KeyFormattingUtils.convertKeyIdToHex(keyId)
            );
            mIndent += 1;

            boolean c = key.canCertify(), e = key.canEncrypt(), s = key.canSign(), a = key.canAuthenticate();

            if (masterKeyId == keyId) {
                if (key.getKeyUsage() == null) {
                    log(LogType.MSG_IP_MASTER_FLAGS_UNSPECIFIED);
                } else {
                    log(LOG_TYPES_FLAG_MASTER[(c ? 1 : 0) + (e ? 2 : 0) + (s ? 4 : 0) + (a ? 8 : 0)]);
                }
            } else {
                if (key.getKeyUsage() == null) {
                    log(LogType.MSG_IP_SUBKEY_FLAGS_UNSPECIFIED);
                } else {
                    log(LOG_TYPES_FLAG_SUBKEY[(c ? 1 : 0) + (e ? 2 : 0) + (s ? 4 : 0) + (a ? 8 : 0)]);
                }
            }

            Date creation = key.getCreationTime();
            Date bindingSignatureTime = key.getBindingSignatureTime();
            Date expiry = key.getExpiryTime();
            if (expiry != null) {
                if (key.isExpired()) {
                    log(keyId == masterKeyId ?
                                    LogType.MSG_IP_MASTER_EXPIRED : LogType.MSG_IP_SUBKEY_EXPIRED,
                            expiry.toString());
                } else {
                    log(keyId == masterKeyId ?
                                    LogType.MSG_IP_MASTER_EXPIRES : LogType.MSG_IP_SUBKEY_EXPIRES,
                            expiry.toString());
                }
            }

            long creationUnixTime = creation.getTime() / 1000;
            Long expiryUnixTime = expiry != null ? expiry.getTime() / 1000 : null;
            long validFromTime = bindingSignatureTime.getTime() / 1000;
            Keys subKey = new Keys(masterKeyId, rank, key.getKeyId(),
                    key.getBitStrength(), key.getCurveOid(), key.getAlgorithm(), key.getFingerprint(),
                    c, s, e, a, key.isRevoked(), SecretKeyType.UNAVAILABLE, key.isSecure(),
                    creationUnixTime, expiryUnixTime, validFromTime);
            operations.add(DatabaseBatchInteractor.createInsertSubKey(subKey));

            ++rank;
            mIndent -= 1;
        }
        mIndent -= 1;
    }

    /**
     * Iterates user IDs of the master key, classifies self-certificates,
     * verifies signatures from trusted keys, and tracks signer key IDs.
     * Appends Key_signatures batch ops for signers encountered.
     * <p/>
     * NOTE: This method tracks signer key IDs in the key_signatures table —
     * this is intentional behavior NOT shared by classifyAndVerifyUserAttributes.
     */
    private void classifyAndVerifyUserIds(UncachedPublicKey masterKey, long masterKeyId,
            LongSparseArray<CanonicalizedPublicKey> trustedKeys,
            List<UserPacketItem> uids, ArrayList<BatchOp> operations) {

        List<Long> signerKeyIds = new ArrayList<>();

        if (trustedKeys.size() == 0) {
            log(LogType.MSG_IP_UID_CLASSIFYING_ZERO);
        } else {
            log(LogType.MSG_IP_UID_CLASSIFYING, trustedKeys.size());
        }
        mIndent += 1;
        for (byte[] rawUserId : masterKey.getUnorderedRawUserIds()) {
            String userId = Utf8Util.fromUTF8ByteArrayReplaceBadEncoding(rawUserId);
            UserPacketItem item = new UserPacketItem();
            uids.add(item);
            OpenPgpUtils.UserId splitUserId = KeyRing.splitUserId(userId);
            item.userId = userId;
            item.name = splitUserId.name;
            item.email = splitUserId.email;
            item.comment = splitUserId.comment;
            int unknownCerts = 0;

            log(LogType.MSG_IP_UID_PROCESSING, userId);
            mIndent += 1;
            for (WrappedSignature cert : new IterableIterator<>(
                    masterKey.getSignaturesForRawId(rawUserId))) {
                long certId = cert.getKeyId();
                if (certId == masterKeyId) {
                    // NOTE self-certificates are already verified during canonicalization,
                    // AND we know there is at most one cert plus at most one revocation
                    if (!cert.isRevocation()) {
                        item.selfCert = cert;
                        item.isPrimary = cert.isPrimaryUserId();
                    } else {
                        item.selfRevocation = cert;
                        log(LogType.MSG_IP_UID_REVOKED);
                    }
                    continue;
                }

                // keep a note about the issuer of this key signature
                if (!signerKeyIds.contains(certId)) {
                    Key_signatures keySignature = new Key_signatures(masterKeyId, certId);
                    operations.add(DatabaseBatchInteractor.createInsertSignerKey(keySignature));
                    signerKeyIds.add(certId);
                }

                boolean isSignatureFromTrustedKey = trustedKeys.indexOfKey(certId) >= 0;
                if (!isSignatureFromTrustedKey) {
                    unknownCerts += 1;
                    continue;
                }

                CanonicalizedPublicKey trustedKey = trustedKeys.get(certId);
                verifyTrustedCert(cert, trustedKey, masterKey, item,
                        (c, mk) -> c.verifySignature(mk, rawUserId),
                        UID_CERT_LOG_TYPES);
            }

            if (unknownCerts > 0) {
                log(LogType.MSG_IP_UID_CERTS_UNKNOWN, unknownCerts);
            }
            mIndent -= 1;
        }
        mIndent -= 1;
    }

    /**
     * Iterates user attributes of the master key, classifies self-certificates,
     * and verifies signatures from trusted keys.
     * <p/>
     * NOTE: Does NOT track signer key IDs (intentional — user attribute signers
     * are not stored in key_signatures table).
     */
    private void classifyAndVerifyUserAttributes(UncachedPublicKey masterKey, long masterKeyId,
            LongSparseArray<CanonicalizedPublicKey> trustedKeys,
            List<UserPacketItem> uids) {

        ArrayList<WrappedUserAttribute> userAttributes = masterKey.getUnorderedUserAttributes();
        if (!userAttributes.isEmpty()) {
            log(LogType.MSG_IP_UAT_CLASSIFYING);
        }

        mIndent += 1;
        for (WrappedUserAttribute userAttribute : userAttributes) {
            UserPacketItem item = new UserPacketItem();
            uids.add(item);
            item.type = userAttribute.getType();
            item.attributeData = userAttribute.getEncoded();

            int unknownCerts = 0;

            switch (item.type) {
                case WrappedUserAttribute.UAT_IMAGE:
                    log(LogType.MSG_IP_UAT_PROCESSING_IMAGE);
                    break;
                default:
                    log(LogType.MSG_IP_UAT_PROCESSING_UNKNOWN);
                    break;
            }
            mIndent += 1;
            for (WrappedSignature cert : new IterableIterator<>(
                    masterKey.getSignaturesForUserAttribute(userAttribute))) {
                long certId = cert.getKeyId();
                if (certId == masterKeyId) {
                    // NOTE self-certificates are already verified during canonicalization,
                    // AND we know there is at most one cert plus at most one revocation
                    // AND the revocation only exists if there is no newer certification
                    if (!cert.isRevocation()) {
                        item.selfCert = cert;
                    } else {
                        item.selfRevocation = cert;
                        log(LogType.MSG_IP_UAT_REVOKED);
                    }
                    continue;
                }

                if (trustedKeys.indexOfKey(certId) < 0) {
                    unknownCerts += 1;
                    continue;
                }

                CanonicalizedPublicKey trustedKey = trustedKeys.get(certId);
                verifyTrustedCert(cert, trustedKey, masterKey, item,
                        (c, mk) -> c.verifySignature(mk, userAttribute),
                        UAT_CERT_LOG_TYPES);
            }

            if (unknownCerts > 0) {
                log(LogType.MSG_IP_UAT_CERTS_UNKNOWN, unknownCerts);
            }
            mIndent -= 1;
        }
        mIndent -= 1;
    }

    /**
     * Sorts user packet items (primary first, revoked last, trusted first),
     * then builds batch operations for inserting user packets and their
     * certifications into the database.
     */
    private void buildUserPacketBatchOperations(long masterKeyId, List<UserPacketItem> uids,
            boolean selfCertsAreTrusted, ArrayList<BatchOp> operations) {

        log(LogType.MSG_IP_UID_REORDER);
        // primary before regular before revoked (see UserPacketItem.compareTo)
        // this is a stable sort, so the order of keys is otherwise preserved.
        Collections.sort(uids);
        for (int userIdRank = 0; userIdRank < uids.size(); userIdRank++) {
            UserPacketItem item = uids.get(userIdRank);
            Long type = item.type != null ? item.type.longValue() : null;
            User_packets userPacket = new User_packets(masterKeyId, userIdRank, type,
                    item.userId, item.name, item.email,
                    item.comment, item.attributeData, item.isPrimary, item.selfRevocation != null);
            operations.add(DatabaseBatchInteractor.createInsertUserPacket(userPacket));

            if (item.selfRevocation != null) {
                operations.add(buildCertOperations(masterKeyId, userIdRank, item.selfRevocation,
                        VerificationStatus.VERIFIED_SELF));
                // don't bother with trusted certs if the uid is revoked, anyways
                continue;
            }

            if (item.selfCert == null) {
                throw new AssertionError("User ids MUST be self-certified at this point!!");
            }

            operations.add(buildCertOperations(masterKeyId, userIdRank, item.selfCert,
                    selfCertsAreTrusted ? VerificationStatus.VERIFIED_SECRET : VerificationStatus.VERIFIED_SELF));

            // iterate over trusted certifications
            for (int i = 0; i < item.trustedCerts.size(); i++) {
                WrappedSignature sig = item.trustedCerts.valueAt(i);
                // skip revocations
                if (sig.isRevocation()) {
                    continue;
                }
                operations.add(buildCertOperations(
                        masterKeyId, userIdRank, sig, VerificationStatus.VERIFIED_SECRET));
            }
        }
    }

    /**
     * Executes the database transaction for saving a public keyring:
     * deletes old data (cascading), applies batch inserts, writes large keys
     * to filesystem, and triggers content notification.
     *
     * @return SaveKeyringResult flags (SAVED_PUBLIC, possibly UPDATED) or RESULT_ERROR
     */
    private int executeSavePublicTransaction(long masterKeyId, ArrayList<BatchOp> operations,
            byte[] encodedKeyRing, int baseResult) {

        int result = baseResult;
        SupportSQLiteDatabase db = getWritableDb();
        try {
            db.beginTransaction();

            // delete old version of this keyRing (from database only!), which also deletes all keys and userIds on cascade
            getDatabase().getKeyRingsPublicQueries().deleteByMasterKeyId(masterKeyId);
            int deletedRows = getDatabase().getUtilQueries().selectChanges().executeAsOne().intValue();

            if (deletedRows > 0) {
                log(LogType.MSG_IP_DELETE_OLD_OK);
                result |= SaveKeyringResult.UPDATED;
            } else {
                log(LogType.MSG_IP_DELETE_OLD_FAIL);
            }

            log(LogType.MSG_IP_APPLY_BATCH);
            databaseBatchInteractor.applyBatch(operations);
            if (encodedKeyRing.length >= MAX_CACHED_KEY_SIZE) {
                mLocalPublicKeyStorage.writePublicKey(masterKeyId, encodedKeyRing);
            }
            databaseNotifyManager.notifyKeyChange(masterKeyId);

            db.setTransactionSuccessful();
            log(LogType.MSG_IP_SUCCESS);
            return result;
        } catch (IOException e) {
            log(LogType.MSG_IP_ERROR_OP_EXC);
            Timber.e(e, "OperationApplicationException during import");
            return SaveKeyringResult.RESULT_ERROR;
        } finally {
            db.endTransaction();
        }
    }

    // ============================================================================================
    // Secret keyring persistence
    // ============================================================================================

    private void writeSecretKeyRing(CanonicalizedSecretKeyRing keyRing, long masterKeyId) throws IOException {
        byte[] encodedKey = keyRing.getEncoded();
        localSecretKeyStorage.writeSecretKey(masterKeyId, encodedKey);
    }

    /**
     * Canonicalizes a secret ring, with fallback to merging self-certificates from the
     * corresponding public keyring (Symantec PGP Desktop compatibility).
     * <p>
     * Symantec PGP Desktop may export secret keys without self-certificates. We don't support
     * those on their own, but if the corresponding public key is known, the self-cert info can
     * be merged in as a special case.
     *
     * @return the canonicalized secret ring, or null if canonicalization fails even after fallback
     */
    private CanonicalizedSecretKeyRing canonicalizeSecretRingWithFallback(
            UncachedKeyRing secretRing, long masterKeyId) throws IOException {
        CanonicalizedSecretKeyRing result =
                (CanonicalizedSecretKeyRing) secretRing.canonicalize(mLog, mIndent);
        if (result != null) {
            return result;
        }
        // Fallback: merge self-certificates from existing public keyring and retry
        try {
            log(LogType.MSG_IS_MERGE_SPECIAL);
            UncachedKeyRing oldPublicRing =
                    getCanonicalizedPublicKeyRing(masterKeyId).getUncachedKeyRing();
            secretRing = secretRing.merge(oldPublicRing, mLog, mIndent);
            return (CanonicalizedSecretKeyRing) secretRing.canonicalize(mLog, mIndent);
        } catch (NotFoundException e2) {
            return null;
        }
    }

    /**
     * Merges secret ring data into the existing public ring, or extracts a public ring
     * from the secret ring if no public ring exists yet.
     *
     * @return the canonicalized public ring, or null on merge/canonicalize failure
     */
    private CanonicalizedPublicKeyRing extractOrMergePublicRing(
            UncachedKeyRing secretRing, long masterKeyId) throws IOException {
        UncachedKeyRing publicRing;
        try {
            UncachedKeyRing oldPublicRing =
                    getCanonicalizedPublicKeyRing(masterKeyId).getUncachedKeyRing();
            log(LogType.MSG_IS_MERGE_PUBLIC);
            publicRing = oldPublicRing.merge(secretRing, mLog, mIndent);
            if (publicRing == null) {
                return null;
            }
        } catch (NotFoundException e) {
            log(LogType.MSG_IS_PUBRING_GENERATE);
            publicRing = secretRing.extractPublicKeyRing();
        }
        return (CanonicalizedPublicKeyRing) publicRing.canonicalize(mLog, mIndent);
    }

    // ============================================================================================
    // Delete
    // ============================================================================================

    public boolean deleteKeyRing(long masterKeyId) {
        try {
            mLocalPublicKeyStorage.deletePublicKey(masterKeyId);
            localSecretKeyStorage.deleteSecretKey(masterKeyId);
        } catch (IOException e) {
            Timber.e(e, "Could not delete file!");
            return false;
        }
        autocryptPeerDao.deleteByMasterKeyId(masterKeyId);

        getDatabase().getKeyRingsPublicQueries().deleteByMasterKeyId(masterKeyId);
        int deletedRows = getDatabase().getUtilQueries().selectChanges().executeAsOne().intValue();

        databaseNotifyManager.notifyKeyChange(masterKeyId);

        return deletedRows > 0;
    }

    // ============================================================================================
    // Inner types
    // ============================================================================================

    static class UserPacketItem implements Comparable<UserPacketItem> {
        Integer type;
        String userId;
        String name;
        String email;
        String comment;
        byte[] attributeData;
        boolean isPrimary = false;
        WrappedSignature selfCert;
        WrappedSignature selfRevocation;
        LongSparseArray<WrappedSignature> trustedCerts = new LongSparseArray<>();

        @Override
        public int compareTo(@NonNull UserPacketItem o) {
            // revoked keys always come last!
            //noinspection DoubleNegation
            if ((selfRevocation != null) != (o.selfRevocation != null)) {
                return selfRevocation != null ? 1 : -1;
            }
            // if one is a user id, but the other isn't, the user id always comes first.
            // we compare for null values here, so != is the correct operator!
            // noinspection NumberEquality
            if (type != o.type) {
                return type == null ? -1 : 1;
            }
            // if one is *trusted* but the other isn't, that one comes first
            // this overrides the primary attribute, even!
            if ((trustedCerts.size() == 0) != (o.trustedCerts.size() == 0)) {
                return trustedCerts.size() > o.trustedCerts.size() ? -1 : 1;
            }
            // if one key is primary but the other isn't, the primary one always comes first
            if (isPrimary != o.isPrimary) {
                return isPrimary ? -1 : 1;
            }
            return 0;
        }
    }

    // ============================================================================================
    // saveCanonicalizedSecretKeyRing — secret keyring persistence
    // ============================================================================================

    /**
     * Saves an UncachedKeyRing of the secret variant into the db.
     * This method will fail if no corresponding public keyring is in the database!
     */
    private int saveCanonicalizedSecretKeyRing(CanonicalizedSecretKeyRing keyRing) {

        long masterKeyId = keyRing.getMasterKeyId();
        log(LogType.MSG_IS, KeyFormattingUtils.convertKeyIdToHex(masterKeyId));
        mIndent += 1;

        try {

            // IF this is successful, it's a secret key
            int result = SaveKeyringResult.SAVED_SECRET;

            // save secret keyring
            try {
                writeSecretKeyRing(keyRing, masterKeyId);
            } catch (IOException e) {
                Timber.e(e, "Failed to encode key!");
                log(LogType.MSG_IS_ERROR_IO_EXC);
                return SaveKeyringResult.RESULT_ERROR;
            }

            KeysQueries keysQueries = getDatabase().getKeysQueries();
            UtilQueries utilQueries = getDatabase().getUtilQueries();

            keysQueries.updateHasSecretByMasterKeyId(masterKeyId, SecretKeyType.GNU_DUMMY);

            // then, mark exactly the keys we have available
            log(LogType.MSG_IS_IMPORTING_SUBKEYS);
            mIndent += 1;
            for (CanonicalizedSecretKey sub : keyRing.secretKeyIterator()) {
                long id = sub.getKeyId();
                SecretKeyType mode = sub.getSecretKeyTypeSuperExpensive();
                keysQueries.updateHasSecretByKeyId(id, mode);
                int upd = utilQueries.selectChanges().executeAsOne().intValue();
                if (upd == 1) {
                    switch (mode) {
                        case PASSPHRASE:
                            log(LogType.MSG_IS_SUBKEY_OK, KeyFormattingUtils.convertKeyIdToHex(id));
                            break;
                        case PASSPHRASE_EMPTY:
                            log(LogType.MSG_IS_SUBKEY_EMPTY, KeyFormattingUtils.convertKeyIdToHex(id));
                            break;
                        case GNU_DUMMY:
                            log(LogType.MSG_IS_SUBKEY_STRIPPED, KeyFormattingUtils.convertKeyIdToHex(id));
                            break;
                        case DIVERT_TO_CARD:
                            log(LogType.MSG_IS_SUBKEY_DIVERT, KeyFormattingUtils.convertKeyIdToHex(id));
                            break;
                    }
                } else {
                    log(LogType.MSG_IS_SUBKEY_NONEXISTENT, KeyFormattingUtils.convertKeyIdToHex(id));
                }
            }
            mIndent -= 1;

            // this implicitly leaves all keys which were not in the secret key ring
            // with has_secret = 1

            databaseNotifyManager.notifyKeyChange(masterKeyId);

            log(LogType.MSG_IS_SUCCESS);
            return result;

        } finally {
            mIndent -= 1;
        }

    }

    // ============================================================================================
    // Public orchestrator: savePublicKeyRing
    // ============================================================================================

    /**
     * Save a public keyring into the database.
     * <p>
     * This is a high level method, which takes care of merging all new information into the old and
     * keep public and secret keyrings in sync.
     * <p>
     * If you want to merge keys in-memory only and not save in database set skipSave=true.
     */
    public SaveKeyringResult savePublicKeyRing(UncachedKeyRing publicRing,
            byte[] expectedFingerprint,
            ArrayList<CanonicalizedKeyRing> canKeyRings,
            boolean forceRefresh,
            boolean skipSave) {

        try {
            long masterKeyId = publicRing.getMasterKeyId();
            log(LogType.MSG_IP, KeyFormattingUtils.convertKeyIdToHex(masterKeyId));
            mIndent += 1;

            if (publicRing.isSecret()) {
                log(LogType.MSG_IP_BAD_TYPE_SECRET);
                return new SaveKeyringResult(SaveKeyringResult.RESULT_ERROR, mLog, null);
            }

            CanonicalizedPublicKeyRing canPublicRing;
            boolean alreadyExists = false;

            // If there is an old keyring, merge it
            try {
                UncachedKeyRing oldPublicRing = UncachedKeyRing.decodeFromData(loadPublicKeyRingData(masterKeyId));
                alreadyExists = true;

                // Merge data from new public ring into the old one
                log(LogType.MSG_IP_MERGE_PUBLIC);
                publicRing = oldPublicRing.merge(publicRing, mLog, mIndent);

                // If this is null, there is an error in the log so we can just return
                if (publicRing == null) {
                    return new SaveKeyringResult(SaveKeyringResult.RESULT_ERROR, mLog, null);
                }

                // Canonicalize this keyring, to assert a number of assumptions made about it.
                canPublicRing = (CanonicalizedPublicKeyRing) publicRing.canonicalize(mLog, mIndent);
                if (canPublicRing == null) {
                    return new SaveKeyringResult(SaveKeyringResult.RESULT_ERROR, mLog, null);
                }
                if (canKeyRings != null) canKeyRings.add(canPublicRing);

                // Early breakout if nothing changed
                if (!forceRefresh && Arrays.hashCode(publicRing.getEncoded())
                        == Arrays.hashCode(oldPublicRing.getEncoded())) {
                    log(LogType.MSG_IP_SUCCESS_IDENTICAL);
                    return new SaveKeyringResult(SaveKeyringResult.UPDATED, mLog, canPublicRing);
                }
            } catch (PgpGeneralException | NotFoundException e) {
                // Not an issue, just means we are dealing with a new keyring.

                // Canonicalize this keyring, to assert a number of assumptions made about it.
                canPublicRing = (CanonicalizedPublicKeyRing) publicRing.canonicalize(mLog, mIndent);
                if (canPublicRing == null) {
                    return new SaveKeyringResult(SaveKeyringResult.RESULT_ERROR, mLog, null);
                }
                if (canKeyRings != null) canKeyRings.add(canPublicRing);
            }

            // If there is a secret key, merge new data (if any) and save the key for later
            CanonicalizedSecretKeyRing canSecretRing;
            try {
                UncachedKeyRing secretRing = getCanonicalizedSecretKeyRing(publicRing.getMasterKeyId())
                        .getUncachedKeyRing();

                // Merge data from new public ring into secret one
                log(LogType.MSG_IP_MERGE_SECRET);
                secretRing = secretRing.merge(publicRing, mLog, mIndent);
                if (secretRing == null) {
                    return new SaveKeyringResult(SaveKeyringResult.RESULT_ERROR, mLog, null);
                }
                // This has always been a secret key ring, this is a safe cast
                canSecretRing = (CanonicalizedSecretKeyRing) secretRing.canonicalize(mLog, mIndent);
                if (canSecretRing == null) {
                    return new SaveKeyringResult(SaveKeyringResult.RESULT_ERROR, mLog, null);
                }

            } catch (NotFoundException e) {
                // No secret key available (this is what happens most of the time)
                canSecretRing = null;
            }


            if (!validateExpectedFingerprint(canPublicRing, expectedFingerprint)) {
                return new SaveKeyringResult(SaveKeyringResult.RESULT_ERROR, mLog, null);
            }

            int result = skipSave
                    ? SaveKeyringResult.SAVED_PUBLIC | (alreadyExists ? SaveKeyringResult.UPDATED : 0)
                    : saveCanonicalizedPublicKeyRing(canPublicRing, canSecretRing != null);

            // Save the secret keyring if one exists
            if (canSecretRing != null) {
                int secretResult = skipSave
                        ? SaveKeyringResult.SAVED_SECRET
                        : saveCanonicalizedSecretKeyRing(canSecretRing);
                if ((secretResult & SaveKeyringResult.RESULT_ERROR) != SaveKeyringResult.RESULT_ERROR) {
                    result |= SaveKeyringResult.SAVED_SECRET;
                }
            }

            return new SaveKeyringResult(result, mLog, canPublicRing);
        } catch (IOException e) {
            log(LogType.MSG_IP_ERROR_IO_EXC);
            return new SaveKeyringResult(SaveKeyringResult.RESULT_ERROR, mLog, null);
        } finally {
            mIndent -= 1;
        }
    }

    public SaveKeyringResult savePublicKeyRing(UncachedKeyRing publicRing, byte[] expectedFingerprint) {
        return savePublicKeyRing(publicRing, expectedFingerprint, null, false, false);
    }

    public SaveKeyringResult savePublicKeyRing(UncachedKeyRing publicRing, byte[] expectedFingerprint,
            boolean forceRefresh) {
        return savePublicKeyRing(publicRing, expectedFingerprint, null, forceRefresh, false);
    }

    public SaveKeyringResult savePublicKeyRing(UncachedKeyRing keyRing) {
        return savePublicKeyRing(keyRing, null, false);
    }

    public SaveKeyringResult savePublicKeyRing(UncachedKeyRing keyRing, boolean forceRefresh) {
        return savePublicKeyRing(keyRing, null, forceRefresh);
    }

    // ============================================================================================
    // Public orchestrator: saveSecretKeyRing
    // ============================================================================================

    public SaveKeyringResult saveSecretKeyRing(UncachedKeyRing secretRing,
                                               ArrayList<CanonicalizedKeyRing> canKeyRings,
                                               boolean skipSave) {

        try {
            long masterKeyId = secretRing.getMasterKeyId();
            log(LogType.MSG_IS, KeyFormattingUtils.convertKeyIdToHex(masterKeyId));
            mIndent += 1;

            if (!secretRing.isSecret()) {
                log(LogType.MSG_IS_BAD_TYPE_PUBLIC);
                return new SaveKeyringResult(SaveKeyringResult.RESULT_ERROR, mLog, null);
            }

            CanonicalizedSecretKeyRing canSecretRing;
            boolean alreadyExists = false;

            // If there is an old secret key, merge it.
            try {
                UncachedKeyRing oldSecretRing = getCanonicalizedSecretKeyRing(masterKeyId).getUncachedKeyRing();
                alreadyExists = true;

                // Merge data from new secret ring into old one
                log(LogType.MSG_IS_MERGE_SECRET);
                secretRing = secretRing.merge(oldSecretRing, mLog, mIndent);

                // If this is null, there is an error in the log so we can just return
                if (secretRing == null) {
                    return new SaveKeyringResult(SaveKeyringResult.RESULT_ERROR, mLog, null);
                }

                // Canonicalize this keyring, to assert a number of assumptions made about it.
                // This is a safe cast, because we made sure this is a secret ring above
                canSecretRing = (CanonicalizedSecretKeyRing) secretRing.canonicalize(mLog, mIndent);
                if (canSecretRing == null) {
                    return new SaveKeyringResult(SaveKeyringResult.RESULT_ERROR, mLog, null);
                }
                if (canKeyRings != null) canKeyRings.add(canSecretRing);

                // Early breakout if nothing changed
                if (Arrays.hashCode(secretRing.getEncoded())
                        == Arrays.hashCode(oldSecretRing.getEncoded())) {
                    log(LogType.MSG_IS_SUCCESS_IDENTICAL,
                            KeyFormattingUtils.convertKeyIdToHex(masterKeyId));
                    return new SaveKeyringResult(SaveKeyringResult.UPDATED, mLog, null);
                }
            } catch (NotFoundException e) {
                // Not an issue, just means we are dealing with a new keyring

                // Canonicalize, with fallback to merging self-certs from the public key (Symantec)
                canSecretRing = canonicalizeSecretRingWithFallback(secretRing, masterKeyId);
                if (canSecretRing == null) {
                    return new SaveKeyringResult(SaveKeyringResult.RESULT_ERROR, mLog, null);
                }
                if (canKeyRings != null) canKeyRings.add(canSecretRing);
            }

            CanonicalizedPublicKeyRing canPublicRing =
                    extractOrMergePublicRing(secretRing, masterKeyId);
            if (canPublicRing == null) {
                return new SaveKeyringResult(SaveKeyringResult.RESULT_ERROR, mLog, null);
            }

            int publicResult = skipSave
                    ? SaveKeyringResult.SAVED_PUBLIC
                    : saveCanonicalizedPublicKeyRing(canPublicRing, true);

            if ((publicResult & SaveKeyringResult.RESULT_ERROR) == SaveKeyringResult.RESULT_ERROR) {
                return new SaveKeyringResult(SaveKeyringResult.RESULT_ERROR, mLog, null);
            }

            int result = skipSave
                    ? SaveKeyringResult.SAVED_SECRET | (alreadyExists ? SaveKeyringResult.UPDATED : 0)
                    : saveCanonicalizedSecretKeyRing(canSecretRing);

            return new SaveKeyringResult(result, mLog, canSecretRing);
        } catch (IOException e) {
            log(LogType.MSG_IS_ERROR_IO_EXC);
            return new SaveKeyringResult(SaveKeyringResult.RESULT_ERROR, mLog, null);
        } finally {
            mIndent -= 1;
        }
    }

    public SaveKeyringResult saveSecretKeyRing(UncachedKeyRing secretRing) {
        return saveSecretKeyRing(secretRing, null, false);
    }

    // ============================================================================================
    // Trust DB update
    // ============================================================================================

    @NonNull
    public UpdateTrustResult updateTrustDb(List<Long> signerMasterKeyIds, Progressable progress) {
        OperationLog log = new OperationLog();

        log.add(LogType.MSG_TRUST, 0);

        Preferences preferences = Preferences.getPreferences(context);
        boolean isTrustDbInitialized = preferences.isKeySignaturesTableInitialized();

        List<Long> masterKeyIds;
        if (!isTrustDbInitialized) {
            log.add(LogType.MSG_TRUST_INITIALIZE, 1);
            masterKeyIds = getAllMasterKeyIds();
        } else {
            masterKeyIds = getMasterKeyIdsBySigner(signerMasterKeyIds);
        }

        int totalKeys = masterKeyIds.size();
        int processedKeys = 0;

        if (totalKeys == 0) {
            log.add(LogType.MSG_TRUST_COUNT_NONE, 1);
        } else {
            progress.setProgress(R.string.progress_update_trust, 0, totalKeys);
            log.add(LogType.MSG_TRUST_COUNT, 1, totalKeys);
        }

        for (long masterKeyId : masterKeyIds) {
            try {
                log.add(LogType.MSG_TRUST_KEY, 1, KeyFormattingUtils.beautifyKeyId(masterKeyId));

                byte[] pubKeyData = loadPublicKeyRingData(masterKeyId);
                UncachedKeyRing uncachedKeyRing = UncachedKeyRing.decodeFromData(pubKeyData);

                clearLog();
                SaveKeyringResult result = savePublicKeyRing(uncachedKeyRing, true);

                log.add(result, 1);
                progress.setProgress(processedKeys++, totalKeys);
            } catch (NotFoundException | PgpGeneralException | IOException e) {
                Timber.e(e, "Error updating trust database");
                return new UpdateTrustResult(UpdateTrustResult.RESULT_ERROR, log);
            }
        }

        preferences.setKeySignaturesTableInitialized();

        log.add(LogType.MSG_TRUST_OK, 1);
        return new UpdateTrustResult(UpdateTrustResult.RESULT_OK, log);
    }

    // ============================================================================================
    // Validation helpers
    // ============================================================================================

    /**
     * Validates the canonicalized ring against an expected fingerprint.
     * Returns true if no fingerprint was specified or if a bound subkey matches.
     */
    private boolean validateExpectedFingerprint(
            CanonicalizedPublicKeyRing canPublicRing, byte[] expectedFingerprint) {
        if (expectedFingerprint == null) {
            return true;
        }
        if (!canPublicRing.containsBoundSubkey(expectedFingerprint)) {
            log(LogType.MSG_IP_FINGERPRINT_ERROR);
            return false;
        }
        log(LogType.MSG_IP_FINGERPRINT_OK);
        return true;
    }

    // ============================================================================================
    // Batch operation helpers
    // ============================================================================================

    private BatchOp buildCertOperations(long masterKeyId, int rank, WrappedSignature cert, VerificationStatus verificationStatus) {
        try {
            long creationUnixTime = cert.getCreationTime().getTime() / 1000;
            Certs certification = new Certs(masterKeyId, rank, cert.getKeyId(),
                    cert.getSignatureType(), verificationStatus, creationUnixTime, cert.getEncoded());
            return DatabaseBatchInteractor.createInsertCertification(certification);
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

}
