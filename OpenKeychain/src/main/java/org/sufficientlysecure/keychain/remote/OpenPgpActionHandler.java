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


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.TextUtils;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.openintents.openpgp.AutocryptPeerUpdate;
import org.openintents.openpgp.OpenPgpDecryptionResult;
import org.openintents.openpgp.OpenPgpError;
import org.openintents.openpgp.OpenPgpMetadata;
import org.openintents.openpgp.OpenPgpSignatureResult;
import org.openintents.openpgp.OpenPgpSignatureResult.AutocryptPeerResult;
import org.openintents.openpgp.util.OpenPgpApi;
import org.sufficientlysecure.keychain.Autocrypt_peers;
import org.sufficientlysecure.keychain.Constants;
import org.sufficientlysecure.keychain.daos.ApiAppDao;
import org.sufficientlysecure.keychain.daos.AutocryptPeerDao;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.daos.KeyRepository.NotFoundException;
import org.sufficientlysecure.keychain.daos.OverriddenWarningsDao;
import org.sufficientlysecure.keychain.model.UnifiedKeyInfo;
import org.sufficientlysecure.keychain.operations.BackupOperation;
import org.sufficientlysecure.keychain.operations.results.DecryptVerifyResult;
import org.sufficientlysecure.keychain.operations.results.ExportResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogEntryParcel;
import org.sufficientlysecure.keychain.operations.results.PgpSignEncryptResult;
import org.sufficientlysecure.keychain.pgp.CanonicalizedPublicKeyRing;
import org.sufficientlysecure.keychain.pgp.DecryptVerifySecurityProblem;
import org.sufficientlysecure.keychain.pgp.PgpDecryptVerifyInputParcel;
import org.sufficientlysecure.keychain.pgp.PgpDecryptVerifyOperation;
import org.sufficientlysecure.keychain.pgp.PgpSecurityConstants.OpenKeychainCompressionAlgorithmTags;
import org.sufficientlysecure.keychain.pgp.PgpSignEncryptData;
import org.sufficientlysecure.keychain.pgp.PgpSignEncryptOperation;
import org.sufficientlysecure.keychain.pgp.Progressable;
import org.sufficientlysecure.keychain.pgp.SecurityProblem;
import org.sufficientlysecure.keychain.provider.KeychainExternalContract.AutocryptStatus;
import org.sufficientlysecure.keychain.remote.OpenPgpServiceKeyIdExtractor.KeyIdResult;
import org.sufficientlysecure.keychain.remote.OpenPgpServiceKeyIdExtractor.KeyIdResultStatus;
import org.sufficientlysecure.keychain.service.BackupKeyringParcel;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.service.input.RequiredInputParcel;
import org.sufficientlysecure.keychain.util.InputData;
import org.sufficientlysecure.keychain.util.Numeric9x4PassphraseUtil;
import org.sufficientlysecure.keychain.util.Passphrase;
import timber.log.Timber;


/**
 * Handles all OpenPGP API action implementations, extracted from {@link OpenPgpService}
 * for better testability and separation of concerns.
 *
 * This class contains the business logic for all 16 supported OpenPGP API actions.
 * Stream lifecycle and permission checking are managed by the calling service.
 */
public class OpenPgpActionHandler {

    static final int API_VERSION_WITH_KEY_INVALID_INSECURE = OpenPgpService.API_VERSION_WITH_KEY_INVALID_INSECURE;
    static final int API_VERSION_WITHOUT_SIGNATURE_ONLY_FLAG = OpenPgpService.API_VERSION_WITHOUT_SIGNATURE_ONLY_FLAG;
    static final int API_VERSION_WITH_DECRYPTION_RESULT = OpenPgpService.API_VERSION_WITH_DECRYPTION_RESULT;
    static final int API_VERSION_WITH_RESULT_NO_SIGNATURE = OpenPgpService.API_VERSION_WITH_RESULT_NO_SIGNATURE;
    static final int API_VERSION_WITH_AUTOCRYPT = OpenPgpService.API_VERSION_WITH_AUTOCRYPT;

    private final Context mContext;
    private final KeyRepository mKeyRepository;
    private final ApiAppDao mApiAppDao;
    private final ApiPermissionHelper mApiPermissionHelper;
    private final ApiPendingIntentFactory mApiPendingIntentFactory;
    private final OpenPgpServiceKeyIdExtractor mKeyIdExtractor;
    private final OpenPgpResultBuilder mResultBuilder;

    public OpenPgpActionHandler(Context context, KeyRepository keyRepository, ApiAppDao apiAppDao,
            ApiPermissionHelper apiPermissionHelper, ApiPendingIntentFactory apiPendingIntentFactory,
            OpenPgpServiceKeyIdExtractor keyIdExtractor, OpenPgpResultBuilder resultBuilder) {
        mContext = context;
        mKeyRepository = keyRepository;
        mApiAppDao = apiAppDao;
        mApiPermissionHelper = apiPermissionHelper;
        mApiPendingIntentFactory = apiPendingIntentFactory;
        mKeyIdExtractor = keyIdExtractor;
        mResultBuilder = resultBuilder;
    }

    /**
     * Dispatches an API call to the appropriate action handler method.
     *
     * @param data        the API call Intent with action and extras
     * @param inputStream input data stream (may be null for non-stream actions)
     * @param outputStream output data stream (may be null for non-stream actions)
     * @param progressable progress reporter (may be null)
     * @return result Intent with RESULT_CODE and optional extras
     */
    @Nullable
    public Intent dispatch(@NonNull Intent data, @Nullable InputStream inputStream,
            @Nullable OutputStream outputStream, @Nullable Progressable progressable) {

        String action = data.getAction();
        switch (action) {
            case OpenPgpApi.ACTION_CHECK_PERMISSION: {
                return checkPermissionImpl(data);
            }
            case OpenPgpApi.ACTION_CLEARTEXT_SIGN: {
                return signImpl(data, inputStream, outputStream, true);
            }
            case OpenPgpApi.ACTION_SIGN: {
                Timber.w("You are using a deprecated API call, please use ACTION_CLEARTEXT_SIGN instead of ACTION_SIGN!");
                return signImpl(data, inputStream, outputStream, true);
            }
            case OpenPgpApi.ACTION_DETACHED_SIGN: {
                return signImpl(data, inputStream, outputStream, false);
            }
            case OpenPgpApi.ACTION_QUERY_AUTOCRYPT_STATUS: {
                return autocryptQueryImpl(data);
            }
            case OpenPgpApi.ACTION_ENCRYPT:
            case OpenPgpApi.ACTION_SIGN_AND_ENCRYPT: {
                boolean enableSign = action.equals(OpenPgpApi.ACTION_SIGN_AND_ENCRYPT);
                return encryptAndSignImpl(data, inputStream, outputStream, enableSign);
            }
            case OpenPgpApi.ACTION_DECRYPT_VERIFY: {
                return decryptAndVerifyImpl(data, inputStream, outputStream, false, progressable);
            }
            case OpenPgpApi.ACTION_DECRYPT_METADATA: {
                return decryptAndVerifyImpl(data, inputStream, outputStream, true, null);
            }
            case OpenPgpApi.ACTION_GET_SIGN_KEY_ID: {
                return getSignKeyIdImpl(data);
            }
            case OpenPgpApi.ACTION_GET_SIGN_KEY_ID_LEGACY: {
                return getSignKeyIdImplLegacy(data);
            }
            case OpenPgpApi.ACTION_GET_KEY_IDS: {
                return getKeyIdsImpl(data);
            }
            case OpenPgpApi.ACTION_GET_KEY: {
                return getKeyImpl(data, outputStream);
            }
            case OpenPgpApi.ACTION_BACKUP: {
                return backupImpl(data, outputStream);
            }
            case OpenPgpApi.ACTION_AUTOCRYPT_KEY_TRANSFER: {
                return autocryptKeyTransferImpl(data, outputStream);
            }
            case OpenPgpApi.ACTION_UPDATE_AUTOCRYPT_PEER: {
                return updateAutocryptPeerImpl(data);
            }
            default: {
                return null;
            }
        }
    }

    // ─── Action Implementations ─────────────────────────────────────────────

    private Intent signImpl(Intent data, InputStream inputStream,
                            OutputStream outputStream, boolean cleartextSign) {
        try {
            boolean asciiArmor = cleartextSign || data.getBooleanExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, true);

            PgpSignEncryptData.Builder pgpData = PgpSignEncryptData.builder();
            pgpData.setEnableAsciiArmorOutput(asciiArmor)
                    .setCleartextSignature(cleartextSign)
                    .setDetachedSignature(!cleartextSign)
                    .setVersionHeader(null);

            Intent signKeyIdIntent = resolveSignKeyId(data);
            if (signKeyIdIntent.getIntExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_SUCCESS)
                    == OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED) {
                return signKeyIdIntent;
            }

            long signKeyId = signKeyIdIntent.getLongExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID, Constants.key.none);
            if (signKeyId == Constants.key.none) {
                throw new Exception("No signing key given");
            } else {
                pgpData.setSignatureMasterKeyId(signKeyId);
                try {
                    long signSubKeyId = mKeyRepository.getSecretSignId(signKeyId);
                    pgpData.setSignatureSubKeyId(signSubKeyId);
                } catch (NotFoundException e) {
                    throw new Exception("signing subkey not found!", e);
                }
            }
            pgpData.setAllowedSigningKeyIds(getAllowedKeyIds());

            if (!cleartextSign) {
                outputStream = null;
            }
            long inputLength = inputStream.available();
            InputData inputData = new InputData(inputStream, inputLength);

            CryptoInputParcel inputParcel = retrieveCryptoInputParcel(data);
            if (data.hasExtra(OpenPgpApi.EXTRA_PASSPHRASE)) {
                inputParcel = inputParcel.withPassphrase(
                        new Passphrase(data.getCharArrayExtra(OpenPgpApi.EXTRA_PASSPHRASE)), null);
            }

            PgpSignEncryptOperation pse = new PgpSignEncryptOperation(mContext, mKeyRepository, null);
            PgpSignEncryptResult pgpResult = pse.execute(pgpData.build(), inputParcel, inputData, outputStream);

            if (pgpResult.isPending()) {
                RequiredInputParcel requiredInput = pgpResult.getRequiredInputParcel();
                PendingIntent pIntent = mApiPendingIntentFactory.requiredInputPi(data,
                        requiredInput, pgpResult.mCryptoInputParcel);
                return mResultBuilder.createUserInteractionRequiredResult(pIntent);
            } else if (pgpResult.success()) {
                byte[] detachedSig = pgpResult.getDetachedSignature();
                String micAlg = pgpResult.getMicAlgDigestName();
                if (detachedSig != null && !cleartextSign) {
                    return mResultBuilder.createSignSuccessResult(detachedSig, micAlg);
                }
                return mResultBuilder.createSignSuccessResult(null, null);
            } else {
                LogEntryParcel errorMsg = pgpResult.getLog().getLast();
                throw new Exception(mContext.getString(errorMsg.mType.getMsgId()));
            }
        } catch (Exception e) {
            Timber.d(e, "signImpl");
            return mResultBuilder.createErrorResult(OpenPgpError.GENERIC_ERROR, e.getMessage());
        }
    }

    private Intent autocryptQueryImpl(Intent data) {
        try {
            KeyIdResult keyIdResult = mKeyIdExtractor.returnKeyIdsFromIntent(data, false,
                    mApiPermissionHelper.getCurrentCallingPackage());
            return getAutocryptStatusResult(keyIdResult);
        } catch (Exception e) {
            Timber.d(e, "encryptAndSignImpl");
            return mResultBuilder.createErrorResult(OpenPgpError.GENERIC_ERROR, e.getMessage());
        }
    }

    private Intent encryptAndSignImpl(Intent data, InputStream inputStream,
            OutputStream outputStream, boolean sign) {
        try {
            PgpSignEncryptData.Builder pgpData = PgpSignEncryptData.builder()
                    .setVersionHeader(null);

            if (sign) {
                Intent signKeyIdIntent = resolveSignKeyId(data);
                if (signKeyIdIntent.getIntExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_ERROR)
                        == OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED) {
                    return signKeyIdIntent;
                }

                long signKeyId = signKeyIdIntent.getLongExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID, Constants.key.none);
                if (signKeyId == Constants.key.none) {
                    throw new Exception("No signing key given");
                }
                long signSubKeyId = mKeyRepository.getSecretSignId(signKeyId);

                pgpData.setSignatureMasterKeyId(signKeyId)
                        .setSignatureSubKeyId(signSubKeyId)
                        .setAdditionalEncryptId(signKeyId);
            }

            KeyIdResult keyIdResult = mKeyIdExtractor.returnKeyIdsFromIntent(data, false,
                    mApiPermissionHelper.getCurrentCallingPackage());

            KeyIdResultStatus keyIdResultStatus = keyIdResult.getStatus();

            boolean asciiArmor = data.getBooleanExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, true);
            pgpData.setEnableAsciiArmorOutput(asciiArmor);

            boolean enableCompression = data.getBooleanExtra(OpenPgpApi.EXTRA_ENABLE_COMPRESSION, true);
            pgpData.setCompressionAlgorithm(enableCompression ? OpenKeychainCompressionAlgorithmTags.USE_DEFAULT :
                    OpenKeychainCompressionAlgorithmTags.UNCOMPRESSED);

            String originalFilename = data.getStringExtra(OpenPgpApi.EXTRA_ORIGINAL_FILENAME);
            if (originalFilename == null) {
                originalFilename = "";
            }

            if (keyIdResult.hasKeySelectionPendingIntent()) {
                boolean isOpportunistic = data.getBooleanExtra(OpenPgpApi.EXTRA_OPPORTUNISTIC_ENCRYPTION, false);
                if ((keyIdResultStatus == KeyIdResultStatus.MISSING || keyIdResultStatus == KeyIdResultStatus.NO_KEYS ||
                        keyIdResultStatus == KeyIdResultStatus.NO_KEYS_ERROR) && isOpportunistic) {
                    return mResultBuilder.createErrorResult(OpenPgpError.OPPORTUNISTIC_MISSING_KEYS,
                            "missing keys in opportunistic mode");
                }

                return mResultBuilder.createUserInteractionRequiredResult(keyIdResult.getKeySelectionPendingIntent());
            }
            pgpData.setEncryptionMasterKeyIds(keyIdResult.getKeyIds());
            pgpData.setAllowedSigningKeyIds(getAllowedKeyIds());

            CryptoInputParcel inputParcel = retrieveCryptoInputParcel(data);
            if (data.hasExtra(OpenPgpApi.EXTRA_PASSPHRASE)) {
                inputParcel = inputParcel.withPassphrase(
                        new Passphrase(data.getCharArrayExtra(OpenPgpApi.EXTRA_PASSPHRASE)), null);
            }

            long inputLength = inputStream.available();
            InputData inputData = new InputData(inputStream, inputLength, originalFilename);

            PgpSignEncryptOperation op = new PgpSignEncryptOperation(mContext, mKeyRepository, null);
            PgpSignEncryptResult pgpResult = op.execute(pgpData.build(), inputParcel, inputData, outputStream);

            if (pgpResult.isPending()) {
                RequiredInputParcel requiredInput = pgpResult.getRequiredInputParcel();
                PendingIntent pIntent = mApiPendingIntentFactory.requiredInputPi(data,
                        requiredInput, pgpResult.mCryptoInputParcel);
                return mResultBuilder.createUserInteractionRequiredResult(pIntent);
            } else if (pgpResult.success()) {
                return mResultBuilder.createSuccessResult();
            } else {
                LogEntryParcel errorMsg = pgpResult.getLog().getLast();
                throw new Exception(mContext.getString(errorMsg.mType.getMsgId()));
            }
        } catch (Exception e) {
            Timber.d(e, "encryptAndSignImpl");
            return mResultBuilder.createErrorResult(OpenPgpError.GENERIC_ERROR, e.getMessage());
        }
    }

    private Intent decryptAndVerifyImpl(Intent data, InputStream inputStream, OutputStream outputStream,
            boolean decryptMetadataOnly, Progressable progressable) {
        try {
            if (decryptMetadataOnly) {
                outputStream = null;
            }

            int targetApiVersion = data.getIntExtra(OpenPgpApi.EXTRA_API_VERSION, -1);

            CryptoInputParcel cryptoInput = retrieveCryptoInputParcelForDecrypt(data);
            if (data.hasExtra(OpenPgpApi.EXTRA_PASSPHRASE)) {
                cryptoInput = cryptoInput.withPassphrase(
                        new Passphrase(data.getCharArrayExtra(OpenPgpApi.EXTRA_PASSPHRASE)), null);
            }
            if (data.hasExtra(OpenPgpApi.EXTRA_DECRYPTION_RESULT)) {
                OpenPgpDecryptionResult decryptionResult = data.getParcelableExtra(OpenPgpApi.EXTRA_DECRYPTION_RESULT);
                if (decryptionResult != null && decryptionResult.hasDecryptedSessionKey()) {
                    cryptoInput = cryptoInput.withCryptoData(
                            decryptionResult.getSessionKey(), decryptionResult.getDecryptedSessionKey());
                }
            }

            byte[] detachedSignature = data.getByteArrayExtra(OpenPgpApi.EXTRA_DETACHED_SIGNATURE);
            String senderAddress = data.getStringExtra(OpenPgpApi.EXTRA_SENDER_ADDRESS);

            updateAutocryptPeerImpl(data);

            PgpDecryptVerifyOperation op = new PgpDecryptVerifyOperation(mContext, mKeyRepository, progressable);

            long inputLength = data.getLongExtra(OpenPgpApi.EXTRA_DATA_LENGTH, InputData.UNKNOWN_FILESIZE);
            InputData inputData = new InputData(inputStream, inputLength);

            PgpDecryptVerifyInputParcel input = PgpDecryptVerifyInputParcel.builder()
                    .setAllowSymmetricDecryption(false)
                    .setAllowedKeyIds(new ArrayList<>(getAllowedKeyIds()))
                    .setDecryptMetadataOnly(decryptMetadataOnly)
                    .setDetachedSignature(detachedSignature)
                    .setSenderAddress(senderAddress)
                    .build();

            DecryptVerifyResult pgpResult = op.execute(input, cryptoInput, inputData, outputStream);

            if (pgpResult.isPending()) {
                RequiredInputParcel requiredInput = pgpResult.getRequiredInputParcel();
                PendingIntent pIntent = mApiPendingIntentFactory.requiredInputPi(data,
                        requiredInput, pgpResult.mCryptoInputParcel);
                return mResultBuilder.createUserInteractionRequiredResult(pIntent);

            } else if (pgpResult.success()) {
                Intent result = mResultBuilder.createSuccessResult();

                processDecryptionResultForResultIntent(targetApiVersion, result, pgpResult.getDecryptionResult());
                processMetadataForResultIntent(result, pgpResult.getDecryptionMetadata());
                processSignatureResultForResultIntent(targetApiVersion, data, result, pgpResult);
                processSecurityProblemsPendingIntent(data, result, pgpResult);

                return result;
            } else {
                long[] skippedDisallowedEncryptionKeys = pgpResult.getSkippedDisallowedKeys();
                if (pgpResult.isKeysDisallowed() &&
                        skippedDisallowedEncryptionKeys != null && skippedDisallowedEncryptionKeys.length > 0) {
                    String packageName = mApiPermissionHelper.getCurrentCallingPackage();
                    PendingIntent pi = mApiPendingIntentFactory.createRequestKeyPermissionPendingIntent(
                            data, packageName, skippedDisallowedEncryptionKeys);
                    return mResultBuilder.createUserInteractionRequiredResult(pi);
                }

                String errorMsg = mContext.getString(pgpResult.getLog().getLast().mType.getMsgId());
                return mResultBuilder.createErrorResult(OpenPgpError.GENERIC_ERROR, errorMsg);
            }

        } catch (Exception e) {
            Timber.e(e, "decryptAndVerifyImpl");
            return mResultBuilder.createErrorResult(OpenPgpError.GENERIC_ERROR, e.getMessage());
        }
    }

    private Intent getKeyImpl(Intent data, OutputStream outputStream) {
        try {
            long masterKeyId;
            if (data.hasExtra(OpenPgpApi.EXTRA_KEY_ID)) {
                masterKeyId = data.getLongExtra(OpenPgpApi.EXTRA_KEY_ID, 0);
            } else if (data.hasExtra(OpenPgpApi.EXTRA_USER_ID)) {
                KeyIdResult keyIdResult = mKeyIdExtractor.returnKeyIdsFromEmails(
                        null, new String[] { data.getStringExtra(OpenPgpApi.EXTRA_USER_ID) },
                        mApiPermissionHelper.getCurrentCallingPackage());
                if (keyIdResult.getStatus() != KeyIdResultStatus.OK) {
                    Intent result = getAutocryptStatusResult(keyIdResult);
                    result.putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_ERROR);
                    return result;
                }
                masterKeyId = keyIdResult.getKeyIds()[0];
            } else {
                throw new IllegalArgumentException("Missing argument key_id or user_id!");
            }

            try {
                CanonicalizedPublicKeyRing keyRing =
                        mKeyRepository.getCanonicalizedPublicKeyRing(masterKeyId);

                Intent result = mResultBuilder.createSuccessResult();

                if (data.getBooleanExtra(OpenPgpApi.EXTRA_MINIMIZE, false)) {
                    String userIdToKeep = data.getStringExtra(OpenPgpApi.EXTRA_MINIMIZE_USER_ID);
                    keyRing = keyRing.minimize(userIdToKeep);
                }

                boolean requestedKeyData = outputStream != null;
                if (requestedKeyData) {
                    boolean requestAsciiArmor = data.getBooleanExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, false);

                    try {
                        if (requestAsciiArmor) {
                            outputStream = new ArmoredOutputStream(outputStream);
                        }
                        keyRing.encode(outputStream);
                    } finally {
                        try {
                            outputStream.close();
                        } catch (IOException e) {
                            Timber.e(e, "IOException when closing OutputStream");
                        }
                    }
                }

                result.putExtra(OpenPgpApi.RESULT_INTENT,
                        mApiPendingIntentFactory.createShowKeyPendingIntent(data, masterKeyId));

                return result;
            } catch (KeyRepository.NotFoundException e) {
                PendingIntent pi = mApiPendingIntentFactory.createImportFromKeyserverPendingIntent(data, masterKeyId);
                return mResultBuilder.createUserInteractionRequiredResult(pi);
            }
        } catch (Exception e) {
            Timber.d(e, "getKeyImpl");
            return mResultBuilder.createErrorResult(OpenPgpError.GENERIC_ERROR, e.getMessage());
        }
    }

    Intent getSignKeyIdImplLegacy(Intent data) {
        if (data.hasExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID)) {
            long signKeyId = data.getLongExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID, Constants.key.none);

            Intent result = mResultBuilder.createSuccessResult();
            result.putExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID, signKeyId);
            return result;
        } else {
            String currentPkg = mApiPermissionHelper.getCurrentCallingPackage();
            byte[] packageSignature = mApiPermissionHelper.getPackageCertificateOrError(currentPkg);
            String preferredUserId = data.getStringExtra(OpenPgpApi.EXTRA_USER_ID);

            PendingIntent pi = mApiPendingIntentFactory.createSelectSignKeyIdLegacyPendingIntent(
                    data, currentPkg, packageSignature, preferredUserId);

            return mResultBuilder.createUserInteractionRequiredResult(pi);
        }
    }

    Intent getSignKeyIdImpl(Intent data) {
        data.setAction(OpenPgpApi.ACTION_GET_SIGN_KEY_ID);

        String currentPkg = mApiPermissionHelper.getCurrentCallingPackage();
        byte[] packageSignature = mApiPermissionHelper.getPackageCertificateOrError(currentPkg);
        String preferredUserId = data.getStringExtra(OpenPgpApi.EXTRA_USER_ID);
        PendingIntent pi;
        if (TextUtils.isEmpty(preferredUserId)) {
            pi = mApiPendingIntentFactory.createSelectSignKeyIdLegacyPendingIntent(
                    data, currentPkg, packageSignature, null);
        } else {
            boolean showAutocryptHint = data.getBooleanExtra(OpenPgpApi.EXTRA_SHOW_AUTOCRYPT_HINT, false);
            pi = mApiPendingIntentFactory.createSelectSignKeyIdPendingIntent(
                    data, currentPkg, packageSignature, preferredUserId, showAutocryptHint);
        }

        long signKeyId;
        boolean alreadySelected;
        if (data.hasExtra(OpenPgpApi.RESULT_SIGN_KEY_ID)) {
            signKeyId = data.getLongExtra(OpenPgpApi.RESULT_SIGN_KEY_ID, Constants.key.none);
            alreadySelected = true;
        } else {
            signKeyId = data.getLongExtra(OpenPgpApi.EXTRA_PRESELECT_KEY_ID, Constants.key.none);
            alreadySelected = false;
        }

        Intent result = mResultBuilder.createSignKeyIdResult(signKeyId, null, 0, alreadySelected);
        result.putExtra(OpenPgpApi.RESULT_INTENT, pi);

        if (signKeyId != Constants.key.none) {
            UnifiedKeyInfo unifiedKeyInfo = mKeyRepository.getUnifiedKeyInfo(signKeyId);
            if (unifiedKeyInfo == null) {
                Timber.e("Error loading key info");
                return mResultBuilder.createErrorResult(OpenPgpError.GENERIC_ERROR, "Signing key not found!");
            }
            String userId = unifiedKeyInfo.user_id();
            long creationTime = unifiedKeyInfo.creation() * 1000;

            result.putExtra(OpenPgpApi.RESULT_PRIMARY_USER_ID, userId);
            result.putExtra(OpenPgpApi.RESULT_KEY_CREATION_TIME, creationTime);
        }

        return result;
    }

    private Intent getKeyIdsImpl(Intent data) {
        KeyIdResult keyIdResult = mKeyIdExtractor.returnKeyIdsFromIntent(data, true,
                mApiPermissionHelper.getCurrentCallingPackage());
        if (keyIdResult.hasKeySelectionPendingIntent()) {
            return mResultBuilder.createUserInteractionRequiredResult(keyIdResult.getKeySelectionPendingIntent());
        }
        long[] keyIds = keyIdResult.getKeyIds();

        Intent result = mResultBuilder.createSuccessResult();
        result.putExtra(OpenPgpApi.RESULT_KEY_IDS, keyIds);
        return result;
    }

    private Intent backupImpl(Intent data, OutputStream outputStream) {
        try {
            long[] masterKeyIds = data.getLongArrayExtra(OpenPgpApi.EXTRA_KEY_IDS);
            boolean backupSecret = data.getBooleanExtra(OpenPgpApi.EXTRA_BACKUP_SECRET, false);
            boolean enableAsciiArmorOutput = data.getBooleanExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, true);

            CryptoInputParcel inputParcel = CryptoInputParcelCacheService.getCryptoInputParcel(mContext, data);
            if (inputParcel == null) {
                PendingIntent pi = mApiPendingIntentFactory.createBackupPendingIntent(data, masterKeyIds, backupSecret);
                return mResultBuilder.createUserInteractionRequiredResult(pi);
            }

            BackupKeyringParcel input = BackupKeyringParcel
                    .create(masterKeyIds, backupSecret, true, enableAsciiArmorOutput, null);
            BackupOperation op = new BackupOperation(mContext, mKeyRepository, null);
            ExportResult pgpResult = op.execute(input, inputParcel, outputStream);

            if (pgpResult.success()) {
                return mResultBuilder.createSuccessResult();
            } else {
                String errorMsg = mContext.getString(pgpResult.getLog().getLast().mType.getMsgId());
                return mResultBuilder.createErrorResult(OpenPgpError.GENERIC_ERROR, errorMsg);
            }
        } catch (Exception e) {
            Timber.d(e, "backupImpl");
            return mResultBuilder.createErrorResult(OpenPgpError.GENERIC_ERROR, e.getMessage());
        }
    }

    private Intent autocryptKeyTransferImpl(Intent data, OutputStream outputStream) {
        try {
            long[] masterKeyIds = data.getLongArrayExtra(OpenPgpApi.EXTRA_KEY_IDS);

            HashSet<Long> allowedKeyIds = getAllowedKeyIds();
            for (long masterKeyId : masterKeyIds) {
                if (!allowedKeyIds.contains(masterKeyId)) {
                    String packageName = mApiPermissionHelper.getCurrentCallingPackage();
                    PendingIntent pi = mApiPendingIntentFactory.createRequestKeyPermissionPendingIntent(
                            data, packageName, masterKeyId);
                    return mResultBuilder.createUserInteractionRequiredResult(pi);
                }
            }

            List<String> headerLines = data.getStringArrayListExtra(OpenPgpApi.EXTRA_CUSTOM_HEADERS);

            Passphrase autocryptTransferCode = Numeric9x4PassphraseUtil.generateNumeric9x4Passphrase();
            CryptoInputParcel inputParcel = CryptoInputParcel.createCryptoInputParcel(autocryptTransferCode);

            BackupKeyringParcel input = BackupKeyringParcel.createExportAutocryptSetupMessage(masterKeyIds, headerLines);
            BackupOperation op = new BackupOperation(mContext, mKeyRepository, null);
            ExportResult pgpResult = op.execute(input, inputParcel, outputStream);

            PendingIntent displayTransferCodePendingIntent =
                    mApiPendingIntentFactory.createDisplayTransferCodePendingIntent(autocryptTransferCode);

            if (pgpResult.success()) {
                Intent result = mResultBuilder.createSuccessResult();
                result.putExtra(OpenPgpApi.RESULT_INTENT, displayTransferCodePendingIntent);
                return result;
            } else {
                String errorMsg = mContext.getString(pgpResult.getLog().getLast().mType.getMsgId());
                return mResultBuilder.createErrorResult(OpenPgpError.GENERIC_ERROR, errorMsg);
            }
        } catch (Exception e) {
            Timber.d(e);
            return mResultBuilder.createErrorResult(OpenPgpError.GENERIC_ERROR, e.getMessage());
        }
    }

    Intent updateAutocryptPeerImpl(Intent data) {
        try {
            AutocryptInteractor autocryptInteractor = AutocryptInteractor.getInstance(
                    mContext, mApiPermissionHelper.getCurrentCallingPackage());

            if (data.hasExtra(OpenPgpApi.EXTRA_AUTOCRYPT_PEER_ID) &&
                    data.hasExtra(OpenPgpApi.EXTRA_AUTOCRYPT_PEER_UPDATE)) {
                String autocryptPeerId = data.getStringExtra(OpenPgpApi.EXTRA_AUTOCRYPT_PEER_ID);
                AutocryptPeerUpdate autocryptPeerUpdate = data.getParcelableExtra(OpenPgpApi.EXTRA_AUTOCRYPT_PEER_UPDATE);

                if (autocryptPeerUpdate != null) {
                    autocryptInteractor.updateAutocryptPeerState(autocryptPeerId, autocryptPeerUpdate);
                }
            }

            if (data.hasExtra(OpenPgpApi.EXTRA_AUTOCRYPT_PEER_GOSSIP_UPDATES)) {
                Bundle updates = data.getBundleExtra(OpenPgpApi.EXTRA_AUTOCRYPT_PEER_GOSSIP_UPDATES);
                for (String address : updates.keySet()) {
                    Timber.d(Constants.TAG, "Updating gossip state: " + address);
                    AutocryptPeerUpdate update = updates.getParcelable(address);
                    if (update != null) {
                        autocryptInteractor.updateAutocryptPeerGossipState(address, update);
                    }
                }
            }

            return mResultBuilder.createSuccessResult();
        } catch (Exception e) {
            Timber.d(e, "exception in updateAutocryptPeerImpl");
            return mResultBuilder.createErrorResult(OpenPgpError.GENERIC_ERROR, e.getMessage());
        }
    }

    private Intent checkPermissionImpl(@NonNull Intent data) {
        Intent permissionIntent = mApiPermissionHelper.isAllowedOrReturnIntent(data);
        if (permissionIntent != null) {
            return permissionIntent;
        }
        return mResultBuilder.createSuccessResult();
    }

    // ─── Decrypt result processing helpers ───────────────────────────────────

    private void processSecurityProblemsPendingIntent(Intent data, Intent result,
            DecryptVerifyResult decryptVerifyResult) {
        DecryptVerifySecurityProblem securityProblem = decryptVerifyResult.getSecurityProblem();
        if (securityProblem == null) {
            return;
        }

        boolean supportOverride = data.getBooleanExtra(OpenPgpApi.EXTRA_SUPPORT_OVERRIDE_CRYPTO_WARNING, false);
        if (supportOverride) {
            SecurityProblem prioritySecurityProblem = securityProblem.getPrioritySecurityProblem();
            if (prioritySecurityProblem.isIdentifiable()) {
                String identifier = prioritySecurityProblem.getIdentifier();
                boolean isOverridden = OverriddenWarningsDao.create(mContext)
                        .isWarningOverridden(identifier);
                result.putExtra(OpenPgpApi.RESULT_OVERRIDE_CRYPTO_WARNING, isOverridden);
            }
        }

        String packageName = mApiPermissionHelper.getCurrentCallingPackage();
        result.putExtra(OpenPgpApi.RESULT_INSECURE_DETAIL_INTENT,
                mApiPendingIntentFactory.createSecurityProblemIntent(packageName, securityProblem, supportOverride));
    }

    private void processDecryptionResultForResultIntent(int targetApiVersion, Intent result,
            OpenPgpDecryptionResult decryptionResult) {
        if (targetApiVersion < API_VERSION_WITH_DECRYPTION_RESULT) {
            return;
        }
        if (decryptionResult != null) {
            result.putExtra(OpenPgpApi.RESULT_DECRYPTION, decryptionResult);
        }
    }

    private OpenPgpSignatureResult getSignatureResultWithApiCompatibilityFallbacks(
            int targetApiVersion, DecryptVerifyResult pgpResult) {
        OpenPgpSignatureResult signatureResult = pgpResult.getSignatureResult();

        if (targetApiVersion < API_VERSION_WITH_KEY_INVALID_INSECURE) {
            if (signatureResult.getResult() == OpenPgpSignatureResult.RESULT_INVALID_KEY_INSECURE) {
                signatureResult = OpenPgpSignatureResult.createWithInvalidSignature();
            }
        }

        if (targetApiVersion < API_VERSION_WITHOUT_SIGNATURE_ONLY_FLAG) {
            OpenPgpDecryptionResult decryptionResult = pgpResult.getDecryptionResult();
            boolean signatureOnly = decryptionResult.getResult() == OpenPgpDecryptionResult.RESULT_NOT_ENCRYPTED
                    && signatureResult.getResult() != OpenPgpSignatureResult.RESULT_NO_SIGNATURE;
            // noinspection deprecation
            signatureResult = signatureResult.withSignatureOnlyFlag(signatureOnly);
        }

        return signatureResult;
    }

    private void processMetadataForResultIntent(Intent result, OpenPgpMetadata metadata) {
        String charset = metadata != null ? metadata.getCharset() : null;
        if (charset != null) {
            result.putExtra(OpenPgpApi.RESULT_CHARSET, charset);
        }
        if (metadata != null) {
            result.putExtra(OpenPgpApi.RESULT_METADATA, metadata);
        }
    }

    private void processSignatureResultForResultIntent(int targetApiVersion, Intent data,
            Intent result, DecryptVerifyResult pgpResult) {
        OpenPgpSignatureResult signatureResult =
                getSignatureResultWithApiCompatibilityFallbacks(targetApiVersion, pgpResult);

        switch (signatureResult.getResult()) {
            case OpenPgpSignatureResult.RESULT_KEY_MISSING: {
                result.putExtra(OpenPgpApi.RESULT_INTENT,
                        mApiPendingIntentFactory.createImportFromKeyserverPendingIntent(data,
                                signatureResult.getKeyId()));
                break;
            }
            case OpenPgpSignatureResult.RESULT_VALID_KEY_CONFIRMED:
            case OpenPgpSignatureResult.RESULT_VALID_KEY_UNCONFIRMED:
            case OpenPgpSignatureResult.RESULT_INVALID_KEY_REVOKED:
            case OpenPgpSignatureResult.RESULT_INVALID_KEY_EXPIRED:
            case OpenPgpSignatureResult.RESULT_INVALID_KEY_INSECURE: {
                result.putExtra(OpenPgpApi.RESULT_INTENT,
                        mApiPendingIntentFactory.createShowKeyPendingIntent(data, signatureResult.getKeyId()));
                break;
            }
            default:
            case OpenPgpSignatureResult.RESULT_NO_SIGNATURE: {
                if (targetApiVersion < API_VERSION_WITH_RESULT_NO_SIGNATURE) {
                    signatureResult = null;
                }
            }

            case OpenPgpSignatureResult.RESULT_INVALID_SIGNATURE: {
                // no key id -> no PendingIntent
            }
        }

        String autocryptPeerentity = data.getStringExtra(OpenPgpApi.EXTRA_AUTOCRYPT_PEER_ID);
        if (autocryptPeerentity != null) {
            if (targetApiVersion < API_VERSION_WITH_AUTOCRYPT) {
                throw new IllegalStateException("API version conflict, autocrypt is supported v12 and up!");
            }
            signatureResult = processAutocryptPeerInfoToSignatureResult(signatureResult, autocryptPeerentity);
        }

        result.putExtra(OpenPgpApi.RESULT_SIGNATURE, signatureResult);
    }

    private OpenPgpSignatureResult processAutocryptPeerInfoToSignatureResult(
            OpenPgpSignatureResult signatureResult, String autocryptPeerId) {
        boolean hasValidSignature =
                signatureResult.getResult() == OpenPgpSignatureResult.RESULT_VALID_KEY_CONFIRMED ||
                signatureResult.getResult() == OpenPgpSignatureResult.RESULT_VALID_KEY_UNCONFIRMED;
        if (!hasValidSignature) {
            return signatureResult;
        }

        AutocryptPeerDao autocryptPeerentityDao =
                AutocryptPeerDao.getInstance(mContext);
        String packageName = mApiPermissionHelper.getCurrentCallingPackage();
        Autocrypt_peers autocryptPeer = autocryptPeerentityDao.getAutocryptPeer(packageName, autocryptPeerId);

        long masterKeyId = signatureResult.getKeyId();
        if (autocryptPeer == null) {
            Date now = new Date();
            Date effectiveTime = signatureResult.getSignatureTimestamp();
            if (effectiveTime.after(now)) {
                effectiveTime = now;
            }
            AutocryptInteractor autocryptInteractor =
                    AutocryptInteractor.getInstance(mContext, mApiPermissionHelper.getCurrentCallingPackage());
            autocryptInteractor.updateKeyGossipFromSignature(autocryptPeerId, effectiveTime, masterKeyId);
            return signatureResult.withAutocryptPeerResult(AutocryptPeerResult.NEW);
        } else if (autocryptPeer.getMaster_key_id() != null && masterKeyId == autocryptPeer.getMaster_key_id()) {
            return signatureResult.withAutocryptPeerResult(AutocryptPeerResult.OK);
        } else {
            return signatureResult.withAutocryptPeerResult(AutocryptPeerResult.MISMATCH);
        }
    }

    // ─── Autocrypt status result ────────────────────────────────────────────

    @NonNull
    Intent getAutocryptStatusResult(KeyIdResult keyIdResult) {
        Intent result = mResultBuilder.createSuccessResult();
        result.putExtra(OpenPgpApi.RESULT_KEYS_CONFIRMED, keyIdResult.isAllKeysConfirmed());

        int combinedAutocryptState = keyIdResult.getAutocryptRecommendation();
        if (combinedAutocryptState == AutocryptStatus.AUTOCRYPT_PEER_DISABLED) {
            switch (keyIdResult.getStatus()) {
                case NO_KEYS:
                case NO_KEYS_ERROR:
                case MISSING: {
                    result.putExtra(OpenPgpApi.RESULT_AUTOCRYPT_STATUS, OpenPgpApi.AUTOCRYPT_STATUS_UNAVAILABLE);
                    break;
                }
                case DUPLICATE: {
                    if (keyIdResult.hasKeySelectionPendingIntent()) {
                        result.putExtra(OpenPgpApi.RESULT_INTENT, keyIdResult.getKeySelectionPendingIntent());
                    }
                    result.putExtra(OpenPgpApi.RESULT_AUTOCRYPT_STATUS, OpenPgpApi.AUTOCRYPT_STATUS_DISCOURAGE);
                    break;
                }
                case OK: {
                    result.putExtra(OpenPgpApi.RESULT_AUTOCRYPT_STATUS, OpenPgpApi.AUTOCRYPT_STATUS_DISCOURAGE);
                    break;
                }
            }
            return result;
        }

        switch (combinedAutocryptState) {
            case AutocryptStatus.AUTOCRYPT_PEER_DISCOURAGED_OLD:
            case AutocryptStatus.AUTOCRYPT_PEER_GOSSIP: {
                result.putExtra(OpenPgpApi.RESULT_AUTOCRYPT_STATUS, OpenPgpApi.AUTOCRYPT_STATUS_DISCOURAGE);
                break;
            }
            case AutocryptStatus.AUTOCRYPT_PEER_AVAILABLE_EXTERNAL:
            case AutocryptStatus.AUTOCRYPT_PEER_AVAILABLE: {
                result.putExtra(OpenPgpApi.RESULT_AUTOCRYPT_STATUS, OpenPgpApi.AUTOCRYPT_STATUS_AVAILABLE);
                break;
            }
            case AutocryptStatus.AUTOCRYPT_PEER_MUTUAL: {
                result.putExtra(OpenPgpApi.RESULT_AUTOCRYPT_STATUS, OpenPgpApi.AUTOCRYPT_STATUS_MUTUAL);
                break;
            }
            default: {
                throw new IllegalStateException("unhandled case!");
            }
        }

        return result;
    }

    // ─── Shared helpers ─────────────────────────────────────────────────────

    /**
     * Retrieves a cached CryptoInputParcel from the cache service, or creates a fresh one
     * with the current timestamp. Used by sign and encrypt operations.
     */
    CryptoInputParcel retrieveCryptoInputParcel(Intent data) {
        CryptoInputParcel inputParcel = CryptoInputParcelCacheService.getCryptoInputParcel(mContext, data);
        if (inputParcel == null) {
            inputParcel = CryptoInputParcel.createCryptoInputParcel(new Date());
        }
        return inputParcel;
    }

    /**
     * Retrieves a cached CryptoInputParcel from the cache service, or creates a fresh one
     * without timestamp. Used by decrypt operations (preserving original behavior).
     */
    CryptoInputParcel retrieveCryptoInputParcelForDecrypt(Intent data) {
        CryptoInputParcel cryptoInput = CryptoInputParcelCacheService.getCryptoInputParcel(mContext, data);
        if (cryptoInput == null) {
            cryptoInput = CryptoInputParcel.createCryptoInputParcel();
        }
        return cryptoInput;
    }

    /**
     * Resolves the signing key master ID from the Intent. If EXTRA_SIGN_KEY_ID is present,
     * returns the data Intent directly. Otherwise delegates to getSignKeyIdImpl which may
     * return a USER_INTERACTION_REQUIRED result.
     */
    Intent resolveSignKeyId(Intent data) {
        long signKeyId = data.getLongExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID, Constants.key.none);
        if (signKeyId == Constants.key.none) {
            return getSignKeyIdImpl(data);
        }
        return data;
    }

    HashSet<Long> getAllowedKeyIds() {
        String currentPkg = mApiPermissionHelper.getCurrentCallingPackage();
        return mApiAppDao.getAllowedKeyIdsForApp(currentPkg);
    }
}
