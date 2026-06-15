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


import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashSet;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;

import androidx.annotation.NonNull;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.openintents.ssh.authentication.SshAuthenticationApi;
import org.openintents.ssh.authentication.SshAuthenticationApiError;
import org.openintents.ssh.authentication.response.KeySelectionResponse;
import org.openintents.ssh.authentication.response.PublicKeyResponse;
import org.openintents.ssh.authentication.response.SigningResponse;
import org.openintents.ssh.authentication.response.SshPublicKeyResponse;
import org.sufficientlysecure.keychain.Constants;
import org.sufficientlysecure.keychain.daos.ApiAppDao;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.daos.KeyRepository.NotFoundException;
import org.sufficientlysecure.keychain.model.UnifiedKeyInfo;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogEntryParcel;
import org.sufficientlysecure.keychain.pgp.CanonicalizedPublicKey;
import org.sufficientlysecure.keychain.pgp.SshPublicKey;
import org.sufficientlysecure.keychain.pgp.exception.PgpGeneralException;
import org.sufficientlysecure.keychain.pgp.exception.PgpKeyNotFoundException;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.service.input.RequiredInputParcel;
import org.sufficientlysecure.keychain.ssh.AuthenticationData;
import org.sufficientlysecure.keychain.ssh.AuthenticationOperation;
import org.sufficientlysecure.keychain.ssh.AuthenticationParcel;
import org.sufficientlysecure.keychain.ssh.AuthenticationResult;
import org.sufficientlysecure.keychain.ssh.signature.SshSignatureConverter;
import timber.log.Timber;


/**
 * Handles all SSH authentication API action implementations, extracted from
 * {@link SshAuthenticationService} for better testability and separation of concerns.
 *
 * This class contains the business logic for all 4 supported SSH API actions.
 * Permission checking is managed by the calling service.
 */
public class SshActionHandler {

    private static final int HASHALGORITHM_NONE = SshAuthenticationApiError.INVALID_HASH_ALGORITHM;

    private final Context mContext;
    private final KeyRepository mKeyRepository;
    private final ApiAppDao mApiAppDao;
    private final ApiPermissionHelper mApiPermissionHelper;
    private final ApiPendingIntentFactory mApiPendingIntentFactory;
    private final SshResultBuilder mResultBuilder;

    public SshActionHandler(Context context, KeyRepository keyRepository, ApiAppDao apiAppDao,
            ApiPermissionHelper apiPermissionHelper, ApiPendingIntentFactory apiPendingIntentFactory,
            SshResultBuilder resultBuilder) {
        mContext = context;
        mKeyRepository = keyRepository;
        mApiAppDao = apiAppDao;
        mApiPermissionHelper = apiPermissionHelper;
        mApiPendingIntentFactory = apiPendingIntentFactory;
        mResultBuilder = resultBuilder;
    }

    /**
     * Dispatches an SSH API call to the appropriate action handler method.
     *
     * @param intent the API call Intent with action and extras
     * @return result Intent with EXTRA_RESULT_CODE and optional extras
     */
    @NonNull
    public Intent dispatch(@NonNull Intent intent) {
        switch (intent.getAction()) {
            case SshAuthenticationApi.ACTION_SIGN:
                return authenticate(intent);
            case SshAuthenticationApi.ACTION_SELECT_KEY:
                return getAuthenticationKey(intent);
            case SshAuthenticationApi.ACTION_GET_PUBLIC_KEY:
                return getAuthenticationPublicKey(intent, false);
            case SshAuthenticationApi.ACTION_GET_SSH_PUBLIC_KEY:
                return getAuthenticationPublicKey(intent, true);
            default:
                return mResultBuilder.createErrorResult(SshAuthenticationApiError.UNKNOWN_ACTION, "Unknown action");
        }
    }

    // ─── Action Implementations ─────────────────────────────────────────────

    private Intent authenticate(Intent data) {
        Intent errorIntent = checkForKeyId(data);
        if (errorIntent != null) {
            return errorIntent;
        }

        String keyIdString = data.getStringExtra(SshAuthenticationApi.EXTRA_KEY_ID);
        long masterKeyId = Long.valueOf(keyIdString);

        int hashAlgorithmTag = getHashAlgorithm(data);
        if (hashAlgorithmTag == HASHALGORITHM_NONE) {
            return mResultBuilder.createErrorResult(SshAuthenticationApiError.GENERIC_ERROR, "No valid hash algorithm!");
        }

        byte[] challenge = data.getByteArrayExtra(SshAuthenticationApi.EXTRA_CHALLENGE);
        if (challenge == null || challenge.length == 0) {
            return mResultBuilder.createErrorResult(SshAuthenticationApiError.GENERIC_ERROR, "No challenge given");
        }

        AuthenticationData.Builder authData = AuthenticationData.builder();
        authData.setAuthenticationMasterKeyId(masterKeyId);

        long authSubKeyId;
        int authSubKeyAlgorithm;
        String authSubKeyCurveOid = null;
        try {
            authSubKeyId = mKeyRepository.getEffectiveAuthenticationKeyId(masterKeyId);
            authSubKeyAlgorithm = getPublicKey(masterKeyId).getAlgorithm();
            if (authSubKeyAlgorithm == PublicKeyAlgorithmTags.ECDSA) {
                authSubKeyCurveOid = getPublicKey(masterKeyId).getCurveOid();
            }
        } catch (NotFoundException e) {
            return mResultBuilder.createExceptionErrorResult(SshAuthenticationApiError.NO_SUCH_KEY,
                    "Key for master key id not found", e);
        }

        authData.setAuthenticationSubKeyId(authSubKeyId);
        authData.setAllowedAuthenticationKeyIds(getAllowedKeyIds());
        authData.setHashAlgorithm(hashAlgorithmTag);

        CryptoInputParcel inputParcel = retrieveCryptoInputParcel(data);

        AuthenticationParcel authParcel = AuthenticationParcel
                .createAuthenticationParcel(authData.build(), challenge);

        AuthenticationOperation authOperation = new AuthenticationOperation(mContext, mKeyRepository);
        AuthenticationResult authResult = authOperation.execute(authData.build(), inputParcel, authParcel);

        if (authResult.isPending()) {
            RequiredInputParcel requiredInput = authResult.getRequiredInputParcel();
            PendingIntent pi = mApiPendingIntentFactory.requiredInputPi(data, requiredInput,
                    authResult.mCryptoInputParcel);
            return mResultBuilder.createUserInteractionRequiredResult(pi);
        } else if (authResult.success()) {
            byte[] rawSignature = authResult.getSignature();
            byte[] sshSignature;
            try {
                sshSignature = convertSignature(rawSignature, authSubKeyAlgorithm, hashAlgorithmTag, authSubKeyCurveOid);
            } catch (NoSuchAlgorithmException e) {
                return mResultBuilder.createExceptionErrorResult(SshAuthenticationApiError.INTERNAL_ERROR,
                        "Error converting signature", e);
            }
            return new SigningResponse(sshSignature).toIntent();
        } else {
            LogEntryParcel errorMsg = authResult.getLog().getLast();
            return mResultBuilder.createErrorResult(SshAuthenticationApiError.INTERNAL_ERROR,
                    mContext.getString(errorMsg.mType.getMsgId()));
        }
    }

    private Intent getAuthenticationKey(Intent data) {
        long masterKeyId = getKeyId(data);
        if (masterKeyId != Constants.key.none) {
            String description;
            try {
                description = getDescription(masterKeyId);
            } catch (NotFoundException e) {
                return mResultBuilder.createExceptionErrorResult(SshAuthenticationApiError.NO_SUCH_KEY,
                        "Could not create description", e);
            }
            return new KeySelectionResponse(String.valueOf(masterKeyId), description).toIntent();
        } else {
            return redirectToKeySelection(data);
        }
    }

    private Intent getAuthenticationPublicKey(Intent data, boolean asSshKey) {
        long masterKeyId = getKeyId(data);
        if (masterKeyId != Constants.key.none) {
            try {
                if (asSshKey) {
                    return getSSHPublicKey(masterKeyId);
                } else {
                    return getX509PublicKey(masterKeyId);
                }
            } catch (KeyRepository.NotFoundException e) {
                return mResultBuilder.createExceptionErrorResult(SshAuthenticationApiError.NO_SUCH_KEY,
                        "Key for master key id not found", e);
            } catch (PgpKeyNotFoundException e) {
                return mResultBuilder.createExceptionErrorResult(SshAuthenticationApiError.NO_AUTH_KEY,
                        "Authentication key for master key id not found in keychain", e);
            } catch (NoSuchAlgorithmException e) {
                return mResultBuilder.createExceptionErrorResult(SshAuthenticationApiError.INVALID_ALGORITHM,
                        "Algorithm not supported", e);
            }
        } else {
            return mResultBuilder.createErrorResult(SshAuthenticationApiError.NO_KEY_ID,
                    "No key id in request");
        }
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    private Intent checkForKeyId(Intent data) {
        long authMasterKeyId = getKeyId(data);
        if (authMasterKeyId == Constants.key.none) {
            return mResultBuilder.createErrorResult(SshAuthenticationApiError.NO_KEY_ID,
                    "No key id in request");
        }
        return null;
    }

    private Intent redirectToKeySelection(Intent data) {
        String currentPkg = mApiPermissionHelper.getCurrentCallingPackage();
        PendingIntent pi = mApiPendingIntentFactory.createSelectAuthenticationKeyIdPendingIntent(data, currentPkg);
        return mResultBuilder.createUserInteractionRequiredResult(pi);
    }

    private Intent getX509PublicKey(long masterKeyId) throws KeyRepository.NotFoundException, PgpKeyNotFoundException, NoSuchAlgorithmException {
        PublicKey publicKey;
        try {
            publicKey = getPublicKey(masterKeyId).getJcaPublicKey();
        } catch (PgpGeneralException e) {
            return mResultBuilder.createExceptionErrorResult(SshAuthenticationApiError.GENERIC_ERROR,
                    "Error converting public key", e);
        }

        byte[] encodedPublicKey = publicKey.getEncoded();
        int algorithm = translateAlgorithm(publicKey.getAlgorithm());

        return new PublicKeyResponse(encodedPublicKey, algorithm).toIntent();
    }

    private Intent getSSHPublicKey(long masterKeyId) throws KeyRepository.NotFoundException {
        CanonicalizedPublicKey publicKey = getPublicKey(masterKeyId);

        SshPublicKey sshPublicKey = new SshPublicKey(publicKey);
        String sshPublicKeyBlob;
        try {
            sshPublicKeyBlob = sshPublicKey.getEncodedKey();
        } catch (PgpGeneralException | NoSuchAlgorithmException e) {
            return mResultBuilder.createExceptionErrorResult(SshAuthenticationApiError.GENERIC_ERROR,
                    "Error converting public key to SSH format", e);
        }

        return new SshPublicKeyResponse(sshPublicKeyBlob).toIntent();
    }

    private CanonicalizedPublicKey getPublicKey(long masterKeyId) throws NotFoundException {
        KeyRepository keyRepository = KeyRepository.create(mContext.getApplicationContext());
        long authKeyId = keyRepository.getEffectiveAuthenticationKeyId(masterKeyId);
        return keyRepository.getCanonicalizedPublicKeyRing(masterKeyId).getPublicKey(authKeyId);
    }

    private String getDescription(long masterKeyId) throws NotFoundException {
        UnifiedKeyInfo unifiedKeyInfo = mKeyRepository.getUnifiedKeyInfo(masterKeyId);
        String description = "";
        long authSubKeyId = mKeyRepository.getEffectiveAuthenticationKeyId(masterKeyId);
        description += unifiedKeyInfo.user_id();
        description += " (" + Long.toHexString(authSubKeyId) + ")";
        return description;
    }

    private HashSet<Long> getAllowedKeyIds() {
        String currentPkg = mApiPermissionHelper.getCurrentCallingPackage();
        return mApiAppDao.getAllowedKeyIdsForApp(currentPkg);
    }

    // ─── Package-private helpers (for testing) ─────────────────────────────

    /**
     * Retrieves a cached CryptoInputParcel from the cache service, or creates a fresh one.
     */
    CryptoInputParcel retrieveCryptoInputParcel(Intent data) {
        CryptoInputParcel inputParcel = CryptoInputParcelCacheService.getCryptoInputParcel(mContext, data);
        if (inputParcel == null) {
            inputParcel = CryptoInputParcel.createCryptoInputParcel(new Date());
        }
        return inputParcel;
    }

    /**
     * Parses the key ID from the Intent's EXTRA_KEY_ID string extra.
     * Returns Constants.key.none if missing or unparseable.
     */
    long getKeyId(Intent data) {
        String keyIdString = data.getStringExtra(SshAuthenticationApi.EXTRA_KEY_ID);
        long authMasterKeyId = Constants.key.none;
        if (keyIdString != null) {
            try {
                authMasterKeyId = Long.valueOf(keyIdString);
            } catch (NumberFormatException e) {
                return Constants.key.none;
            }
        }
        return authMasterKeyId;
    }

    /**
     * Maps the SSH API hash algorithm constant to the BouncyCastle HashAlgorithmTags constant.
     */
    int getHashAlgorithm(Intent data) {
        int hashAlgorithm = data.getIntExtra(SshAuthenticationApi.EXTRA_HASH_ALGORITHM, HASHALGORITHM_NONE);

        switch (hashAlgorithm) {
            case SshAuthenticationApi.SHA1:
                return HashAlgorithmTags.SHA1;
            case SshAuthenticationApi.RIPEMD160:
                return HashAlgorithmTags.RIPEMD160;
            case SshAuthenticationApi.SHA224:
                return HashAlgorithmTags.SHA224;
            case SshAuthenticationApi.SHA256:
                return HashAlgorithmTags.SHA256;
            case SshAuthenticationApi.SHA384:
                return HashAlgorithmTags.SHA384;
            case SshAuthenticationApi.SHA512:
                return HashAlgorithmTags.SHA512;
            default:
                return HASHALGORITHM_NONE;
        }
    }

    /**
     * Converts a raw PGP signature to SSH format based on the key algorithm.
     */
    byte[] convertSignature(byte[] rawSignature, int keyAlgorithm, int hashAlgorithm, String curveOid)
            throws NoSuchAlgorithmException {
        switch (keyAlgorithm) {
            case PublicKeyAlgorithmTags.EDDSA:
                return SshSignatureConverter.getSshSignatureEdDsa(rawSignature);
            case PublicKeyAlgorithmTags.RSA_SIGN:
            case PublicKeyAlgorithmTags.RSA_GENERAL:
                return SshSignatureConverter.getSshSignatureRsa(rawSignature, hashAlgorithm);
            case PublicKeyAlgorithmTags.ECDSA:
                return SshSignatureConverter.getSshSignatureEcDsa(rawSignature, curveOid);
            case PublicKeyAlgorithmTags.DSA:
                return SshSignatureConverter.getSshSignatureDsa(rawSignature);
            default:
                throw new NoSuchAlgorithmException("Unknown algorithm");
        }
    }

    private int translateAlgorithm(String algorithm) throws NoSuchAlgorithmException {
        switch (algorithm) {
            case "RSA":
                return SshAuthenticationApi.RSA;
            case "ECDSA":
                return SshAuthenticationApi.ECDSA;
            case "EdDSA":
                return SshAuthenticationApi.EDDSA;
            case "DSA":
                return SshAuthenticationApi.DSA;
            default:
                throw new NoSuchAlgorithmException("Error matching key algorithm to API supported algorithm: "
                        + algorithm);
        }
    }
}
