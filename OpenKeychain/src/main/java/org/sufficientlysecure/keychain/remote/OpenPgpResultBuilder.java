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


import android.app.PendingIntent;
import android.content.Intent;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import org.openintents.openpgp.OpenPgpError;
import org.openintents.openpgp.util.OpenPgpApi;


/**
 * Centralizes construction of OpenPGP API result Intents.
 *
 * All result Intents returned by the OpenPGP API follow one of three patterns:
 * - SUCCESS: RESULT_CODE = RESULT_CODE_SUCCESS, with optional extras
 * - ERROR: RESULT_CODE = RESULT_CODE_ERROR + RESULT_ERROR containing an OpenPgpError
 * - USER_INTERACTION_REQUIRED: RESULT_CODE = RESULT_CODE_USER_INTERACTION_REQUIRED + RESULT_INTENT
 *
 * This builder ensures consistent result Intent structure across all action handlers.
 */
public class OpenPgpResultBuilder {

    /**
     * Creates a basic success result Intent with no additional extras.
     */
    @NonNull
    public Intent createSuccessResult() {
        Intent result = new Intent();
        result.putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_SUCCESS);
        return result;
    }

    /**
     * Creates an error result Intent containing an OpenPgpError parcelable.
     */
    @NonNull
    public Intent createErrorResult(int errorCode, String errorMsg) {
        Intent result = new Intent();
        result.putExtra(OpenPgpApi.RESULT_ERROR, new OpenPgpError(errorCode, errorMsg));
        result.putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_ERROR);
        return result;
    }

    /**
     * Creates a user-interaction-required result Intent with a PendingIntent
     * that the client should fire to complete the operation.
     */
    @NonNull
    public Intent createUserInteractionRequiredResult(@NonNull PendingIntent pendingIntent) {
        Intent result = new Intent();
        result.putExtra(OpenPgpApi.RESULT_INTENT, pendingIntent);
        result.putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED);
        return result;
    }

    /**
     * Creates a success result for sign operations. If a detached signature is present
     * (non-cleartext detached sign), it is included along with the MIC algorithm digest name.
     *
     * @param detachedSignature the detached signature bytes, or null for cleartext/non-detached
     * @param micAlgDigestName  the MIC algorithm digest name, or null
     */
    @NonNull
    public Intent createSignSuccessResult(@Nullable byte[] detachedSignature,
            @Nullable String micAlgDigestName) {
        Intent result = new Intent();
        if (detachedSignature != null) {
            result.putExtra(OpenPgpApi.RESULT_DETACHED_SIGNATURE, detachedSignature);
            result.putExtra(OpenPgpApi.RESULT_SIGNATURE_MICALG, micAlgDigestName);
        }
        result.putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_SUCCESS);
        return result;
    }

    /**
     * Creates a success result for the GET_SIGN_KEY_ID action, including the key ID,
     * primary user ID, and creation time.
     *
     * @param signKeyId    the signing master key ID
     * @param userId       the primary user ID string
     * @param creationTime the key creation time in milliseconds
     * @param alreadySelected true if the key was already selected (SUCCESS), false if
     *                        user interaction is still needed (USER_INTERACTION_REQUIRED)
     */
    @NonNull
    public Intent createSignKeyIdResult(long signKeyId, @Nullable String userId,
            long creationTime, boolean alreadySelected) {
        Intent result = new Intent();
        result.putExtra(OpenPgpApi.RESULT_SIGN_KEY_ID, signKeyId);

        if (signKeyId != 0) {
            result.putExtra(OpenPgpApi.RESULT_PRIMARY_USER_ID, userId);
            result.putExtra(OpenPgpApi.RESULT_KEY_CREATION_TIME, creationTime);
        }

        if (alreadySelected) {
            result.putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_SUCCESS);
        } else {
            result.putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED);
        }
        return result;
    }
}
