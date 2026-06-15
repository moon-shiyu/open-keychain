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
import org.openintents.ssh.authentication.SshAuthenticationApi;
import org.openintents.ssh.authentication.SshAuthenticationApiError;
import timber.log.Timber;


/**
 * Centralizes construction of SSH Authentication API result Intents.
 *
 * SSH uses different extra keys than OpenPGP:
 * - EXTRA_RESULT_CODE instead of RESULT_CODE
 * - EXTRA_ERROR (SshAuthenticationApiError) instead of RESULT_ERROR (OpenPgpError)
 * - EXTRA_PENDING_INTENT instead of RESULT_INTENT
 */
public class SshResultBuilder {

    /**
     * Creates a basic success result Intent. SSH responses are typically built by
     * the response classes (SigningResponse, KeySelectionResponse, etc.) via toIntent(),
     * so this is mainly used for simple success cases.
     */
    @NonNull
    public Intent createSuccessResult() {
        Intent result = new Intent();
        result.putExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, SshAuthenticationApi.RESULT_CODE_SUCCESS);
        return result;
    }

    /**
     * Creates an error result Intent containing an SshAuthenticationApiError.
     */
    @NonNull
    public Intent createErrorResult(int errorCode, String errorMessage) {
        Timber.e(errorMessage);
        Intent result = new Intent();
        result.putExtra(SshAuthenticationApi.EXTRA_ERROR,
                new SshAuthenticationApiError(errorCode, errorMessage));
        result.putExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, SshAuthenticationApi.RESULT_CODE_ERROR);
        return result;
    }

    /**
     * Creates an error result from an exception, appending the exception message.
     */
    @NonNull
    public Intent createExceptionErrorResult(int errorCode, String errorMessage, Exception e) {
        String message = errorMessage + " : " + e.getMessage();
        return createErrorResult(errorCode, message);
    }

    /**
     * Creates a user-interaction-required result Intent with a PendingIntent.
     * SSH uses EXTRA_PENDING_INTENT (not RESULT_INTENT like OpenPGP).
     */
    @NonNull
    public Intent createUserInteractionRequiredResult(@NonNull PendingIntent pendingIntent) {
        Intent result = new Intent();
        result.putExtra(SshAuthenticationApi.EXTRA_RESULT_CODE,
                SshAuthenticationApi.RESULT_CODE_USER_INTERACTION_REQUIRED);
        result.putExtra(SshAuthenticationApi.EXTRA_PENDING_INTENT, pendingIntent);
        return result;
    }
}
