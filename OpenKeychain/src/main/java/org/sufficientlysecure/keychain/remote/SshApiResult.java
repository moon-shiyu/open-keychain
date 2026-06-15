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


/**
 * Builds the result {@link Intent}s returned by {@link SshAuthenticationService} over the SSH
 * authentication API.
 *
 * <p>Kept separate from {@link OpenPgpApiResult} on purpose: although the two APIs happen to share
 * the same wire keys, they are distinct public contracts and should be free to evolve
 * independently. The extras emitted here are identical to the previous inline code.
 */
final class SshApiResult {

    private SshApiResult() {
    }

    @NonNull
    static Intent error(int errorCode, String errorMessage) {
        Intent result = new Intent();
        result.putExtra(SshAuthenticationApi.EXTRA_ERROR,
                new SshAuthenticationApiError(errorCode, errorMessage));
        result.putExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, SshAuthenticationApi.RESULT_CODE_ERROR);
        return result;
    }

    @NonNull
    static Intent userInteractionRequired(PendingIntent pendingIntent) {
        Intent result = new Intent();
        result.putExtra(SshAuthenticationApi.EXTRA_RESULT_CODE,
                SshAuthenticationApi.RESULT_CODE_USER_INTERACTION_REQUIRED);
        result.putExtra(SshAuthenticationApi.EXTRA_PENDING_INTENT, pendingIntent);
        return result;
    }
}
