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
import org.openintents.openpgp.OpenPgpError;
import org.openintents.openpgp.util.OpenPgpApi;


/**
 * Builds the result {@link Intent}s returned by {@link OpenPgpService} over the OpenPGP API.
 *
 * <p>This only centralises the {@code RESULT_*} extras that were previously assembled inline at
 * dozens of call sites; the keys and values emitted are intentionally identical to the previous
 * inline code so the wire protocol with API clients is unchanged.
 */
final class OpenPgpApiResult {

    private OpenPgpApiResult() {
    }

    @NonNull
    static Intent success() {
        Intent result = new Intent();
        result.putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_SUCCESS);
        return result;
    }

    @NonNull
    static Intent userInteractionRequired(PendingIntent pendingIntent) {
        Intent result = new Intent();
        result.putExtra(OpenPgpApi.RESULT_INTENT, pendingIntent);
        result.putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED);
        return result;
    }

    @NonNull
    static Intent error(int errorCode, String errorMsg) {
        Intent result = new Intent();
        result.putExtra(OpenPgpApi.RESULT_ERROR, new OpenPgpError(errorCode, errorMsg));
        result.putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_ERROR);
        return result;
    }
}
