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


import java.util.Collections;
import java.util.List;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

import org.openintents.ssh.authentication.ISshAuthenticationService;
import org.openintents.ssh.authentication.SshAuthenticationApi;
import org.openintents.ssh.authentication.SshAuthenticationApiError;
import org.sufficientlysecure.keychain.daos.ApiAppDao;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import timber.log.Timber;


/**
 * Bound service exposing the SSH Authentication API (ISshAuthenticationService AIDL interface).
 *
 * This service handles:
 * - AIDL binder lifecycle
 * - Requirements checking (null data, API version, permission)
 *
 * All action-specific business logic is delegated to {@link SshActionHandler}.
 */
public class SshAuthenticationService extends Service {
    private ApiPermissionHelper mApiPermissionHelper;
    private SshActionHandler mActionHandler;

    private static final List<Integer> SUPPORTED_VERSIONS = Collections.unmodifiableList(Collections.singletonList(1));
    private static final int INVALID_API_VERSION = -1;

    @Override
    public void onCreate() {
        super.onCreate();
        KeyRepository keyRepository = KeyRepository.create(this);
        ApiAppDao apiAppDao = ApiAppDao.getInstance(this);
        mApiPermissionHelper = new ApiPermissionHelper(this, apiAppDao);

        ApiPendingIntentFactory apiPendingIntentFactory = new ApiPendingIntentFactory(getBaseContext());
        SshResultBuilder resultBuilder = new SshResultBuilder();

        mActionHandler = new SshActionHandler(this, keyRepository, apiAppDao,
                mApiPermissionHelper, apiPendingIntentFactory, resultBuilder);
    }

    private final ISshAuthenticationService.Stub mSSHAgent = new ISshAuthenticationService.Stub() {
        @Override
        public Intent execute(Intent intent) {
            return checkIntent(intent);
        }

    };

    @Override
    public IBinder onBind(Intent intent) {
        return mSSHAgent;
    }

    private Intent checkIntent(Intent intent) {
        Intent errorResult = checkRequirements(intent);
        if (errorResult == null) {
            return mActionHandler.dispatch(intent);
        } else {
            return errorResult;
        }
    }

    /**
     * @return null if basic requirements are met
     */
    private Intent checkRequirements(Intent data) {
        if (data == null) {
            return createErrorResult(SshAuthenticationApiError.GENERIC_ERROR, "No parameter bundle");
        }

        // check version
        int apiVersion = data.getIntExtra(SshAuthenticationApi.EXTRA_API_VERSION, INVALID_API_VERSION);
        if (!SUPPORTED_VERSIONS.contains(apiVersion)) {
            String errorMsg = "Incompatible API versions:\n"
                    + "used : " + data.getIntExtra(SshAuthenticationApi.EXTRA_API_VERSION, INVALID_API_VERSION) + "\n"
                    + "supported : " + SUPPORTED_VERSIONS;

            return createErrorResult(SshAuthenticationApiError.INCOMPATIBLE_API_VERSIONS, errorMsg);
        }

        // check if caller is allowed to access OpenKeychain
        Intent result = mApiPermissionHelper.isAllowedOrReturnIntent(data);
        if (result != null) {
            return result; // disallowed, redirect to registration
        }

        return null;
    }

    private Intent createErrorResult(int errorCode, String errorMessage) {
        Timber.e(errorMessage);
        Intent result = new Intent();
        result.putExtra(SshAuthenticationApi.EXTRA_ERROR, new SshAuthenticationApiError(errorCode, errorMessage));
        result.putExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, SshAuthenticationApi.RESULT_CODE_ERROR);
        return result;
    }

}
