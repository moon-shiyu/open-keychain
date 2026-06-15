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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.os.SystemClock;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import org.openintents.openpgp.IOpenPgpService;
import org.openintents.openpgp.OpenPgpError;
import org.openintents.openpgp.util.OpenPgpApi;
import org.sufficientlysecure.keychain.daos.ApiAppDao;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.pgp.Progressable;
import timber.log.Timber;


/**
 * Bound service exposing the OpenPGP API (IOpenPgpService AIDL interface).
 *
 * This service handles:
 * - AIDL binder lifecycle
 * - Stream management (ParcelFileDescriptor → auto-close streams)
 * - Requirements checking (null data, API version, permission)
 *
 * All action-specific business logic is delegated to {@link OpenPgpActionHandler}.
 */
public class OpenPgpService extends Service {
    public static final int API_VERSION_WITH_KEY_INVALID_INSECURE = 8;
    public static final int API_VERSION_WITHOUT_SIGNATURE_ONLY_FLAG = 8;
    public static final int API_VERSION_WITH_DECRYPTION_RESULT = 8;
    public static final int API_VERSION_WITH_RESULT_NO_SIGNATURE = 8;
    public static final int API_VERSION_WITH_AUTOCRYPT = 12;

    public static final List<Integer> SUPPORTED_VERSIONS =
            Collections.unmodifiableList(Arrays.asList(7, 8, 9, 10, 11, 12));

    private ApiPermissionHelper mApiPermissionHelper;
    private OpenPgpActionHandler mActionHandler;

    @Override
    public void onCreate() {
        super.onCreate();
        KeyRepository keyRepository = KeyRepository.create(this);
        ApiAppDao apiAppDao = ApiAppDao.getInstance(this);
        mApiPermissionHelper = new ApiPermissionHelper(this, apiAppDao);
        ApiPendingIntentFactory apiPendingIntentFactory = new ApiPendingIntentFactory(getBaseContext());
        OpenPgpServiceKeyIdExtractor keyIdExtractor = OpenPgpServiceKeyIdExtractor.getInstance(
                getContentResolver(), apiPendingIntentFactory);
        OpenPgpResultBuilder resultBuilder = new OpenPgpResultBuilder();

        mActionHandler = new OpenPgpActionHandler(this, keyRepository, apiAppDao,
                mApiPermissionHelper, apiPendingIntentFactory, keyIdExtractor, resultBuilder);
    }

    private final IOpenPgpService.Stub mBinder = new IOpenPgpService.Stub() {
        @Override
        public Intent execute(Intent data, ParcelFileDescriptor input, ParcelFileDescriptor output) {
            Timber.w(
                    "You are using a deprecated service which may lead to truncated data on return, please use IOpenPgpService2!");
            return executeInternal(data, input, output);
        }

    };

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    /**
     * Wraps ParcelFileDescriptors into auto-close streams, delegates to
     * {@link #executeInternalWithStreams}, and ensures streams are always closed.
     */
    @Nullable
    protected Intent executeInternal(
            @NonNull Intent data,
            @Nullable ParcelFileDescriptor input,
            @Nullable ParcelFileDescriptor output) {

        OutputStream outputStream =
                (output != null) ? new ParcelFileDescriptor.AutoCloseOutputStream(output) : null;
        InputStream inputStream =
                (input != null) ? new ParcelFileDescriptor.AutoCloseInputStream(input) : null;

        try {
            long startTime = SystemClock.elapsedRealtime();
            Timber.i("API call: %s", data.getAction());
            Intent result = executeInternalWithStreams(data, inputStream, outputStream);
            long elapsedTime = SystemClock.elapsedRealtime() - startTime;
            Timber.i("Elapsed time: %d", elapsedTime);
            return result;
        } finally {
            // always close input and output file descriptors even in error cases
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    Timber.e(e, "IOException when closing input ParcelFileDescriptor");
                }
            }
            if (outputStream != null) {
                try {
                    outputStream.close();
                } catch (IOException e) {
                    Timber.e(e, "IOException when closing output ParcelFileDescriptor");
                }
            }
        }
    }

    /**
     * Sets the classloader, checks requirements, and delegates to the action handler.
     */
    @Nullable
    protected Intent executeInternalWithStreams(
            @NonNull Intent data,
            @Nullable InputStream inputStream,
            @Nullable OutputStream outputStream) {

        // We need to be able to load our own parcelables
        data.setExtrasClassLoader(getClassLoader());

        Intent errorResult = checkRequirements(data);
        if (errorResult != null) {
            return errorResult;
        }

        Progressable progressable = null;
        if (data.hasExtra(OpenPgpApi.EXTRA_PROGRESS_MESSENGER)) {
            Messenger messenger = data.getParcelableExtra(OpenPgpApi.EXTRA_PROGRESS_MESSENGER);
            progressable = createMessengerProgressable(messenger);
        }

        return mActionHandler.dispatch(data, inputStream, outputStream, progressable);
    }

    /**
     * Check requirements:
     * - params != null
     * - has supported API version
     * - is allowed to call the service (access has been granted)
     *
     * @return null if everything is okay, or an error/redirect Intent
     */
    private Intent checkRequirements(Intent data) {
        // params Bundle is required!
        if (data == null) {
            Intent result = new Intent();
            OpenPgpError error = new OpenPgpError(OpenPgpError.GENERIC_ERROR, "params Bundle required!");
            result.putExtra(OpenPgpApi.RESULT_ERROR, error);
            result.putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_ERROR);
            return result;
        }

        // version code is required and needs to correspond to version code of service!
        // History of versions in openpgp-api's CHANGELOG.md
        if (!SUPPORTED_VERSIONS.contains(data.getIntExtra(OpenPgpApi.EXTRA_API_VERSION, -1))) {
            Intent result = new Intent();
            OpenPgpError error = new OpenPgpError
                    (OpenPgpError.INCOMPATIBLE_API_VERSIONS, "Incompatible API versions!\n"
                            + "used API version: " + data.getIntExtra(OpenPgpApi.EXTRA_API_VERSION, -1) + "\n"
                            + "supported API versions: " + SUPPORTED_VERSIONS);
            result.putExtra(OpenPgpApi.RESULT_ERROR, error);
            result.putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_ERROR);
            return result;
        }

        // special exception: getting a sign key id will also register the app
        if (OpenPgpApi.ACTION_GET_SIGN_KEY_ID.equals(data.getAction())) {
            return null;
        }

        // check if caller is allowed to access OpenKeychain
        Intent result = mApiPermissionHelper.isAllowedOrReturnIntent(data);
        if (result != null) {
            return result;
        }

        return null;
    }

    @NonNull
    private static Progressable createMessengerProgressable(final Messenger messenger) {
        return new Progressable() {
            boolean errorState = false;
            @Override
            public void setProgress(Integer ignored, int current, int total) {
                if (errorState) {
                    return;
                }
                Message m = Message.obtain();
                m.arg1 = current;
                m.arg2 = total;
                try {
                    messenger.send(m);
                } catch (RemoteException e) {
                    e.printStackTrace();
                    errorState = true;
                }
            }

            @Override
            public void setPreventCancel() {

            }
        };
    }

}
