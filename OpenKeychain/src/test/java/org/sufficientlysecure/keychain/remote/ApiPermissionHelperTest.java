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


import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.Signature;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openintents.openpgp.util.OpenPgpApi;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowBinder;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.ApiAppDao;
import org.sufficientlysecure.keychain.remote.ApiPermissionHelper.PermissionCheckResult;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.robolectric.Shadows.shadowOf;


/**
 * Verifies the caller-permission representative branch shared by both remote services:
 * {@link ApiPermissionHelper#checkSubjectPermission} returns a user-interaction handling Intent for
 * an unregistered caller and {@code allowed} when the stored certificate matches the caller's
 * package signature. Uses a real {@link ApiAppDao} (the proven pattern from
 * {@code KeychainExternalProviderTest}).
 */
@RunWith(KeychainTestRunner.class)
public class ApiPermissionHelperTest {

    private static final String PACKAGE_NAME = "test.package";
    private static final byte[] PACKAGE_SIGNATURE = new byte[] { 1, 2, 3 };
    private static final int PACKAGE_UID = 42;

    private ApiAppDao apiAppDao;
    private ApiPermissionHelper apiPermissionHelper;

    @Before
    public void setUp() {
        ShadowLog.stream = System.out;

        Context context = RuntimeEnvironment.getApplication();

        shadowOf(context.getPackageManager()).setPackagesForUid(PACKAGE_UID, PACKAGE_NAME);

        PackageInfo packageInfo = new PackageInfo();
        packageInfo.packageName = PACKAGE_NAME;
        packageInfo.signatures = new Signature[] { new Signature(PACKAGE_SIGNATURE) };
        shadowOf(context.getPackageManager()).addPackage(packageInfo);

        ShadowBinder.setCallingUid(PACKAGE_UID);

        apiAppDao = ApiAppDao.getInstance(context);
        apiPermissionHelper = new ApiPermissionHelper(context, apiAppDao);
    }

    @Test
    public void checkSubjectPermission_unregisteredPackage_requiresUserInteraction() {
        // No insertApiApp(): the caller is unknown, so a registration handling Intent is expected.
        PermissionCheckResult result = apiPermissionHelper.checkSubjectPermission(new Intent());

        assertFalse(result.isAllowed());

        Intent handlingIntent = result.getHandlingIntent();
        assertNotNull(handlingIntent);
        assertEquals(OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED,
                handlingIntent.getIntExtra(OpenPgpApi.RESULT_CODE, -1));
        assertNotNull(handlingIntent.getParcelableExtra(OpenPgpApi.RESULT_INTENT));
    }

    @Test
    public void checkSubjectPermission_matchingCertificate_isAllowed() {
        apiAppDao.insertApiApp(PACKAGE_NAME, PACKAGE_SIGNATURE);

        PermissionCheckResult result = apiPermissionHelper.checkSubjectPermission(new Intent());

        assertTrue(result.isAllowed());
        assertNull(result.getHandlingIntent());
    }
}
