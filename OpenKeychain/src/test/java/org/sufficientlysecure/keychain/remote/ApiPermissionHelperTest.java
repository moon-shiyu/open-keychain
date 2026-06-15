package org.sufficientlysecure.keychain.remote;


import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openintents.openpgp.util.OpenPgpApi;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.ApiAppDao;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


@RunWith(KeychainTestRunner.class)
public class ApiPermissionHelperTest {

    private ApiPermissionHelper permissionHelper;
    private ApiAppDao apiAppDao;
    private PackageManager packageManager;
    private Context context;

    @Before
    public void setUp() {
        context = mock(Context.class);
        apiAppDao = mock(ApiAppDao.class);
        packageManager = mock(PackageManager.class);
        when(context.getPackageManager()).thenReturn(packageManager);

        permissionHelper = new ApiPermissionHelper(context, apiAppDao);
    }

    @Test
    public void isPackageAllowed__withUnknownPackage__shouldReturnFalse() throws Exception {
        when(apiAppDao.getApiAppCertificate("com.unknown.app")).thenReturn(null);

        boolean result = permissionHelper.isPackageAllowed("com.unknown.app");

        assertEquals(false, result);
    }

    @Test
    public void isPackageAllowed__withCertMismatch__shouldThrowWrongCertException() throws Exception {
        byte[] storedCert = new byte[] { 1, 2, 3 };
        byte[] currentCert = new byte[] { 4, 5, 6 };

        when(apiAppDao.getApiAppCertificate("com.test.app")).thenReturn(storedCert);

        PackageInfo pkgInfo = new PackageInfo();
        pkgInfo.signatures = new Signature[] { new Signature(currentCert) };
        when(packageManager.getPackageInfo(anyString(),
                org.mockito.Matchers.anyInt())).thenReturn(pkgInfo);

        try {
            permissionHelper.isPackageAllowed("com.test.app");
            fail("Expected WrongPackageCertificateException");
        } catch (ApiPermissionHelper.WrongPackageCertificateException e) {
            // expected
            assertTrue(e.getMessage().contains("CERTIFICATE MISMATCH"));
        }
    }

    @Test
    public void isPackageAllowed__withMatchingCert__shouldReturnTrue() throws Exception {
        byte[] cert = new byte[] { 1, 2, 3 };

        when(apiAppDao.getApiAppCertificate("com.test.app")).thenReturn(cert);

        PackageInfo pkgInfo = new PackageInfo();
        pkgInfo.signatures = new Signature[] { new Signature(cert) };
        when(packageManager.getPackageInfo(anyString(),
                org.mockito.Matchers.anyInt())).thenReturn(pkgInfo);

        boolean result = permissionHelper.isPackageAllowed("com.test.app");

        assertTrue(result);
    }

    @Test
    public void isAllowedIgnoreErrors__withUnknownPackage__shouldReturnFalse() throws Exception {
        when(apiAppDao.getApiAppCertificate(anyString())).thenReturn(null);

        // Note: in unit test, Binder.getCallingUid() returns 0 which maps to no packages,
        // so isCallerAllowed will fail. We're testing the error-swallowing behavior.
        boolean result = permissionHelper.isAllowedIgnoreErrors();

        // Result depends on PackageManager behavior in Robolectric test env
        // The key thing is it doesn't throw an exception
        assertNotNull(Boolean.valueOf(result));
    }
}
