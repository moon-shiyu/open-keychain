package org.sufficientlysecure.keychain.remote;


import java.util.HashSet;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openintents.openpgp.OpenPgpError;
import org.openintents.openpgp.util.OpenPgpApi;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.ApiAppDao;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.remote.OpenPgpServiceKeyIdExtractor.KeyIdResult;
import org.sufficientlysecure.keychain.remote.OpenPgpServiceKeyIdExtractor.KeyIdResultStatus;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


@RunWith(KeychainTestRunner.class)
public class OpenPgpActionHandlerTest {

    private OpenPgpActionHandler handler;
    private OpenPgpResultBuilder resultBuilder;
    private ApiPermissionHelper apiPermissionHelper;
    private ApiPendingIntentFactory apiPendingIntentFactory;
    private ApiAppDao apiAppDao;
    private KeyRepository keyRepository;
    private OpenPgpServiceKeyIdExtractor keyIdExtractor;
    private Context context;

    @Before
    public void setUp() {
        context = mock(Context.class);
        keyRepository = mock(KeyRepository.class);
        apiAppDao = mock(ApiAppDao.class);
        apiPermissionHelper = mock(ApiPermissionHelper.class);
        apiPendingIntentFactory = mock(ApiPendingIntentFactory.class);
        keyIdExtractor = mock(OpenPgpServiceKeyIdExtractor.class);
        resultBuilder = new OpenPgpResultBuilder();

        when(apiPermissionHelper.getCurrentCallingPackage()).thenReturn("com.test.app");
        when(apiAppDao.getAllowedKeyIdsForApp(anyString())).thenReturn(new HashSet<Long>());

        handler = new OpenPgpActionHandler(context, keyRepository, apiAppDao,
                apiPermissionHelper, apiPendingIntentFactory, keyIdExtractor, resultBuilder);
    }

    // ─── dispatch: ACTION_CHECK_PERMISSION ──────────────────────────────────

    @Test
    public void dispatch__checkPermission__whenAllowed__shouldReturnSuccess() {
        Intent data = new Intent();
        data.setAction(OpenPgpApi.ACTION_CHECK_PERMISSION);
        when(apiPermissionHelper.isAllowedOrReturnIntent(any(Intent.class))).thenReturn(null);

        Intent result = handler.dispatch(data, null, null, null);

        assertNotNull(result);
        assertEquals(OpenPgpApi.RESULT_CODE_SUCCESS,
                result.getIntExtra(OpenPgpApi.RESULT_CODE, -1));
    }

    @Test
    public void dispatch__checkPermission__whenNotAllowed__shouldReturnPendingIntent() {
        Intent data = new Intent();
        data.setAction(OpenPgpApi.ACTION_CHECK_PERMISSION);

        PendingIntent pi = mock(PendingIntent.class);
        Intent redirectIntent = new Intent();
        redirectIntent.putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED);
        redirectIntent.putExtra(OpenPgpApi.RESULT_INTENT, pi);
        when(apiPermissionHelper.isAllowedOrReturnIntent(any(Intent.class))).thenReturn(redirectIntent);

        Intent result = handler.dispatch(data, null, null, null);

        assertNotNull(result);
        assertEquals(OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED,
                result.getIntExtra(OpenPgpApi.RESULT_CODE, -1));
    }

    // ─── dispatch: unknown action ───────────────────────────────────────────

    @Test
    public void dispatch__withUnknownAction__shouldReturnNull() {
        Intent data = new Intent();
        data.setAction("unknown.action");

        Intent result = handler.dispatch(data, null, null, null);

        // Unknown actions return null (matching original behavior)
        assertEquals(null, result);
    }

    // ─── dispatch: ACTION_GET_KEY_IDS ───────────────────────────────────────

    @Test
    public void dispatch__getKeyIds__withSelectedKeys__shouldReturnSuccess() {
        Intent data = new Intent();
        data.setAction(OpenPgpApi.ACTION_GET_KEY_IDS);
        long[] keyIds = new long[] { 111L, 222L };

        KeyIdResult keyIdResult = mock(KeyIdResult.class);
        when(keyIdResult.hasKeySelectionPendingIntent()).thenReturn(false);
        when(keyIdResult.getKeyIds()).thenReturn(keyIds);
        when(keyIdExtractor.returnKeyIdsFromIntent(any(Intent.class), anyBoolean(), anyString()))
                .thenReturn(keyIdResult);

        Intent result = handler.dispatch(data, null, null, null);

        assertNotNull(result);
        assertEquals(OpenPgpApi.RESULT_CODE_SUCCESS,
                result.getIntExtra(OpenPgpApi.RESULT_CODE, -1));
    }

    @Test
    public void dispatch__getKeyIds__withMissingKeys__shouldReturnUserInteractionRequired() {
        Intent data = new Intent();
        data.setAction(OpenPgpApi.ACTION_GET_KEY_IDS);

        PendingIntent pi = mock(PendingIntent.class);
        KeyIdResult keyIdResult = mock(KeyIdResult.class);
        when(keyIdResult.hasKeySelectionPendingIntent()).thenReturn(true);
        when(keyIdResult.getKeySelectionPendingIntent()).thenReturn(pi);
        when(keyIdExtractor.returnKeyIdsFromIntent(any(Intent.class), anyBoolean(), anyString()))
                .thenReturn(keyIdResult);

        Intent result = handler.dispatch(data, null, null, null);

        assertNotNull(result);
        assertEquals(OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED,
                result.getIntExtra(OpenPgpApi.RESULT_CODE, -1));
    }

    // ─── dispatch: ACTION_QUERY_AUTOCRYPT_STATUS ────────────────────────────

    @Test
    public void dispatch__queryAutocryptStatus__withOkKeys__shouldReturnAvailable() {
        Intent data = new Intent();
        data.setAction(OpenPgpApi.ACTION_QUERY_AUTOCRYPT_STATUS);

        KeyIdResult keyIdResult = mock(KeyIdResult.class);
        when(keyIdResult.getStatus()).thenReturn(KeyIdResultStatus.OK);
        when(keyIdResult.isAllKeysConfirmed()).thenReturn(true);
        when(keyIdResult.getAutocryptRecommendation()).thenReturn(
                org.sufficientlysecure.keychain.provider.KeychainExternalContract.AutocryptStatus.AUTOCRYPT_PEER_AVAILABLE);
        when(keyIdResult.hasKeySelectionPendingIntent()).thenReturn(false);
        when(keyIdExtractor.returnKeyIdsFromIntent(any(Intent.class), anyBoolean(), anyString()))
                .thenReturn(keyIdResult);

        Intent result = handler.dispatch(data, null, null, null);

        assertNotNull(result);
        assertEquals(OpenPgpApi.RESULT_CODE_SUCCESS,
                result.getIntExtra(OpenPgpApi.RESULT_CODE, -1));
        assertEquals(OpenPgpApi.AUTOCRYPT_STATUS_AVAILABLE,
                result.getIntExtra(OpenPgpApi.RESULT_AUTOCRYPT_STATUS, -1));
    }

    // ─── retrieveCryptoInputParcel ──────────────────────────────────────────

    @Test
    public void retrieveCryptoInputParcel__withNoCachedParcel__shouldCreateFresh() {
        Intent data = new Intent();

        // CryptoInputParcelCacheService.getCryptoInputParcel returns null when nothing cached
        // In unit test environment it will return null since the cache service isn't running
        CryptoInputParcel result = handler.retrieveCryptoInputParcel(data);

        // When cache returns null, we create a fresh parcel with Date
        assertNotNull(result);
    }

    @Test
    public void retrieveCryptoInputParcelForDecrypt__withNoCachedParcel__shouldCreateFresh() {
        Intent data = new Intent();

        CryptoInputParcel result = handler.retrieveCryptoInputParcelForDecrypt(data);

        assertNotNull(result);
    }

    // ─── resolveSignKeyId ───────────────────────────────────────────────────

    @Test
    public void resolveSignKeyId__withKeyIdPresent__shouldReturnDataIntent() {
        Intent data = new Intent();
        data.putExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID, 12345L);

        Intent result = handler.resolveSignKeyId(data);

        // Should return the data intent directly when sign key ID is present
        assertNotNull(result);
        assertEquals(12345L, result.getLongExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID, 0));
    }

    // ─── getAllowedKeyIds ────────────────────────────────────────────────────

    @Test
    public void getAllowedKeyIds__shouldQueryApiAppDao() {
        HashSet<Long> expectedKeys = new HashSet<>();
        expectedKeys.add(100L);
        expectedKeys.add(200L);
        when(apiAppDao.getAllowedKeyIdsForApp("com.test.app")).thenReturn(expectedKeys);

        HashSet<Long> result = handler.getAllowedKeyIds();

        assertEquals(2, result.size());
        assertTrue(result.contains(100L));
        assertTrue(result.contains(200L));
    }

    // ─── dispatch: ACTION_ENCRYPT with opportunistic missing keys ───────────

    @Test
    public void dispatch__encryptWithOpportunisticMissingKeys__shouldReturnError() {
        Intent data = new Intent();
        data.setAction(OpenPgpApi.ACTION_ENCRYPT);
        data.putExtra(OpenPgpApi.EXTRA_OPPORTUNISTIC_ENCRYPTION, true);

        KeyIdResult keyIdResult = mock(KeyIdResult.class);
        when(keyIdResult.getStatus()).thenReturn(KeyIdResultStatus.MISSING);
        when(keyIdResult.hasKeySelectionPendingIntent()).thenReturn(true);
        when(keyIdExtractor.returnKeyIdsFromIntent(any(Intent.class), anyBoolean(), anyString()))
                .thenReturn(keyIdResult);

        Intent result = handler.dispatch(data, mock(java.io.InputStream.class), null, null);

        assertNotNull(result);
        assertEquals(OpenPgpApi.RESULT_CODE_ERROR,
                result.getIntExtra(OpenPgpApi.RESULT_CODE, -1));
        OpenPgpError error = result.getParcelableExtra(OpenPgpApi.RESULT_ERROR);
        assertNotNull(error);
        assertEquals(OpenPgpError.OPPORTUNISTIC_MISSING_KEYS, error.getErrorId());
    }
}
