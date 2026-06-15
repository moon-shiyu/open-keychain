package org.sufficientlysecure.keychain.remote;


import java.util.HashSet;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openintents.openpgp.util.OpenPgpApi;
import org.openintents.ssh.authentication.SshAuthenticationApi;
import org.openintents.ssh.authentication.SshAuthenticationApiError;
import org.sufficientlysecure.keychain.Constants;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.ApiAppDao;
import org.sufficientlysecure.keychain.daos.KeyRepository;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


@RunWith(KeychainTestRunner.class)
public class SshActionHandlerTest {

    private SshActionHandler handler;
    private SshResultBuilder resultBuilder;
    private ApiPermissionHelper apiPermissionHelper;
    private ApiPendingIntentFactory apiPendingIntentFactory;
    private ApiAppDao apiAppDao;
    private KeyRepository keyRepository;

    @Before
    public void setUp() {
        Context context = mock(Context.class);
        keyRepository = mock(KeyRepository.class);
        apiAppDao = mock(ApiAppDao.class);
        apiPermissionHelper = mock(ApiPermissionHelper.class);
        apiPendingIntentFactory = mock(ApiPendingIntentFactory.class);
        resultBuilder = new SshResultBuilder();

        when(apiPermissionHelper.getCurrentCallingPackage()).thenReturn("com.test.app");
        when(apiAppDao.getAllowedKeyIdsForApp(anyString())).thenReturn(new HashSet<Long>());

        handler = new SshActionHandler(context, keyRepository, apiAppDao,
                apiPermissionHelper, apiPendingIntentFactory, resultBuilder);
    }

    // ─── dispatch ───────────────────────────────────────────────────────────

    @Test
    public void dispatch__withUnknownAction__shouldReturnError() {
        Intent intent = new Intent();
        intent.setAction("unknown.action");

        Intent result = handler.dispatch(intent);

        assertNotNull(result);
        assertEquals(SshAuthenticationApi.RESULT_CODE_ERROR,
                result.getIntExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, -1));
    }

    // ─── getKeyId ───────────────────────────────────────────────────────────

    @Test
    public void getKeyId__withValidKeyId__shouldReturnParsedValue() {
        Intent intent = new Intent();
        intent.putExtra(SshAuthenticationApi.EXTRA_KEY_ID, "12345");

        long keyId = handler.getKeyId(intent);

        assertEquals(12345L, keyId);
    }

    @Test
    public void getKeyId__withNoKeyId__shouldReturnNone() {
        Intent intent = new Intent();

        long keyId = handler.getKeyId(intent);

        assertEquals(Constants.key.none, keyId);
    }

    @Test
    public void getKeyId__withInvalidKeyId__shouldReturnNone() {
        Intent intent = new Intent();
        intent.putExtra(SshAuthenticationApi.EXTRA_KEY_ID, "not_a_number");

        long keyId = handler.getKeyId(intent);

        assertEquals(Constants.key.none, keyId);
    }

    // ─── getHashAlgorithm ───────────────────────────────────────────────────

    @Test
    public void getHashAlgorithm__sha256__shouldReturnCorrectTag() {
        Intent intent = new Intent();
        intent.putExtra(SshAuthenticationApi.EXTRA_HASH_ALGORITHM, SshAuthenticationApi.SHA256);

        int hashAlg = handler.getHashAlgorithm(intent);

        assertEquals(org.bouncycastle.bcpg.HashAlgorithmTags.SHA256, hashAlg);
    }

    @Test
    public void getHashAlgorithm__sha512__shouldReturnCorrectTag() {
        Intent intent = new Intent();
        intent.putExtra(SshAuthenticationApi.EXTRA_HASH_ALGORITHM, SshAuthenticationApi.SHA512);

        int hashAlg = handler.getHashAlgorithm(intent);

        assertEquals(org.bouncycastle.bcpg.HashAlgorithmTags.SHA512, hashAlg);
    }

    @Test
    public void getHashAlgorithm__sha1__shouldReturnCorrectTag() {
        Intent intent = new Intent();
        intent.putExtra(SshAuthenticationApi.EXTRA_HASH_ALGORITHM, SshAuthenticationApi.SHA1);

        int hashAlg = handler.getHashAlgorithm(intent);

        assertEquals(org.bouncycastle.bcpg.HashAlgorithmTags.SHA1, hashAlg);
    }

    @Test
    public void getHashAlgorithm__sha384__shouldReturnCorrectTag() {
        Intent intent = new Intent();
        intent.putExtra(SshAuthenticationApi.EXTRA_HASH_ALGORITHM, SshAuthenticationApi.SHA384);

        int hashAlg = handler.getHashAlgorithm(intent);

        assertEquals(org.bouncycastle.bcpg.HashAlgorithmTags.SHA384, hashAlg);
    }

    @Test
    public void getHashAlgorithm__sha224__shouldReturnCorrectTag() {
        Intent intent = new Intent();
        intent.putExtra(SshAuthenticationApi.EXTRA_HASH_ALGORITHM, SshAuthenticationApi.SHA224);

        int hashAlg = handler.getHashAlgorithm(intent);

        assertEquals(org.bouncycastle.bcpg.HashAlgorithmTags.SHA224, hashAlg);
    }

    @Test
    public void getHashAlgorithm__ripemd160__shouldReturnCorrectTag() {
        Intent intent = new Intent();
        intent.putExtra(SshAuthenticationApi.EXTRA_HASH_ALGORITHM, SshAuthenticationApi.RIPEMD160);

        int hashAlg = handler.getHashAlgorithm(intent);

        assertEquals(org.bouncycastle.bcpg.HashAlgorithmTags.RIPEMD160, hashAlg);
    }

    @Test
    public void getHashAlgorithm__invalidAlgorithm__shouldReturnNone() {
        Intent intent = new Intent();
        intent.putExtra(SshAuthenticationApi.EXTRA_HASH_ALGORITHM, 999);

        int hashAlg = handler.getHashAlgorithm(intent);

        assertEquals(SshAuthenticationApiError.INVALID_HASH_ALGORITHM, hashAlg);
    }

    @Test
    public void getHashAlgorithm__noAlgorithmExtra__shouldReturnNone() {
        Intent intent = new Intent();

        int hashAlg = handler.getHashAlgorithm(intent);

        assertEquals(SshAuthenticationApiError.INVALID_HASH_ALGORITHM, hashAlg);
    }

    // ─── ACTION_SIGN dispatch ───────────────────────────────────────────────

    @Test
    public void dispatch__signWithNoKeyId__shouldReturnNoKeyIdError() {
        Intent intent = new Intent();
        intent.setAction(SshAuthenticationApi.ACTION_SIGN);

        Intent result = handler.dispatch(intent);

        assertNotNull(result);
        assertEquals(SshAuthenticationApi.RESULT_CODE_ERROR,
                result.getIntExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, -1));
    }

    @Test
    public void dispatch__signWithInvalidHashAlgorithm__shouldReturnError() {
        Intent intent = new Intent();
        intent.setAction(SshAuthenticationApi.ACTION_SIGN);
        intent.putExtra(SshAuthenticationApi.EXTRA_KEY_ID, "12345");
        intent.putExtra(SshAuthenticationApi.EXTRA_HASH_ALGORITHM, 999);
        intent.putExtra(SshAuthenticationApi.EXTRA_CHALLENGE, new byte[] { 1, 2, 3 });

        Intent result = handler.dispatch(intent);

        assertNotNull(result);
        assertEquals(SshAuthenticationApi.RESULT_CODE_ERROR,
                result.getIntExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, -1));
    }

    @Test
    public void dispatch__signWithNoChallenge__shouldReturnError() {
        Intent intent = new Intent();
        intent.setAction(SshAuthenticationApi.ACTION_SIGN);
        intent.putExtra(SshAuthenticationApi.EXTRA_KEY_ID, "12345");
        intent.putExtra(SshAuthenticationApi.EXTRA_HASH_ALGORITHM, SshAuthenticationApi.SHA256);

        Intent result = handler.dispatch(intent);

        assertNotNull(result);
        assertEquals(SshAuthenticationApi.RESULT_CODE_ERROR,
                result.getIntExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, -1));
    }

    // ─── ACTION_SELECT_KEY dispatch ─────────────────────────────────────────

    @Test
    public void dispatch__selectKeyWithNoKeyId__shouldReturnPendingIntent() {
        Intent intent = new Intent();
        intent.setAction(SshAuthenticationApi.ACTION_SELECT_KEY);

        PendingIntent pi = mock(PendingIntent.class);
        when(apiPendingIntentFactory.createSelectAuthenticationKeyIdPendingIntent(
                any(Intent.class), anyString())).thenReturn(pi);

        Intent result = handler.dispatch(intent);

        assertNotNull(result);
        assertEquals(SshAuthenticationApi.RESULT_CODE_USER_INTERACTION_REQUIRED,
                result.getIntExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, -1));
    }

    // ─── ACTION_GET_PUBLIC_KEY dispatch ─────────────────────────────────────

    @Test
    public void dispatch__getPublicKeyWithNoKeyId__shouldReturnError() {
        Intent intent = new Intent();
        intent.setAction(SshAuthenticationApi.ACTION_GET_PUBLIC_KEY);

        Intent result = handler.dispatch(intent);

        assertNotNull(result);
        assertEquals(SshAuthenticationApi.RESULT_CODE_ERROR,
                result.getIntExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, -1));
    }

    // ─── ACTION_GET_SSH_PUBLIC_KEY dispatch ─────────────────────────────────

    @Test
    public void dispatch__getSshPublicKeyWithNoKeyId__shouldReturnError() {
        Intent intent = new Intent();
        intent.setAction(SshAuthenticationApi.ACTION_GET_SSH_PUBLIC_KEY);

        Intent result = handler.dispatch(intent);

        assertNotNull(result);
        assertEquals(SshAuthenticationApi.RESULT_CODE_ERROR,
                result.getIntExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, -1));
    }
}
