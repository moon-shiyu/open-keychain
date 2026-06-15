package org.sufficientlysecure.keychain.remote;


import android.app.PendingIntent;
import android.content.Intent;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openintents.openpgp.OpenPgpError;
import org.openintents.openpgp.util.OpenPgpApi;
import org.sufficientlysecure.keychain.KeychainTestRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;


@RunWith(KeychainTestRunner.class)
public class OpenPgpResultBuilderTest {

    private OpenPgpResultBuilder resultBuilder;

    @Before
    public void setUp() {
        resultBuilder = new OpenPgpResultBuilder();
    }

    // ─── createSuccessResult ────────────────────────────────────────────────

    @Test
    public void createSuccessResult__shouldHaveSuccessResultCode() {
        Intent result = resultBuilder.createSuccessResult();

        assertNotNull(result);
        assertEquals(OpenPgpApi.RESULT_CODE_SUCCESS,
                result.getIntExtra(OpenPgpApi.RESULT_CODE, -1));
    }

    @Test
    public void createSuccessResult__shouldNotHaveErrorExtra() {
        Intent result = resultBuilder.createSuccessResult();

        assertFalse(result.hasExtra(OpenPgpApi.RESULT_ERROR));
    }

    @Test
    public void createSuccessResult__shouldNotHavePendingIntent() {
        Intent result = resultBuilder.createSuccessResult();

        assertFalse(result.hasExtra(OpenPgpApi.RESULT_INTENT));
    }

    // ─── createErrorResult ──────────────────────────────────────────────────

    @Test
    public void createErrorResult__shouldHaveErrorResultCode() {
        Intent result = resultBuilder.createErrorResult(OpenPgpError.GENERIC_ERROR, "test error");

        assertEquals(OpenPgpApi.RESULT_CODE_ERROR,
                result.getIntExtra(OpenPgpApi.RESULT_CODE, -1));
    }

    @Test
    public void createErrorResult__shouldContainOpenPgpError() {
        Intent result = resultBuilder.createErrorResult(OpenPgpError.GENERIC_ERROR, "test error");

        OpenPgpError error = result.getParcelableExtra(OpenPgpApi.RESULT_ERROR);
        assertNotNull(error);
        assertEquals(OpenPgpError.GENERIC_ERROR, error.getErrorId());
        assertEquals("test error", error.getMessage());
    }

    @Test
    public void createErrorResult__withIncompatibleVersions() {
        Intent result = resultBuilder.createErrorResult(
                OpenPgpError.INCOMPATIBLE_API_VERSIONS, "version mismatch");

        OpenPgpError error = result.getParcelableExtra(OpenPgpApi.RESULT_ERROR);
        assertNotNull(error);
        assertEquals(OpenPgpError.INCOMPATIBLE_API_VERSIONS, error.getErrorId());
    }

    // ─── createUserInteractionRequiredResult ────────────────────────────────

    @Test
    public void createUserInteractionRequiredResult__shouldHaveCorrectResultCode() {
        PendingIntent pi = mock(PendingIntent.class);

        Intent result = resultBuilder.createUserInteractionRequiredResult(pi);

        assertEquals(OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED,
                result.getIntExtra(OpenPgpApi.RESULT_CODE, -1));
    }

    @Test
    public void createUserInteractionRequiredResult__shouldContainPendingIntent() {
        PendingIntent pi = mock(PendingIntent.class);

        Intent result = resultBuilder.createUserInteractionRequiredResult(pi);

        assertSame(pi, result.getParcelableExtra(OpenPgpApi.RESULT_INTENT));
    }

    // ─── createSignSuccessResult ────────────────────────────────────────────

    @Test
    public void createSignSuccessResult__withDetachedSignature() {
        byte[] detachedSig = new byte[] { 1, 2, 3 };
        String micAlg = "pgp-sha256";

        Intent result = resultBuilder.createSignSuccessResult(detachedSig, micAlg);

        assertEquals(OpenPgpApi.RESULT_CODE_SUCCESS,
                result.getIntExtra(OpenPgpApi.RESULT_CODE, -1));
        assertNotNull(result.getByteArrayExtra(OpenPgpApi.RESULT_DETACHED_SIGNATURE));
        assertEquals(micAlg, result.getStringExtra(OpenPgpApi.RESULT_SIGNATURE_MICALG));
    }

    @Test
    public void createSignSuccessResult__withoutDetachedSignature() {
        Intent result = resultBuilder.createSignSuccessResult(null, null);

        assertEquals(OpenPgpApi.RESULT_CODE_SUCCESS,
                result.getIntExtra(OpenPgpApi.RESULT_CODE, -1));
        assertFalse(result.hasExtra(OpenPgpApi.RESULT_DETACHED_SIGNATURE));
    }

    // ─── createSignKeyIdResult ──────────────────────────────────────────────

    @Test
    public void createSignKeyIdResult__alreadySelected__shouldReturnSuccess() {
        Intent result = resultBuilder.createSignKeyIdResult(12345L, "user@example.org", 1000L, true);

        assertEquals(OpenPgpApi.RESULT_CODE_SUCCESS,
                result.getIntExtra(OpenPgpApi.RESULT_CODE, -1));
        assertEquals(12345L, result.getLongExtra(OpenPgpApi.RESULT_SIGN_KEY_ID, 0));
        assertEquals("user@example.org", result.getStringExtra(OpenPgpApi.RESULT_PRIMARY_USER_ID));
        assertEquals(1000L, result.getLongExtra(OpenPgpApi.RESULT_KEY_CREATION_TIME, 0));
    }

    @Test
    public void createSignKeyIdResult__notSelected__shouldReturnUserInteractionRequired() {
        Intent result = resultBuilder.createSignKeyIdResult(12345L, null, 0, false);

        assertEquals(OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED,
                result.getIntExtra(OpenPgpApi.RESULT_CODE, -1));
        assertEquals(12345L, result.getLongExtra(OpenPgpApi.RESULT_SIGN_KEY_ID, 0));
    }
}
