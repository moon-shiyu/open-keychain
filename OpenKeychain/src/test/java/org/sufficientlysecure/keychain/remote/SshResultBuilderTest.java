package org.sufficientlysecure.keychain.remote;


import android.app.PendingIntent;
import android.content.Intent;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openintents.ssh.authentication.SshAuthenticationApi;
import org.openintents.ssh.authentication.SshAuthenticationApiError;
import org.sufficientlysecure.keychain.KeychainTestRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;


@RunWith(KeychainTestRunner.class)
public class SshResultBuilderTest {

    private SshResultBuilder resultBuilder;

    @Before
    public void setUp() {
        resultBuilder = new SshResultBuilder();
    }

    // ─── createSuccessResult ────────────────────────────────────────────────

    @Test
    public void createSuccessResult__shouldHaveSuccessResultCode() {
        Intent result = resultBuilder.createSuccessResult();

        assertNotNull(result);
        assertEquals(SshAuthenticationApi.RESULT_CODE_SUCCESS,
                result.getIntExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, -1));
    }

    // ─── createErrorResult ──────────────────────────────────────────────────

    @Test
    public void createErrorResult__shouldHaveErrorResultCode() {
        Intent result = resultBuilder.createErrorResult(
                SshAuthenticationApiError.GENERIC_ERROR, "test error");

        assertEquals(SshAuthenticationApi.RESULT_CODE_ERROR,
                result.getIntExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, -1));
    }

    @Test
    public void createErrorResult__shouldContainSshError() {
        Intent result = resultBuilder.createErrorResult(
                SshAuthenticationApiError.NO_KEY_ID, "no key");

        SshAuthenticationApiError error = result.getParcelableExtra(SshAuthenticationApi.EXTRA_ERROR);
        assertNotNull(error);
        assertEquals(SshAuthenticationApiError.NO_KEY_ID, error.getErrorId());
    }

    @Test
    public void createExceptionErrorResult__shouldAppendExceptionMessage() {
        Exception cause = new RuntimeException("root cause");

        Intent result = resultBuilder.createExceptionErrorResult(
                SshAuthenticationApiError.INTERNAL_ERROR, "failed", cause);

        SshAuthenticationApiError error = result.getParcelableExtra(SshAuthenticationApi.EXTRA_ERROR);
        assertNotNull(error);
        assertTrue(error.getMessage().contains("failed"));
        assertTrue(error.getMessage().contains("root cause"));
    }

    // ─── createUserInteractionRequiredResult ────────────────────────────────

    @Test
    public void createUserInteractionRequiredResult__shouldHaveCorrectResultCode() {
        PendingIntent pi = mock(PendingIntent.class);

        Intent result = resultBuilder.createUserInteractionRequiredResult(pi);

        assertEquals(SshAuthenticationApi.RESULT_CODE_USER_INTERACTION_REQUIRED,
                result.getIntExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, -1));
    }

    @Test
    public void createUserInteractionRequiredResult__shouldUseExtraPendingIntent() {
        PendingIntent pi = mock(PendingIntent.class);

        Intent result = resultBuilder.createUserInteractionRequiredResult(pi);

        // SSH uses EXTRA_PENDING_INTENT, not RESULT_INTENT
        assertSame(pi, result.getParcelableExtra(SshAuthenticationApi.EXTRA_PENDING_INTENT));
    }
}
