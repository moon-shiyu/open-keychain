package org.sufficientlysecure.keychain.securitytoken;


import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.sufficientlysecure.keychain.KeychainTestRunner;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


/**
 * Unit tests for {@link PinState}.
 * Pure POJO tests — no mocking, no Android dependencies.
 */
@RunWith(KeychainTestRunner.class)
public class PinStateTest {

    private PinState pinState;

    @Before
    public void setUp() {
        pinState = new PinState();
    }

    @Test
    public void test_initialState_allUnvalidated() {
        assertFalse(pinState.isPw1ValidatedForSignature());
        assertFalse(pinState.isPw1ValidatedForOther());
        assertFalse(pinState.isPw3Validated());
    }

    @Test
    public void test_markPw1ValidatedForSignature() {
        pinState.markPw1ValidatedForSignature();

        assertTrue(pinState.isPw1ValidatedForSignature());
        assertFalse(pinState.isPw1ValidatedForOther());
        assertFalse(pinState.isPw3Validated());
    }

    @Test
    public void test_markPw1ValidatedForOther() {
        pinState.markPw1ValidatedForOther();

        assertFalse(pinState.isPw1ValidatedForSignature());
        assertTrue(pinState.isPw1ValidatedForOther());
        assertFalse(pinState.isPw3Validated());
    }

    @Test
    public void test_markPw3Validated() {
        pinState.markPw3Validated();

        assertFalse(pinState.isPw1ValidatedForSignature());
        assertFalse(pinState.isPw1ValidatedForOther());
        assertTrue(pinState.isPw3Validated());
    }

    @Test
    public void test_invalidateSingleUsePw1_whenNotMultipleSignatures() {
        pinState.markPw1ValidatedForSignature();
        assertTrue(pinState.isPw1ValidatedForSignature());

        pinState.invalidateSingleUsePw1(false);

        assertFalse("PW1 for signature should be invalidated when not valid for multiple signatures",
                pinState.isPw1ValidatedForSignature());
    }

    @Test
    public void test_invalidateSingleUsePw1_whenMultipleSignatures() {
        pinState.markPw1ValidatedForSignature();
        assertTrue(pinState.isPw1ValidatedForSignature());

        pinState.invalidateSingleUsePw1(true);

        assertTrue("PW1 for signature should remain valid when configured for multiple signatures",
                pinState.isPw1ValidatedForSignature());
    }

    @Test
    public void test_invalidateSingleUsePw1_doesNotAffectOtherFlags() {
        pinState.markPw1ValidatedForSignature();
        pinState.markPw1ValidatedForOther();
        pinState.markPw3Validated();

        pinState.invalidateSingleUsePw1(false);

        assertFalse(pinState.isPw1ValidatedForSignature());
        assertTrue("PW1 for other should not be affected by single-use invalidation",
                pinState.isPw1ValidatedForOther());
        assertTrue("PW3 should not be affected by single-use invalidation",
                pinState.isPw3Validated());
    }

    @Test
    public void test_invalidatePw3() {
        pinState.markPw3Validated();
        assertTrue(pinState.isPw3Validated());

        pinState.invalidatePw3();

        assertFalse(pinState.isPw3Validated());
    }

    @Test
    public void test_invalidatePw3_doesNotAffectPw1() {
        pinState.markPw1ValidatedForSignature();
        pinState.markPw1ValidatedForOther();
        pinState.markPw3Validated();

        pinState.invalidatePw3();

        assertTrue(pinState.isPw1ValidatedForSignature());
        assertTrue(pinState.isPw1ValidatedForOther());
        assertFalse(pinState.isPw3Validated());
    }

    @Test
    public void test_reset_clearsAll() {
        pinState.markPw1ValidatedForSignature();
        pinState.markPw1ValidatedForOther();
        pinState.markPw3Validated();

        pinState.reset();

        assertFalse(pinState.isPw1ValidatedForSignature());
        assertFalse(pinState.isPw1ValidatedForOther());
        assertFalse(pinState.isPw3Validated());
    }

    @Test
    public void test_reset_doesNotAffectNewValidations() {
        pinState.markPw1ValidatedForSignature();
        pinState.reset();

        assertFalse(pinState.isPw1ValidatedForSignature());

        // Re-validate after reset should work
        pinState.markPw1ValidatedForSignature();
        assertTrue(pinState.isPw1ValidatedForSignature());
    }

    @Test
    public void test_allFlagsCanBeSetIndependently() {
        pinState.markPw1ValidatedForSignature();
        pinState.markPw3Validated();

        assertTrue(pinState.isPw1ValidatedForSignature());
        assertFalse(pinState.isPw1ValidatedForOther());
        assertTrue(pinState.isPw3Validated());

        pinState.markPw1ValidatedForOther();
        assertTrue(pinState.isPw1ValidatedForOther());

        // Other flags should still be set
        assertTrue(pinState.isPw1ValidatedForSignature());
        assertTrue(pinState.isPw3Validated());
    }
}
