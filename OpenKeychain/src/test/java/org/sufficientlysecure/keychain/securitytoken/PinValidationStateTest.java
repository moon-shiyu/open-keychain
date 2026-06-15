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

package org.sufficientlysecure.keychain.securitytoken;


import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


/**
 * Plain unit tests (no Android / Robolectric needed) for {@link PinValidationState}, the small state
 * machine that tracks which OpenPGP-card PINs are currently validated within a card session.
 *
 * The three validation states (PW1 mode 81 / PW1 mode 82 / PW3) are independent on a real card, so
 * the tests assert that each transition affects only its own flag.
 */
public class PinValidationStateTest {

    @Test
    public void defaults_areAllFalse() {
        PinValidationState state = new PinValidationState();

        assertFalse(state.isPw1ValidatedForSignature());
        assertFalse(state.isPw1ValidatedForOther());
        assertFalse(state.isPw3Validated());
    }

    @Test
    public void markPw1ForSignature_flipsOnlySignature() {
        PinValidationState state = new PinValidationState();

        state.markPw1ValidatedForSignature();

        assertTrue(state.isPw1ValidatedForSignature());
        assertFalse(state.isPw1ValidatedForOther());
        assertFalse(state.isPw3Validated());
    }

    @Test
    public void markPw1ForOther_flipsOnlyOther() {
        PinValidationState state = new PinValidationState();

        state.markPw1ValidatedForOther();

        assertFalse(state.isPw1ValidatedForSignature());
        assertTrue(state.isPw1ValidatedForOther());
        assertFalse(state.isPw3Validated());
    }

    @Test
    public void markPw3_flipsOnlyPw3() {
        PinValidationState state = new PinValidationState();

        state.markPw3Validated();

        assertFalse(state.isPw1ValidatedForSignature());
        assertFalse(state.isPw1ValidatedForOther());
        assertTrue(state.isPw3Validated());
    }

    @Test
    public void reset_clearsAll() {
        PinValidationState state = new PinValidationState();
        state.markPw1ValidatedForSignature();
        state.markPw1ValidatedForOther();
        state.markPw3Validated();

        state.reset();

        assertFalse(state.isPw1ValidatedForSignature());
        assertFalse(state.isPw1ValidatedForOther());
        assertFalse(state.isPw3Validated());
    }

    @Test
    public void invalidatePw1ForSignature_clearsOnlySignature() {
        PinValidationState state = new PinValidationState();
        state.markPw1ValidatedForSignature();
        state.markPw1ValidatedForOther();
        state.markPw3Validated();

        state.invalidatePw1ForSignature();

        assertFalse(state.isPw1ValidatedForSignature());
        assertTrue(state.isPw1ValidatedForOther());
        assertTrue(state.isPw3Validated());
    }

    @Test
    public void invalidatePw3_clearsOnlyPw3() {
        PinValidationState state = new PinValidationState();
        state.markPw1ValidatedForSignature();
        state.markPw1ValidatedForOther();
        state.markPw3Validated();

        state.invalidatePw3();

        assertTrue(state.isPw1ValidatedForSignature());
        assertTrue(state.isPw1ValidatedForOther());
        assertFalse(state.isPw3Validated());
    }

    @Test
    public void remark_afterInvalidate_validatesAgain() {
        PinValidationState state = new PinValidationState();

        state.markPw1ValidatedForSignature();
        state.invalidatePw1ForSignature();
        state.markPw1ValidatedForSignature();

        assertTrue(state.isPw1ValidatedForSignature());
    }
}
