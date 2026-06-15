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


/**
 * Tracks which OpenPGP card PINs are currently validated within a single card session, so that
 * {@link SecurityTokenConnection} can skip redundant VERIFY commands.
 *
 * The OpenPGP application keeps three independent validation states (see [0], 7.2.2 VERIFY):
 * PW1 in mode 81 (signing), PW1 in mode 82 (decrypt/authenticate/"other"), and PW3 (admin).
 *
 * This is intentionally a plain mutable holder with no card communication of its own; the decision
 * of <em>when</em> to invalidate (e.g. single-use PW1) stays with the connection, which owns the
 * card capabilities. Instances are confined to one connection and are not thread-safe.
 *
 * [0] OpenPGP smart card application spec, https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf
 */
class PinValidationState {
    private boolean pw1ValidatedForSignature; // Mode 81
    private boolean pw1ValidatedForOther; // Mode 82
    private boolean pw3Validated;

    boolean isPw1ValidatedForSignature() {
        return pw1ValidatedForSignature;
    }

    boolean isPw1ValidatedForOther() {
        return pw1ValidatedForOther;
    }

    boolean isPw3Validated() {
        return pw3Validated;
    }

    void markPw1ValidatedForSignature() {
        pw1ValidatedForSignature = true;
    }

    void markPw1ValidatedForOther() {
        pw1ValidatedForOther = true;
    }

    void markPw3Validated() {
        pw3Validated = true;
    }

    /** Clears all PIN validations, e.g. after (re)connecting to the card. */
    void reset() {
        pw1ValidatedForSignature = false;
        pw1ValidatedForOther = false;
        pw3Validated = false;
    }

    /** Invalidates the signing PIN (PW1 mode 81), e.g. after a single-use signature. */
    void invalidatePw1ForSignature() {
        pw1ValidatedForSignature = false;
    }

    /** Invalidates the admin PIN (PW3). */
    void invalidatePw3() {
        pw3Validated = false;
    }
}
