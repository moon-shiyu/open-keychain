package org.sufficientlysecure.keychain.securitytoken;


/**
 * Tracks PIN validation state for an OpenPGP card session.
 *
 * <p>The OpenPGP card specification defines three PIN verification modes:
 * <ul>
 *   <li>PW1 mode 81 — for digital signature operations (PSO: COMPUTE DIGITAL SIGNATURE)</li>
 *   <li>PW1 mode 82 — for other operations (PSO: DECIPHER, INTERNAL AUTHENTICATE, etc.)</li>
 *   <li>PW3 — admin PIN for management operations (key import, PIN change, etc.)</li>
 * </ul>
 *
 * <p>Once verified, a PIN remains valid for the duration of the card session unless explicitly
 * invalidated. PW1 mode 81 may be configured as "single use" — invalidated after each signature
 * operation — controlled by the card's {@link OpenPgpCapabilities#isPw1ValidForMultipleSignatures()}
 * flag.
 *
 * <p>This class is a pure state holder with no I/O dependencies. It is extracted from
 * {@link SecurityTokenConnection} to make PIN state management explicit and independently testable.
 */
public class PinState {

    private boolean isPw1ValidatedForSignature; // Mode 81
    private boolean isPw1ValidatedForOther;     // Mode 82
    private boolean isPw3Validated;


    // region queries

    /**
     * @return true if PW1 has been verified for signature operations (mode 81) and has not been
     *         invalidated since
     */
    public boolean isPw1ValidatedForSignature() {
        return isPw1ValidatedForSignature;
    }

    /**
     * @return true if PW1 has been verified for other operations (mode 82) and has not been
     *         invalidated since
     */
    public boolean isPw1ValidatedForOther() {
        return isPw1ValidatedForOther;
    }

    /**
     * @return true if PW3 (admin PIN) has been verified and has not been invalidated since
     */
    public boolean isPw3Validated() {
        return isPw3Validated;
    }

    // endregion

    // region state transitions

    /**
     * Mark PW1 as validated for signature operations. Called after a successful VERIFY command
     * with P2=0x81.
     */
    public void markPw1ValidatedForSignature() {
        isPw1ValidatedForSignature = true;
    }

    /**
     * Mark PW1 as validated for other operations. Called after a successful VERIFY command
     * with P2=0x82.
     */
    public void markPw1ValidatedForOther() {
        isPw1ValidatedForOther = true;
    }

    /**
     * Mark PW3 (admin PIN) as validated. Called after a successful VERIFY command with P2=0x83.
     */
    public void markPw3Validated() {
        isPw3Validated = true;
    }

    // endregion

    // region invalidation

    /**
     * Conditionally invalidate PW1 for signature operations after a signing operation.
     *
     * <p>If the card is configured with {@code pw1ValidForMultipleSignatures = false}, the
     * signature PIN validation is reset so the next signing operation will require re-verification.
     * If {@code pw1ValidForMultipleSignatures = true}, the PIN remains valid.
     *
     * @param pw1ValidForMultipleSignatures the card's "PW1 valid for multiple signatures" flag
     *        from the application related data (DO 0x006E → C4 → byte 0)
     */
    public void invalidateSingleUsePw1(boolean pw1ValidForMultipleSignatures) {
        if (!pw1ValidForMultipleSignatures) {
            isPw1ValidatedForSignature = false;
        }
    }

    /**
     * Unconditionally invalidate PW3. Called after admin PIN change operations.
     */
    public void invalidatePw3() {
        isPw3Validated = false;
    }

    /**
     * Reset all PIN validation flags. Called when a new connection is established
     * (via {@link SecurityTokenConnection#connectToDevice(android.content.Context)}) or when
     * the connection is explicitly torn down.
     */
    public void reset() {
        isPw1ValidatedForSignature = false;
        isPw1ValidatedForOther = false;
        isPw3Validated = false;
    }

    // endregion
}
