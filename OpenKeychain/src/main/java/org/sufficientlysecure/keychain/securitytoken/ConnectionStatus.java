package org.sufficientlysecure.keychain.securitytoken;


/**
 * Represents the lifecycle state of a {@link SecurityTokenConnection}.
 *
 * <ul>
 *   <li>{@link #DISCONNECTED} — no active transport connection</li>
 *   <li>{@link #CONNECTING} — transport.connect() has been called, applet selection / capabilities
 *       refresh / secure messaging establishment are in progress</li>
 *   <li>{@link #CONNECTED} — OpenPGP applet selected, capabilities loaded, ready for operations</li>
 * </ul>
 */
public enum ConnectionStatus {
    DISCONNECTED,
    CONNECTING,
    CONNECTED;

    /**
     * @return true if the connection is fully established and ready for APDU communication
     */
    public boolean isConnected() {
        return this == CONNECTED;
    }

    /**
     * Guard that throws if the connection is not in {@link #CONNECTED} state.
     * Used by {@link SecurityTokenConnection#communicate(CommandApdu)} to prevent
     * APDU exchange before the OpenPGP applet has been selected and capabilities loaded.
     *
     * @throws IllegalStateException if the status is not {@link #CONNECTED}
     */
    public void requireConnected() {
        if (this != CONNECTED) {
            throw new IllegalStateException(
                    "SecurityTokenConnection is not connected (status: " + this + ")");
        }
    }
}
