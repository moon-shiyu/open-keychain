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


import java.io.IOException;
import java.util.Arrays;

import android.content.Context;
import android.os.SystemClock;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;

import org.sufficientlysecure.keychain.securitytoken.SecurityTokenInfo.TokenType;
import org.sufficientlysecure.keychain.securitytoken.SecurityTokenInfo.TransportType;
import org.sufficientlysecure.keychain.util.Passphrase;
import timber.log.Timber;


/**
 * This class provides a communication interface to OpenPGP applications on ISO SmartCard compliant
 * devices.
 * For the full specs, see [0]
 *
 * References:
 * [0] `Functional Specification of the OpenPGP application on ISO Smart Card Operating Systems`
 *      version 3.4.1
 *      https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf
 */
public class SecurityTokenConnection {
    private static final String AID_PREFIX_FIDESMO = "A000000617";

    private static SecurityTokenConnection sCachedInstance;

    @NonNull
    private final Transport transport;
    @Nullable
    private final Passphrase cachedPin;
    private final OpenPgpCommandApduFactory commandFactory;

    private ConnectionStatus connectionStatus = ConnectionStatus.DISCONNECTED;

    private TokenType tokenType;
    private CardCapabilities cardCapabilities;
    private OpenPgpCapabilities openPgpCapabilities;
    private KdfParameters kdfParameters;

    private SecureMessaging secureMessaging;

    private final PinState pinState = new PinState();


    public static SecurityTokenConnection getInstanceForTransport(
            @NonNull Transport transport, @Nullable Passphrase pin) {
        // Clean up stale cached connection if transport has disconnected
        if (sCachedInstance != null && !sCachedInstance.isConnected()) {
            sCachedInstance.disconnect();
            sCachedInstance = null;
        }

        if (sCachedInstance == null || !sCachedInstance.isPersistentConnectionAllowed() ||
                !sCachedInstance.isConnected() || !sCachedInstance.transport.equals(transport) ||
                (pin != null && !pin.equals(sCachedInstance.cachedPin))) {
            sCachedInstance = new SecurityTokenConnection(transport, pin, new OpenPgpCommandApduFactory());
        }
        return sCachedInstance;
    }

    public static void clearCachedConnections() {
        sCachedInstance = null;
    }


    @VisibleForTesting
    SecurityTokenConnection(@NonNull Transport transport, @Nullable Passphrase pin,
            OpenPgpCommandApduFactory commandFactory) {
        this.transport = transport;
        this.cachedPin = pin;

        this.commandFactory = commandFactory;
    }

    // region connection management

    public void connectIfNecessary(Context context) throws IOException {
        if (isConnected()) {
            refreshConnectionCapabilities();
            return;
        }

        connectToDevice(context);
    }

    /**
     * Connect to device and select pgp applet
     */
    @VisibleForTesting
    void connectToDevice(Context context) throws IOException {
        connectionStatus = ConnectionStatus.CONNECTING;
        try {
            // Connect on transport layer
            transport.connect();

            // dummy instance for initial communicate() calls
            cardCapabilities = new CardCapabilities();

            determineTokenType();

            CommandApdu select = commandFactory.createSelectFileOpenPgpCommand();
            ResponseApdu response = communicate(select);  // activate connection

            if (!response.isSuccess()) {
                throw new CardException("Initialization failed!", response.getSw());
            }

            refreshConnectionCapabilities();

            pinState.reset();

            smEstablishIfAvailable(context);

            connectionStatus = ConnectionStatus.CONNECTED;
        } catch (IOException e) {
            connectionStatus = ConnectionStatus.DISCONNECTED;
            transport.release();
            throw e;
        }
    }

    @VisibleForTesting
    void determineTokenType() throws IOException {
        tokenType = transport.getTokenTypeIfAvailable();
        if (tokenType != null) {
            return;
        }

        CommandApdu selectFidesmoApdu = commandFactory.createSelectFileCommand(AID_PREFIX_FIDESMO);
        if (communicate(selectFidesmoApdu).isSuccess()) {
            tokenType = TokenType.FIDESMO;
            return;
        }

        /* We could determine if this is a yubikey here. The info isn't used at the moment, so we save the roundtrip
        // AID from https://github.com/Yubico/ykneo-oath/blob/master/build.xml#L16
        CommandApdu selectYubicoApdu = commandFactory.createSelectFileCommand("A000000527200101");
        if (communicate(selectYubicoApdu).isSuccess()) {
            tokenType = TokenType.YUBIKEY_UNKNOWN;
            return;
        }
        */

        tokenType = TokenType.UNKNOWN;
    }

    public void refreshConnectionCapabilities() throws IOException {
        byte[] rawOpenPgpCapabilities = readData(0x00, 0x6E);

        OpenPgpCapabilities openPgpCapabilities = OpenPgpCapabilities.fromBytes(rawOpenPgpCapabilities);
        setConnectionCapabilities(openPgpCapabilities);
    }

    @VisibleForTesting
    void setConnectionCapabilities(OpenPgpCapabilities openPgpCapabilities) throws IOException {
        this.openPgpCapabilities = openPgpCapabilities;
        this.cardCapabilities = new CardCapabilities(openPgpCapabilities.getHistoricalBytes(), tokenType);
    }

    // endregion

    // region communication

    /**
     * Transceives APDU through the full pipeline:
     * <ol>
     *   <li>Secure messaging encrypt (if SM is active)</li>
     *   <li>Transport: size adaptation + command chaining + transceive + GET RESPONSE chaining</li>
     *   <li>Secure messaging decrypt (if SM is active)</li>
     * </ol>
     *
     * <p>Throws {@link IllegalStateException} if called when the connection is
     * {@link ConnectionStatus#DISCONNECTED}.
     *
     * @param commandApdu short or extended APDU to transceive
     * @return response from the card
     * @throws IOException on transport or secure messaging failure
     */
    public ResponseApdu communicate(CommandApdu commandApdu) throws IOException {
        if (connectionStatus == ConnectionStatus.DISCONNECTED) {
            throw new IllegalStateException(
                    "SecurityTokenConnection is not connected (status: " + connectionStatus + ")");
        }

        ApduCommunicator apduCommunicator = ApduCommunicator.create(
                transport, commandFactory, cardCapabilities);

        commandApdu = smEncryptIfAvailable(commandApdu);

        ResponseApdu lastResponse;
        try {
            lastResponse = apduCommunicator.communicate(commandApdu);
        } catch (IOException e) {
            if (!transport.isConnected()) {
                connectionStatus = ConnectionStatus.DISCONNECTED;
            }
            throw e;
        }

        lastResponse = smDecryptIfAvailable(lastResponse);

        return lastResponse;
    }

    // endregion

    // region secure messaging

    private void smEstablishIfAvailable(Context context) throws IOException {
        if (!openPgpCapabilities.isHasScp11bSm()) {
            return;
        }

        try {
            long elapsedRealtimeStart = SystemClock.elapsedRealtime();
            secureMessaging = SCP11bSecureMessaging.establish(this, context, commandFactory);
            long elapsedTime = SystemClock.elapsedRealtime() - elapsedRealtimeStart;
            Timber.d("Established Secure Messaging in %d ms", elapsedTime);
        } catch (SecureMessagingException e) {
            secureMessaging = null;
            Timber.e(e, "failed to establish secure messaging");
        }
    }

    private CommandApdu smEncryptIfAvailable(CommandApdu apdu) throws IOException {
        if (secureMessaging == null || !secureMessaging.isEstablished()) {
            return apdu;
        }
        try {
            return secureMessaging.encryptAndSign(apdu);
        } catch (SecureMessagingException e) {
            clearSecureMessaging();
            throw new IOException("secure messaging encrypt/sign failure : " + e.getMessage());
        }
    }

    private ResponseApdu smDecryptIfAvailable(ResponseApdu response) throws IOException {
        if (secureMessaging == null || !secureMessaging.isEstablished()) {
            return response;
        }
        try {
            return secureMessaging.verifyAndDecrypt(response);
        } catch (SecureMessagingException e) {
            clearSecureMessaging();
            throw new IOException("secure messaging verify/decrypt failure : " + e.getMessage());
        }
    }

    public void clearSecureMessaging() {
        if (secureMessaging != null) {
            secureMessaging.clearSession();
        }
        secureMessaging = null;
    }

    // endregion

    // region pin management

    private byte[] calculateKdfIfNecessary(byte[] pin, KdfParameters.PasswordType type) throws IOException {
        if (!this.openPgpCapabilities.isHasKdf()) {
            // KDF-DO is not supported by token
            return pin;
        }
        KdfParameters kdfParameters = retrieveKdfDo();
        if (kdfParameters == null || !kdfParameters.isHasUsesKdf()) {
            return pin;
        } else {
            return KdfCalculator.calculateKdf(kdfParameters.forType(type), pin);
        }
    }

    private KdfParameters retrieveKdfDo() throws IOException {
        if (this.kdfParameters != null) {
            return this.kdfParameters;
        }

        // query token for KDF-DO
        // see page 18 of [0]
        CommandApdu getKdfDoCommand = commandFactory.createGetDataCommand(0x00, 0xf9);
        ResponseApdu kdfDoResponse = communicate(getKdfDoCommand);
        if (!kdfDoResponse.isSuccess()) {
            throw new CardException("Couldn't get KDF.DO!", kdfDoResponse.getSw());
        }
        byte[] kdfDo = kdfDoResponse.getData();

        // empty KDF-DO means plain UTF-8 password is being used
        // see page 19 of [0]
        if (kdfDo.length == 0) {
            return null;
        }

        this.kdfParameters = KdfParameters.fromKdfDo(kdfDo);

        return this.kdfParameters;
    }

    public void verifyPinForSignature() throws IOException {
        if (pinState.isPw1ValidatedForSignature()) {
            return;
        }
        if (cachedPin == null) {
            throw new IllegalStateException("Connection not initialized with Pin!");
        }

        byte[] pin = cachedPin.toStringUnsafe().getBytes();

        byte[] transformedPin = this.calculateKdfIfNecessary(pin, KdfParameters.PasswordType.PW1);

        CommandApdu verifyPw1ForSignatureCommand = commandFactory.createVerifyPw1ForSignatureCommand(transformedPin);

        // delete secrets from memory
        Arrays.fill(pin, (byte) 0);
        Arrays.fill(transformedPin, (byte) 0);

        ResponseApdu response = communicate(verifyPw1ForSignatureCommand);
        if (!response.isSuccess()) {
            throw new CardException("Bad PIN!", response.getSw());
        }

        pinState.markPw1ValidatedForSignature();
    }

    public void verifyPinForOther() throws IOException {
        if (pinState.isPw1ValidatedForOther()) {
            return;
        }
        if (cachedPin == null) {
            throw new IllegalStateException("Connection not initialized with Pin!");
        }

        byte[] pin = cachedPin.toStringUnsafe().getBytes();

        byte[] transformedPin = this.calculateKdfIfNecessary(pin, KdfParameters.PasswordType.PW1);

        CommandApdu verifyPw1ForOtherCommand = commandFactory.createVerifyPw1ForOtherCommand(transformedPin);

        // delete secrets from memory
        Arrays.fill(pin, (byte) 0);
        Arrays.fill(transformedPin, (byte) 0);

        ResponseApdu response = communicate(verifyPw1ForOtherCommand);
        if (!response.isSuccess()) {
            throw new CardException("Bad PIN!", response.getSw());
        }

        pinState.markPw1ValidatedForOther();
    }

    public void verifyAdminPin(Passphrase adminPin) throws IOException {
        if (pinState.isPw3Validated()) {
            return;
        }

        byte[] pin = adminPin.toStringUnsafe().getBytes();
        byte[] transformedPin = this.calculateKdfIfNecessary(pin, KdfParameters.PasswordType.PW3);

        CommandApdu verifyPw3Command = commandFactory.createVerifyPw3Command(transformedPin);

        // delete secrets from memory
        Arrays.fill(pin, (byte) 0);
        Arrays.fill(transformedPin, (byte) 0);

        ResponseApdu response = communicate(verifyPw3Command);
        if (!response.isSuccess()) {
            throw new CardException("Bad PIN!", response.getSw());
        }

        pinState.markPw3Validated();
    }

    public void invalidateSingleUsePw1() {
        pinState.invalidateSingleUsePw1(openPgpCapabilities.isPw1ValidForMultipleSignatures());
    }

    public void invalidatePw3() {
        pinState.invalidatePw3();
    }

    // endregion

    private byte[] readData(int p1, int p2) throws IOException {
        ResponseApdu response = communicate(commandFactory.createGetDataCommand(p1, p2));
        if (!response.isSuccess()) {
            throw new CardException("Failed to get pw status bytes", response.getSw());
        }
        return response.getData();
    }


    private String readUrl() throws IOException {
        byte[] data = readData(0x5F, 0x50);
        return new String(data).trim();
    }

    private byte[] readUserId() throws IOException {
        return readData(0x00, 0x65);
    }

    public SecurityTokenInfo readTokenInfo() throws IOException {
        byte[][] fingerprints = new byte[3][];
        fingerprints[0] = openPgpCapabilities.getFingerprintSign();
        fingerprints[1] = openPgpCapabilities.getFingerprintEncrypt();
        fingerprints[2] = openPgpCapabilities.getFingerprintAuth();

        byte[] aid = openPgpCapabilities.getAid();
        String userId = parseHolderName(readUserId());
        String url = readUrl();
        int pw1TriesLeft = openPgpCapabilities.getPw1TriesLeft();
        int pw3TriesLeft = openPgpCapabilities.getPw3TriesLeft();
        boolean hasLifeCycleManagement = cardCapabilities.hasLifeCycleManagement();

        TransportType transportType = transport.getTransportType();

        return SecurityTokenInfo.create(transportType, tokenType, fingerprints, aid, userId, url, pw1TriesLeft,
                pw3TriesLeft, hasLifeCycleManagement);
    }


    public boolean isPersistentConnectionAllowed() {
        return transport.isPersistentConnectionAllowed() &&
                (secureMessaging == null || !secureMessaging.isEstablished());
    }

    public boolean isConnected() {
        return transport.isConnected();
    }

    /**
     * Explicitly tears down this connection: clears secure messaging session,
     * resets PIN state, marks the connection as disconnected, and releases the transport.
     *
     * <p>This method is idempotent — calling it on an already-disconnected connection is safe.
     */
    public void disconnect() {
        clearSecureMessaging();
        pinState.reset();
        connectionStatus = ConnectionStatus.DISCONNECTED;
        transport.release();
    }

    public TokenType getTokenType() {
        return tokenType;
    }

    public OpenPgpCapabilities getOpenPgpCapabilities() {
        return openPgpCapabilities;
    }

    public OpenPgpCommandApduFactory getCommandFactory() {
        return commandFactory;
    }

    @VisibleForTesting
    ConnectionStatus getConnectionStatus() {
        return connectionStatus;
    }

    @VisibleForTesting
    PinState getPinState() {
        return pinState;
    }


    private static String parseHolderName(byte[] name) {
        try {
            return (new String(name, 4, name[3])).replace('<', ' ');
        } catch (IndexOutOfBoundsException e) {
            // try-catch for https://github.com/FluffyKaon/OpenPGP-Card
            // Note: This should not happen, but happens with
            // https://github.com/FluffyKaon/OpenPGP-Card, thus return an empty string for now!

            Timber.e(e, "Couldn't get holder name, returning empty string!");
            return "";
        }
    }
}
