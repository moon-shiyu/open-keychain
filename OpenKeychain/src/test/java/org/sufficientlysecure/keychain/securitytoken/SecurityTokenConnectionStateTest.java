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

import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.securitytoken.SecurityTokenInfo.TokenType;
import org.sufficientlysecure.keychain.securitytoken.SecurityTokenInfo.TransportType;
import org.sufficientlysecure.keychain.util.Passphrase;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


/**
 * Behavioral tests for the connection-level state that {@link SecurityTokenConnection} owns: PIN
 * validation de-duplication / single-use invalidation, capability refresh, APDU error mapping, and
 * transport release on a dropped connection.
 *
 * These drive a mocked {@link Transport} (same approach as {@link SecurityTokenConnectionTest}) and
 * assert on the number of {@code transceive} round-trips and on thrown exceptions, rather than on
 * exact APDU bytes, so the tests stay robust to APDU-encoding details while still pinning the
 * observable protocol behavior.
 *
 * <p>The capability blob below is the standard test card data (also used in
 * {@link SecurityTokenConnectionTest}). For it: KDF is disabled (so a VERIFY is a single
 * {@code transceive} with no extra KDF round-trip), secure messaging is disabled, extended APDUs are
 * unsupported (so each short command is exactly one {@code transceive}), and the PW status byte C4[0]
 * is {@code 00} &rarr; PW1 is single-use for signing. {@link #CAPS_MULTI_USE_PW1} flips only that
 * byte to {@code 01} &rarr; PW1 stays valid for multiple signatures.
 */
@RunWith(KeychainTestRunner.class)
public class SecurityTokenConnectionStateTest {

    private static final String CAPS_SINGLE_USE_PW1 =
            "6e81de4f10d27600012401020000060364311500005f520f0073000080000000000000000000007381b7c00af" +
            "00000ff04c000ff00ffc106010800001103c206010800001103c306010800001103c407007f7f7f03" +
            "0303c53c4ec5fee25c4e89654d58cad8492510a89d3c3d8468da7b24e15bfc624c6a792794f15b759" +
            "9915f703aab55ed25424d60b17026b7b06c6ad4b9be30a3c63c000000000000000000000000000000" +
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
            "000000000cd0c59cd0f2a59cd0af059cd0c95";

    // Identical card data, except the PW status byte C4[0] is flipped 00 -> 01 (PW1 multi-use).
    private static final String CAPS_MULTI_USE_PW1 =
            CAPS_SINGLE_USE_PW1.replace("c407007f7f7f030303", "c407017f7f7f030303");

    private Transport transport;

    @Before
    public void setUp() {
        ShadowLog.stream = System.out;

        transport = mock(Transport.class);
        when(transport.getTransportType()).thenReturn(TransportType.USB);
        when(transport.getTokenTypeIfAvailable()).thenReturn(TokenType.YUBIKEY_NEO);
    }

    @Test
    public void pinVerification_isDeduplicatedWithinSession() throws Exception {
        SecurityTokenConnection connection = connectionWithCaps(CAPS_SINGLE_USE_PW1);
        replyToAnyCommandWith("9000");

        connection.verifyPinForSignature();
        connection.verifyPinForSignature();

        // Second call must be a no-op: PW1/81 is already validated for this session.
        verify(transport, times(1)).transceive(any(CommandApdu.class));
    }

    @Test
    public void singleUsePw1_isInvalidated_forcingReverify() throws Exception {
        SecurityTokenConnection connection = connectionWithCaps(CAPS_SINGLE_USE_PW1);
        replyToAnyCommandWith("9000");

        connection.verifyPinForSignature();
        connection.invalidateSingleUsePw1();
        connection.verifyPinForSignature();

        // Single-use PW1 was invalidated, so the second verify must hit the card again.
        verify(transport, times(2)).transceive(any(CommandApdu.class));
    }

    @Test
    public void multiUsePw1_isKept_acrossInvalidateCall() throws Exception {
        SecurityTokenConnection connection = connectionWithCaps(CAPS_MULTI_USE_PW1);
        replyToAnyCommandWith("9000");

        connection.verifyPinForSignature();
        connection.invalidateSingleUsePw1();
        connection.verifyPinForSignature();

        // PW1 is valid for multiple signatures, so invalidateSingleUsePw1() is a no-op here.
        verify(transport, times(1)).transceive(any(CommandApdu.class));
    }

    @Test
    public void signatureAndOtherPw1_areTrackedIndependently() throws Exception {
        SecurityTokenConnection connection = connectionWithCaps(CAPS_SINGLE_USE_PW1);
        replyToAnyCommandWith("9000");

        connection.verifyPinForSignature();
        connection.verifyPinForOther();

        // Mode 81 (signing) and mode 82 (other) are independent validations -> two round-trips.
        verify(transport, times(2)).transceive(any(CommandApdu.class));
    }

    @Test
    public void apduErrorResponse_onVerify_throwsCardExceptionWithSw() throws Exception {
        SecurityTokenConnection connection = connectionWithCaps(CAPS_SINGLE_USE_PW1);
        replyToAnyCommandWith("63c0"); // non-success status word

        try {
            connection.verifyPinForSignature();
            fail("expected CardException for non-success status word");
        } catch (CardException e) {
            assertEquals(0x63C0, e.getResponseCode() & 0xFFFF);
        }
    }

    @Test
    public void refreshConnectionCapabilities_replacesCachedCapabilities() throws Exception {
        SecurityTokenConnection connection = connectionWithCaps(CAPS_SINGLE_USE_PW1);
        assertFalse(connection.getOpenPgpCapabilities().isPw1ValidForMultipleSignatures());

        replyToAnyCommandWith(CAPS_MULTI_USE_PW1 + "9000");
        connection.refreshConnectionCapabilities();

        assertTrue(connection.getOpenPgpCapabilities().isPw1ValidForMultipleSignatures());
    }

    @Test
    public void connectionDrop_releasesTransport() throws Exception {
        SecurityTokenConnection connection =
                new SecurityTokenConnection(transport, new Passphrase("123456"), new OpenPgpCommandApduFactory());
        doThrow(new IOException("connection dropped")).when(transport).connect();

        try {
            connection.connectToDevice(RuntimeEnvironment.getApplication());
            fail("expected the transport IOException to propagate");
        } catch (IOException e) {
            // expected
        }

        verify(transport).release();
    }

    private SecurityTokenConnection connectionWithCaps(String capsBlobHex) throws Exception {
        SecurityTokenConnection connection =
                new SecurityTokenConnection(transport, new Passphrase("123456"), new OpenPgpCommandApduFactory());
        connection.setConnectionCapabilities(OpenPgpCapabilities.fromBytes(Hex.decode(capsBlobHex)));
        return connection;
    }

    private void replyToAnyCommandWith(String responseApduHex) throws Exception {
        when(transport.transceive(any(CommandApdu.class)))
                .thenReturn(ResponseApdu.fromBytes(Hex.decode(responseApduHex)));
    }
}
