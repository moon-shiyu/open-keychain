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


import java.io.ByteArrayOutputStream;
import java.io.IOException;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;


/**
 * Handles the APDU transport layer of the communication pipeline:
 * <ul>
 *   <li>Command size adaptation — selects between extended APDU, short APDU, or command chaining
 *       based on the card's {@link CardCapabilities}</li>
 *   <li>Command chaining — splits oversized commands into CLA-chained fragments (ISO 7816-4)</li>
 *   <li>Response chaining — handles GET RESPONSE loops when SW1=0x61 indicates more data
 *       available (ISO/IEC 7816-4 §7.6.1)</li>
 * </ul>
 *
 * <p>This class is a stateless transport-layer component extracted from
 * {@link SecurityTokenConnection} to make the APDU size adaptation and response chaining logic
 * independently testable. It does NOT handle secure messaging — SM encrypt/decrypt is managed
 * by {@link SecurityTokenConnection} which wraps calls to this class.
 *
 * <p>Instances are created via {@link #create(Transport, OpenPgpCommandApduFactory, CardCapabilities)}
 * and are intended to be short-lived (typically one per {@code communicate()} call).
 */
public class ApduCommunicator {
    static final int APDU_SW1_RESPONSE_AVAILABLE = 0x61;

    @NonNull private final Transport transport;
    @NonNull private final OpenPgpCommandApduFactory commandFactory;
    @NonNull private final CardCapabilities cardCapabilities;

    @VisibleForTesting
    ApduCommunicator(@NonNull Transport transport,
            @NonNull OpenPgpCommandApduFactory commandFactory,
            @NonNull CardCapabilities cardCapabilities) {
        this.transport = transport;
        this.commandFactory = commandFactory;
        this.cardCapabilities = cardCapabilities;
    }

    /**
     * Factory method for creating an ApduCommunicator.
     *
     * @param transport the underlying NFC or USB transport
     * @param commandFactory factory for building APDU commands (chaining, short APDU conversion)
     * @param cardCapabilities card capabilities determining size adaptation strategy
     * @return a new ApduCommunicator instance
     */
    static ApduCommunicator create(@NonNull Transport transport,
            @NonNull OpenPgpCommandApduFactory commandFactory,
            @NonNull CardCapabilities cardCapabilities) {
        return new ApduCommunicator(transport, commandFactory, cardCapabilities);
    }

    /**
     * Transceives a command APDU with appropriate size adaptation and handles response chaining.
     *
     * <p>The size adaptation strategy is selected based on card capabilities:
     * <ol>
     *   <li>If the card supports extended APDUs — send directly</li>
     *   <li>If the command fits in a short APDU (≤254 bytes data) — convert to short format</li>
     *   <li>If the card supports command chaining — split into chained fragments</li>
     *   <li>Otherwise — throw {@link IOException}</li>
     * </ol>
     *
     * <p>After the command is sent, if the response indicates more data available (SW1=0x61),
     * a GET RESPONSE loop retrieves the remaining data.
     *
     * @param commandApdu the command to send (may be short or extended)
     * @return the complete response from the card
     * @throws IOException if transport fails, chaining fails mid-sequence, or the command is too
     *         large for the card's capabilities
     */
    @NonNull
    public ResponseApdu communicate(@NonNull CommandApdu commandApdu) throws IOException {
        ResponseApdu lastResponse = transceiveWithChaining(commandApdu);
        return readChainedResponseIfAvailable(lastResponse);
    }

    /**
     * Sends a command APDU using the appropriate size adaptation strategy.
     *
     * @throws IOException if the transport fails or chaining encounters an error
     */
    @NonNull
    private ResponseApdu transceiveWithChaining(@NonNull CommandApdu commandApdu) throws IOException {
        if (cardCapabilities.hasExtended()) {
            return transport.transceive(commandApdu);
        } else if (commandFactory.isSuitableForShortApdu(commandApdu)) {
            CommandApdu shortApdu = commandFactory.createShortApdu(commandApdu);
            return transport.transceive(shortApdu);
        } else if (cardCapabilities.hasChaining()) {
            return transceiveChained(commandApdu);
        } else {
            throw new IOException("Command too long, and chaining unavailable");
        }
    }

    /**
     * Splits a command into CLA-chained fragments and sends them sequentially.
     * Intermediate fragments must receive a success response; only the last fragment's
     * response is returned.
     *
     * @throws IOException if any intermediate chain step fails
     */
    @NonNull
    private ResponseApdu transceiveChained(@NonNull CommandApdu commandApdu) throws IOException {
        ResponseApdu lastResponse = null;

        java.util.List<CommandApdu> chainedApdus = commandFactory.createChainedApdus(commandApdu);
        for (int i = 0, totalCommands = chainedApdus.size(); i < totalCommands; i++) {
            CommandApdu chainedApdu = chainedApdus.get(i);
            lastResponse = transport.transceive(chainedApdu);

            boolean isLastCommand = (i == totalCommands - 1);
            if (!isLastCommand && !lastResponse.isSuccess()) {
                throw new IOException("Failed to chain apdu " +
                        "(" + i + "/" + (totalCommands - 1) + ", last SW: " + lastResponse.getSw() + ")");
            }
        }

        if (lastResponse == null) {
            throw new IllegalStateException("Chained APDU list was empty");
        }

        return lastResponse;
    }

    /**
     * Handles the GET RESPONSE loop (ISO/IEC 7816-4 §7.6.1).
     *
     * <p>If the card's response has SW1=0x61 (more data available), this method sends
     * successive GET RESPONSE commands to retrieve all remaining data, accumulating it
     * into a single response.
     *
     * @param lastResponse the initial response from the card
     * @return the complete accumulated response, or the original response if no chaining needed
     * @throws IOException if a GET RESPONSE command fails at the transport level
     */
    @NonNull
    ResponseApdu readChainedResponseIfAvailable(@NonNull ResponseApdu lastResponse) throws IOException {
        if (lastResponse.getSw1() != APDU_SW1_RESPONSE_AVAILABLE) {
            return lastResponse;
        }

        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(lastResponse.getData());

        do {
            // GET RESPONSE ISO/IEC 7816-4 par.7.6.1
            CommandApdu getResponse = commandFactory.createGetResponseCommand(lastResponse.getSw2());
            lastResponse = transport.transceive(getResponse);
            result.write(lastResponse.getData());
        } while (lastResponse.getSw1() == APDU_SW1_RESPONSE_AVAILABLE);

        result.write(lastResponse.getSw1());
        result.write(lastResponse.getSw2());

        return ResponseApdu.fromBytes(result.toByteArray());
    }
}
