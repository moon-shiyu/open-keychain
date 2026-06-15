package org.sufficientlysecure.keychain.securitytoken;


import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.sufficientlysecure.keychain.KeychainTestRunner;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


/**
 * Unit tests for {@link ApduCommunicator}.
 * Tests the transport-level APDU pipeline: size adaptation, command chaining, and GET RESPONSE loop.
 */
@RunWith(KeychainTestRunner.class)
public class ApduCommunicatorTest {

    private Transport transport;
    private OpenPgpCommandApduFactory commandFactory;

    @Before
    public void setUp() {
        transport = mock(Transport.class);
        commandFactory = new OpenPgpCommandApduFactory();
    }

    // region extended APDU — direct passthrough

    @Test
    public void test_communicate_withExtendedCapabilities_sendsDirectly() throws Exception {
        CardCapabilities cardCapabilities = createCardCapabilities(true, false);
        ApduCommunicator apduCommunicator = new ApduCommunicator(transport, commandFactory, cardCapabilities);

        CommandApdu command = CommandApdu.create(0x00, 0xCA, 0x00, 0x6E, 256);
        ResponseApdu expectedResponse = ResponseApdu.fromBytes(new byte[] { 0x01, 0x02, (byte) 0x90, 0x00 });
        when(transport.transceive(command)).thenReturn(expectedResponse);

        ResponseApdu result = apduCommunicator.communicate(command);

        assertEquals(expectedResponse, result);
        verify(transport).transceive(command);
    }

    // endregion

    // region short APDU — converted when suitable

    @Test
    public void test_communicate_withShortApdu_convertsToShort() throws Exception {
        CardCapabilities cardCapabilities = createCardCapabilities(false, false);
        ApduCommunicator apduCommunicator = new ApduCommunicator(transport, commandFactory, cardCapabilities);

        // Small data payload (3 bytes) — fits in short APDU
        CommandApdu command = CommandApdu.create(0x00, 0xCA, 0x00, 0x6E, new byte[] { 1, 2, 3 });
        ResponseApdu expectedResponse = ResponseApdu.fromBytes(new byte[] { (byte) 0x90, 0x00 });
        when(transport.transceive(any(CommandApdu.class))).thenReturn(expectedResponse);

        ResponseApdu result = apduCommunicator.communicate(command);

        assertEquals(expectedResponse, result);
    }

    // endregion

    // region command chaining

    @Test
    public void test_communicate_withChaining_splitsAndSendsAll() throws Exception {
        CardCapabilities cardCapabilities = createCardCapabilities(false, true);
        ApduCommunicator apduCommunicator = new ApduCommunicator(transport, commandFactory, cardCapabilities);

        // Create a command with data > 254 bytes to force chaining
        byte[] largeData = new byte[300];
        CommandApdu command = CommandApdu.create(0x00, 0xDA, 0x00, 0x6E, largeData);

        ResponseApdu intermediateResponse = ResponseApdu.fromBytes(new byte[] { (byte) 0x90, 0x00 });
        ResponseApdu finalResponse = ResponseApdu.fromBytes(new byte[] { 0x01, 0x02, (byte) 0x90, 0x00 });

        when(transport.transceive(any(CommandApdu.class)))
                .thenReturn(intermediateResponse)
                .thenReturn(finalResponse);

        ResponseApdu result = apduCommunicator.communicate(command);

        assertEquals(finalResponse, result);
        verify(transport, times(2)).transceive(any(CommandApdu.class));
    }

    @Test
    public void test_communicate_chainingIntermediateFailure_throwsIOException() throws Exception {
        CardCapabilities cardCapabilities = createCardCapabilities(false, true);
        ApduCommunicator apduCommunicator = new ApduCommunicator(transport, commandFactory, cardCapabilities);

        byte[] largeData = new byte[300];
        CommandApdu command = CommandApdu.create(0x00, 0xDA, 0x00, 0x6E, largeData);

        // Intermediate chain step fails
        ResponseApdu failureResponse = ResponseApdu.fromBytes(new byte[] { 0x69, (byte) 0x85 });
        when(transport.transceive(any(CommandApdu.class))).thenReturn(failureResponse);

        try {
            apduCommunicator.communicate(command);
            fail("Expected IOException for intermediate chaining failure");
        } catch (IOException e) {
            assertEquals(true, e.getMessage().contains("Failed to chain apdu"));
        }
    }

    @Test
    public void test_communicate_noChainingNoExtended_throwsForLargeCommand() throws Exception {
        CardCapabilities cardCapabilities = createCardCapabilities(false, false);
        ApduCommunicator apduCommunicator = new ApduCommunicator(transport, commandFactory, cardCapabilities);

        // Large data that doesn't fit in short APDU and chaining not available
        byte[] largeData = new byte[300];
        CommandApdu command = CommandApdu.create(0x00, 0xDA, 0x00, 0x6E, largeData);

        try {
            apduCommunicator.communicate(command);
            fail("Expected IOException when command too long and no chaining");
        } catch (IOException e) {
            assertEquals("Command too long, and chaining unavailable", e.getMessage());
        }
    }

    // endregion

    // region GET RESPONSE loop

    @Test
    public void test_communicate_getResponseLoop_accumulatesData() throws Exception {
        CardCapabilities cardCapabilities = createCardCapabilities(true, false);
        ApduCommunicator apduCommunicator = new ApduCommunicator(transport, commandFactory, cardCapabilities);

        CommandApdu command = CommandApdu.create(0x00, 0xCA, 0x00, 0x6E, 256);

        // Initial response: SW1=0x61 (more data), SW2=0x20 (32 bytes remaining)
        ResponseApdu firstResponse = ResponseApdu.fromBytes(
                new byte[] { 0x01, 0x02, 0x03, 0x04, 0x61, 0x20 });
        // GET RESPONSE returns final data
        ResponseApdu secondResponse = ResponseApdu.fromBytes(
                new byte[] { 0x05, 0x06, 0x07, 0x08, (byte) 0x90, 0x00 });

        when(transport.transceive(command)).thenReturn(firstResponse);
        when(transport.transceive(any(CommandApdu.class))).thenReturn(firstResponse, secondResponse);

        ResponseApdu result = apduCommunicator.communicate(command);

        // Verify accumulated data: [01, 02, 03, 04, 05, 06, 07, 08] + SW 9000
        assertEquals(true, result.isSuccess());
        assertArrayEquals(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
                result.getData());
    }

    @Test
    public void test_communicate_getResponseLoop_multipleChained() throws Exception {
        CardCapabilities cardCapabilities = createCardCapabilities(true, false);
        ApduCommunicator apduCommunicator = new ApduCommunicator(transport, commandFactory, cardCapabilities);

        CommandApdu command = CommandApdu.create(0x00, 0xCA, 0x00, 0x6E, 256);

        // Three responses chained: first two have SW1=0x61, last has SW1=0x90
        ResponseApdu resp1 = ResponseApdu.fromBytes(
                new byte[] { 0x0A, 0x0B, 0x61, 0x10 });
        ResponseApdu resp2 = ResponseApdu.fromBytes(
                new byte[] { 0x0C, 0x0D, 0x61, 0x10 });
        ResponseApdu resp3 = ResponseApdu.fromBytes(
                new byte[] { 0x0E, 0x0F, (byte) 0x90, 0x00 });

        when(transport.transceive(any(CommandApdu.class)))
                .thenReturn(resp1)
                .thenReturn(resp2)
                .thenReturn(resp3);

        ResponseApdu result = apduCommunicator.communicate(command);

        assertEquals(true, result.isSuccess());
        assertArrayEquals(new byte[] { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
                result.getData());
    }

    @Test
    public void test_communicate_noGetResponseNeeded_whenSw1Not61() throws Exception {
        CardCapabilities cardCapabilities = createCardCapabilities(true, false);
        ApduCommunicator apduCommunicator = new ApduCommunicator(transport, commandFactory, cardCapabilities);

        CommandApdu command = CommandApdu.create(0x00, 0xCA, 0x00, 0x6E, 256);
        ResponseApdu singleResponse = ResponseApdu.fromBytes(
                new byte[] { 0x01, 0x02, (byte) 0x90, 0x00 });

        when(transport.transceive(command)).thenReturn(singleResponse);

        ResponseApdu result = apduCommunicator.communicate(command);

        assertEquals(singleResponse, result);
        verify(transport, times(1)).transceive(any(CommandApdu.class));
    }

    // endregion

    // region error propagation

    @Test
    public void test_communicate_transportError_propagatesIOException() throws Exception {
        CardCapabilities cardCapabilities = createCardCapabilities(true, false);
        ApduCommunicator apduCommunicator = new ApduCommunicator(transport, commandFactory, cardCapabilities);

        CommandApdu command = CommandApdu.create(0x00, 0xCA, 0x00, 0x6E, 256);
        when(transport.transceive(command)).thenThrow(new IOException("USB disconnected"));

        try {
            apduCommunicator.communicate(command);
            fail("Expected IOException from transport failure");
        } catch (IOException e) {
            assertEquals("USB disconnected", e.getMessage());
        }
    }

    // endregion

    // region card error responses (non-success SW)

    @Test
    public void test_communicate_cardError_stillReturnsResponse() throws Exception {
        CardCapabilities cardCapabilities = createCardCapabilities(true, false);
        ApduCommunicator apduCommunicator = new ApduCommunicator(transport, commandFactory, cardCapabilities);

        CommandApdu command = CommandApdu.create(0x00, 0x20, 0x00, (byte) 0x81, new byte[] { 0x31, 0x32 });
        // Card returns "Bad PIN" error
        ResponseApdu errorResponse = ResponseApdu.fromBytes(new byte[] { 0x69, (byte) 0x82 });
        when(transport.transceive(command)).thenReturn(errorResponse);

        ResponseApdu result = apduCommunicator.communicate(command);

        assertEquals(0x6982, result.getSw());
        assertEquals(false, result.isSuccess());
    }

    // endregion

    // region helper methods

    /**
     * Creates a CardCapabilities instance with controlled chaining/extended support.
     * Uses synthetic historical bytes to encode the desired capabilities.
     *
     * @param hasExtended  whether the card supports extended APDUs
     * @param hasChaining  whether the card supports command chaining
     */
    private static CardCapabilities createCardCapabilities(boolean hasExtended, boolean hasChaining) throws Exception {
        // Build historical bytes with a 0x73 Compact-TLV capability block.
        // CardCapabilities parses: ByteBuffer.wrap(bytes, 1, length-2) looking for tag 0x73
        // whose 3-byte value has the capability byte at index 2:
        //   bit 7 = chaining, bit 6 = extended
        byte capabilityByte = 0;
        if (hasChaining) capabilityByte |= (byte) 0x80; // bit 7
        if (hasExtended) capabilityByte |= (byte) 0x40; // bit 6

        byte[] historicalBytes = new byte[] {
                0x00,                               // category indicator byte (must be 0x00)
                0x73, 0x00, 0x00, capabilityByte,   // Compact-TLV: tag 0x73 + 3 value bytes
                0x00, 0x00                          // Yubikey Neo-style ending
        };

        return new CardCapabilities(historicalBytes, SecurityTokenInfo.TokenType.YUBIKEY_NEO);
    }

    // endregion
}
