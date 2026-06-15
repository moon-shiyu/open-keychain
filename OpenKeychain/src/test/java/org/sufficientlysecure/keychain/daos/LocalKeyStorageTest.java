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

package org.sufficientlysecure.keychain.daos;


import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.sufficientlysecure.keychain.KeychainTestRunner;


/** Tests the on-disk public/secret key storage layer that the repository's oversized-keyring branch relies on. */
@RunWith(KeychainTestRunner.class)
public class LocalKeyStorageTest {

    private static final byte[] SAMPLE_DATA = new byte[] { 1, 2, 3, 4, 5, (byte) 0xFF, 0, 42, (byte) 0x80 };

    private LocalPublicKeyStorage localPublicKeyStorage;
    private LocalSecretKeyStorage localSecretKeyStorage;

    @Before
    public void setUp() {
        localPublicKeyStorage = LocalPublicKeyStorage.getInstance(RuntimeEnvironment.getApplication());
        localSecretKeyStorage = LocalSecretKeyStorage.getInstance(RuntimeEnvironment.getApplication());
    }

    @Test
    public void testPublicWriteThenReadRoundTrips() throws Exception {
        long masterKeyId = 0x0011223344556677L;

        localPublicKeyStorage.writePublicKey(masterKeyId, SAMPLE_DATA);

        Assert.assertArrayEquals(SAMPLE_DATA, localPublicKeyStorage.readPublicKey(masterKeyId));
    }

    @Test
    public void testPublicReadMissingReturnsNull() throws Exception {
        Assert.assertNull(localPublicKeyStorage.readPublicKey(0x7766554433221100L));
    }

    @Test
    public void testPublicDeleteRemovesFile() throws Exception {
        long masterKeyId = 0x00aa00bb00cc00ddL;

        localPublicKeyStorage.writePublicKey(masterKeyId, SAMPLE_DATA);
        Assert.assertArrayEquals(SAMPLE_DATA, localPublicKeyStorage.readPublicKey(masterKeyId));

        localPublicKeyStorage.deletePublicKey(masterKeyId);
        Assert.assertNull("reading a deleted public key should return null",
                localPublicKeyStorage.readPublicKey(masterKeyId));
    }

    @Test
    public void testPublicDeleteMissingIsNoOp() throws Exception {
        // deleting a key that was never written must not throw
        localPublicKeyStorage.deletePublicKey(0x1111111111111111L);
    }

    @Test
    public void testSecretWriteThenReadRoundTrips() throws Exception {
        long masterKeyId = 0x0011223344556677L;

        localSecretKeyStorage.writeSecretKey(masterKeyId, SAMPLE_DATA);

        Assert.assertArrayEquals(SAMPLE_DATA, localSecretKeyStorage.readSecretKey(masterKeyId));
    }

    @Test
    public void testSecretReadMissingReturnsNull() throws Exception {
        Assert.assertNull(localSecretKeyStorage.readSecretKey(0x7766554433221100L));
    }

    @Test
    public void testSecretDeleteRemovesFile() throws Exception {
        long masterKeyId = 0x00aa00bb00cc00ddL;

        localSecretKeyStorage.writeSecretKey(masterKeyId, SAMPLE_DATA);
        Assert.assertArrayEquals(SAMPLE_DATA, localSecretKeyStorage.readSecretKey(masterKeyId));

        localSecretKeyStorage.deleteSecretKey(masterKeyId);
        Assert.assertNull("reading a deleted secret key should return null",
                localSecretKeyStorage.readSecretKey(masterKeyId));
    }

    @Test
    public void testSecretDeleteMissingIsNoOp() throws Exception {
        // deleting a key that was never written must not throw
        localSecretKeyStorage.deleteSecretKey(0x1111111111111111L);
    }
}
