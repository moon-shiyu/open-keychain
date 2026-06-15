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

package org.sufficientlysecure.keychain.provider;


import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.support.KeyringTestingHelper;


@RunWith(KeychainTestRunner.class)
public class KeyRepositoryDeleteTest {

    @BeforeClass
    public static void setUpOnce() {
        ShadowLog.stream = System.out;
    }

    @Test
    public void testDeleteCascades() throws Exception {
        KeyWritableRepository keyRepository = KeyWritableRepository.create(RuntimeEnvironment.getApplication());

        UncachedKeyRing ring =
                KeyringTestingHelper.readRingFromResource("/test-keys/mailvelope_07_no_key_flags.asc");
        long masterKeyId = ring.getMasterKeyId();

        Assert.assertTrue("public keyring import should succeed",
                keyRepository.savePublicKeyRing(ring).success());

        // sanity: keys and user ids are present before deletion
        Assert.assertFalse("subkeys should be present before delete",
                keyRepository.getSubKeysByMasterKeyId(masterKeyId).isEmpty());
        Assert.assertFalse("user ids should be present before delete",
                keyRepository.getUserIds(masterKeyId).isEmpty());

        Assert.assertTrue("delete of existing keyring should return true",
                keyRepository.deleteKeyRing(masterKeyId));

        // the keyrings_public row is gone, and keys + user_packets are removed on cascade
        Assert.assertTrue("subkeys should be gone after delete",
                keyRepository.getSubKeysByMasterKeyId(masterKeyId).isEmpty());
        Assert.assertTrue("user ids should be gone after delete",
                keyRepository.getUserIds(masterKeyId).isEmpty());

        try {
            keyRepository.getCanonicalizedPublicKeyRing(masterKeyId);
            Assert.fail("retrieving a deleted keyring should throw NotFoundException");
        } catch (KeyRepository.NotFoundException expected) {
            // good
        }
    }

    @Test
    public void testDeleteNonexistentReturnsFalse() {
        KeyWritableRepository keyRepository = KeyWritableRepository.create(RuntimeEnvironment.getApplication());

        long unknownMasterKeyId = 0x1234567890abcdefL;
        Assert.assertFalse("deleting a nonexistent keyring should return false",
                keyRepository.deleteKeyRing(unknownMasterKeyId));
    }
}
