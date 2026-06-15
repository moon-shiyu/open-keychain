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

package org.sufficientlysecure.keychain.operations.importOperation;


import java.util.ArrayList;

import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.operations.results.SaveKeyringResult;
import org.sufficientlysecure.keychain.pgp.CanonicalizedKeyRing;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;


/**
 * Wraps the synchronized save dispatch for key imports. Encapsulates the
 * public/secret branching and {@code clearLog()} call that must happen
 * inside the {@code synchronized(keyRepository)} block.
 *
 * <p>Extracted from {@code ImportOperation} to make the save boundary
 * explicit and independently testable.
 *
 * @see <a href="https://github.com/open-keychain/open-keychain/issues/1221">#1221</a>
 * @see <a href="https://github.com/open-keychain/open-keychain/issues/1480">#1480</a>
 */
public class ImportKeySaver {

    private final KeyRepository keyRepository;
    private final KeyWritableRepository writableRepository;

    public ImportKeySaver(KeyRepository keyRepository, KeyWritableRepository writableRepository) {
        this.keyRepository = keyRepository;
        this.writableRepository = writableRepository;
    }

    /**
     * Saves a key ring inside a {@code synchronized(keyRepository)} block,
     * dispatching to the public or secret save method as appropriate.
     *
     * @param key                 the decoded key ring to save
     * @param expectedFingerprint optional expected fingerprint for public keys
     * @param canKeyRings         list that will be populated with canonicalized
     *                            rings as a side effect of the save
     * @param skipSave            if true, canonicalize but don't persist
     * @param forceReinsert       if true, force a full re-insert even for
     *                            existing keys (public keys only)
     * @return the save result
     */
    public SaveKeyringResult save(UncachedKeyRing key, byte[] expectedFingerprint,
            ArrayList<CanonicalizedKeyRing> canKeyRings,
            boolean skipSave, boolean forceReinsert) {
        // synchronizing prevents https://github.com/open-keychain/open-keychain/issues/1221
        // and https://github.com/open-keychain/open-keychain/issues/1480
        synchronized (keyRepository) {
            keyRepository.clearLog();
            if (key.isSecret()) {
                return writableRepository.saveSecretKeyRing(key, canKeyRings, skipSave);
            } else {
                return writableRepository.savePublicKeyRing(key, expectedFingerprint,
                        canKeyRings, forceReinsert, skipSave);
            }
        }
    }
}
