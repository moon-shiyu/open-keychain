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

package org.sufficientlysecure.keychain.operations;


import java.util.ArrayList;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.sufficientlysecure.keychain.operations.ImportOperation.KeyImportAccumulator;
import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.pgp.CanonicalizedKeyRing;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


/**
 * Tests for {@link KeyImportAccumulator} — verifies backward-compatible
 * wrapper behavior after refactoring to delegate to {@link
 * org.sufficientlysecure.keychain.operations.importOperation.ImportResultBuilder}.
 */
@RunWith(JUnit4.class)
public class KeyImportAccumulatorTest {

    private ImportKeyResult makeResult(int resultType, int newKeys, int updatedKeys,
            int missingKeys, int badKeys, int secret, long[] masterKeyIds) {
        OperationLog log = new OperationLog();
        ImportKeyResult r = new ImportKeyResult(
                resultType, log, newKeys, updatedKeys, missingKeys, badKeys, secret, masterKeyIds);
        r.setCanonicalizedKeyRings(new ArrayList<CanonicalizedKeyRing>());
        return r;
    }

    // --- Single result ---

    @Test
    public void singleNewKey_shouldReportOkNewkeys() {
        KeyImportAccumulator acc = new KeyImportAccumulator(1, null);
        acc.accumulateKeyImport(makeResult(
                ImportKeyResult.RESULT_OK_NEWKEYS, 1, 0, 0, 0, 0, new long[]{100L}));

        ImportKeyResult result = acc.getConsolidatedResult();

        assertTrue(result.isOkNew());
        assertEquals(1, result.mNewKeys);
        assertTrue(acc.isImportFinished());
    }

    // --- Multiple mixed results ---

    @Test
    public void multipleMixedResults_shouldAggregateCorrectly() {
        KeyImportAccumulator acc = new KeyImportAccumulator(3, null);

        acc.accumulateKeyImport(makeResult(
                ImportKeyResult.RESULT_OK_NEWKEYS, 1, 0, 0, 0, 0, new long[]{100L}));
        acc.accumulateKeyImport(makeResult(
                ImportKeyResult.RESULT_OK_UPDATED, 0, 1, 0, 0, 0, new long[]{200L}));
        acc.accumulateKeyImport(makeResult(
                ImportKeyResult.RESULT_WITH_ERRORS | OperationResult.RESULT_ERROR,
                0, 0, 0, 1, 0, new long[]{}));

        ImportKeyResult result = acc.getConsolidatedResult();

        assertEquals(1, result.mNewKeys);
        assertEquals(1, result.mUpdatedKeys);
        assertEquals(1, result.mBadKeys);
        assertTrue("should be success (has good keys)", result.success());
        assertTrue("should have WITH_ERRORS", result.isOkWithErrors());
        assertTrue("should have OK_BOTH", result.isOkBoth());
        assertArrayEquals(new long[]{100L, 200L}, result.mImportedMasterKeyIds);
    }

    // --- Null result (cancelled before execution) ---

    @Test
    public void nullResult_shouldCountAsImportedButNotAffectCounters() {
        KeyImportAccumulator acc = new KeyImportAccumulator(2, null);

        acc.accumulateKeyImport(null);
        acc.accumulateKeyImport(makeResult(
                ImportKeyResult.RESULT_OK_NEWKEYS, 1, 0, 0, 0, 0, new long[]{100L}));

        assertTrue(acc.isImportFinished());

        ImportKeyResult result = acc.getConsolidatedResult();
        assertEquals(1, result.mNewKeys);
        assertTrue(result.isOkNew());
    }

    // --- Cancelled result log deduplication ---

    @Test
    public void cancelledResult_shouldSetCancelledBit() {
        KeyImportAccumulator acc = new KeyImportAccumulator(2, null);

        acc.accumulateKeyImport(makeResult(
                ImportKeyResult.RESULT_OK_NEWKEYS | ImportKeyResult.RESULT_CANCELLED,
                1, 0, 0, 0, 0, new long[]{100L}));
        acc.accumulateKeyImport(makeResult(
                ImportKeyResult.RESULT_OK_NEWKEYS,
                1, 0, 0, 0, 0, new long[]{200L}));

        ImportKeyResult result = acc.getConsolidatedResult();

        assertTrue("should have CANCELLED bit", result.cancelled());
        assertEquals(2, result.mNewKeys);
    }

    @Test
    public void multipleCancelledResults_shouldOnlyAddFirstCancelledLog() {
        KeyImportAccumulator acc = new KeyImportAccumulator(2, null);

        // Two cancelled results
        OperationLog log1 = new OperationLog();
        ImportKeyResult r1 = new ImportKeyResult(
                ImportKeyResult.RESULT_CANCELLED, log1,
                0, 0, 0, 0, 0, new long[]{});
        r1.setCanonicalizedKeyRings(new ArrayList<>());

        OperationLog log2 = new OperationLog();
        ImportKeyResult r2 = new ImportKeyResult(
                ImportKeyResult.RESULT_CANCELLED, log2,
                0, 0, 0, 0, 0, new long[]{});
        r2.setCanonicalizedKeyRings(new ArrayList<>());

        acc.accumulateKeyImport(r1);
        acc.accumulateKeyImport(r2);

        assertTrue(acc.isImportFinished());

        ImportKeyResult result = acc.getConsolidatedResult();
        assertTrue("should be cancelled", result.cancelled());
    }

    // --- isImportFinished ---

    @Test
    public void isImportFinished_notAllProcessed_shouldReturnFalse() {
        KeyImportAccumulator acc = new KeyImportAccumulator(3, null);
        acc.accumulateKeyImport(makeResult(
                ImportKeyResult.RESULT_OK_NEWKEYS, 1, 0, 0, 0, 0, new long[]{100L}));

        assertFalse(acc.isImportFinished());
    }

    @Test
    public void isImportFinished_allProcessed_shouldReturnTrue() {
        KeyImportAccumulator acc = new KeyImportAccumulator(1, null);
        acc.accumulateKeyImport(makeResult(
                ImportKeyResult.RESULT_OK_NEWKEYS, 1, 0, 0, 0, 0, new long[]{100L}));

        assertTrue(acc.isImportFinished());
    }

    // --- Empty accumulator ---

    @Test
    public void emptyAccumulator_shouldReturnFailNothing() {
        KeyImportAccumulator acc = new KeyImportAccumulator(0, null);

        ImportKeyResult result = acc.getConsolidatedResult();
        assertEquals(ImportKeyResult.RESULT_FAIL_NOTHING, result.getResult());
    }

    // --- Backward compatibility with KeySyncOperation usage (null progressable) ---

    @Test
    public void nullProgressable_shouldNotCrash() {
        KeyImportAccumulator acc = new KeyImportAccumulator(1, null);
        acc.accumulateKeyImport(makeResult(
                ImportKeyResult.RESULT_OK_NEWKEYS, 1, 0, 0, 0, 0, new long[]{100L}));

        ImportKeyResult result = acc.getConsolidatedResult();
        assertTrue(result.isOkNew());
    }

    // --- Secret key accumulation ---

    @Test
    public void secretKeys_shouldAccumulateSecretCount() {
        KeyImportAccumulator acc = new KeyImportAccumulator(2, null);

        acc.accumulateKeyImport(makeResult(
                ImportKeyResult.RESULT_OK_NEWKEYS, 1, 0, 0, 0, 1, new long[]{100L}));
        acc.accumulateKeyImport(makeResult(
                ImportKeyResult.RESULT_OK_NEWKEYS, 1, 0, 0, 0, 1, new long[]{200L}));

        ImportKeyResult result = acc.getConsolidatedResult();

        assertEquals(2, result.mSecret);
        assertEquals(2, result.mNewKeys);
    }
}
