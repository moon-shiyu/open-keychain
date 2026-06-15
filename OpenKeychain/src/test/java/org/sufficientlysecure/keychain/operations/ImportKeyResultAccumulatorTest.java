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

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.operations.ImportOperation.KeyImportAccumulator;
import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogType;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;

/**
 * Focused tests for {@link KeyImportAccumulator}, which consolidates the per-keyring
 * {@link ImportKeyResult}s produced by {@link ImportOperation} into a single result. These lock down
 * the count aggregation and the result-code derivation that is shared with the serial import path,
 * including the deliberately-divergent empty+cancelled edge case.
 *
 * <p>The accumulator is pure aggregation logic and does not touch the database; we only construct
 * {@link ImportKeyResult}s and feed them in. Runs under Robolectric to match the rest of the
 * operations test suite and ensure the result/log classes load exactly as in production.
 */
@RunWith(KeychainTestRunner.class)
public class ImportKeyResultAccumulatorTest {

    /** Builds an import result the way the production code does, with a (possibly empty) keyring list set. */
    private static ImportKeyResult importResult(int resultCode, int newKeys, int updatedKeys,
            int missingKeys, int badKeys, int secret, long[] masterKeyIds, OperationLog log) {
        ImportKeyResult result = new ImportKeyResult(
                resultCode, log, newKeys, updatedKeys, missingKeys, badKeys, secret, masterKeyIds);
        // serialKeyRingImport always sets this; the accumulator dereferences it, so mirror production
        result.setCanonicalizedKeyRings(new ArrayList<>());
        return result;
    }

    private static OperationLog emptyLog() {
        return new OperationLog();
    }

    private static OperationLog logWithWarning() {
        OperationLog log = new OperationLog();
        log.add(LogType.MSG_IMPORT, 0, 1);
        log.add(LogType.MSG_IP_UID_CERT_BAD, 1); // LogLevel.WARN
        return log;
    }

    @Test
    public void newKeysOnly_setsOkNew() {
        KeyImportAccumulator accumulator = new KeyImportAccumulator(1, null);
        accumulator.accumulateKeyImport(
                importResult(OperationResult.RESULT_OK, 2, 0, 0, 0, 0, new long[] { 111L, 222L }, emptyLog()));

        ImportKeyResult result = accumulator.getConsolidatedResult();

        Assert.assertTrue("must report new keys", result.isOkNew());
        Assert.assertFalse("must not report updated keys", result.isOkUpdated());
        Assert.assertFalse("must not report errors", result.isOkWithErrors());
        Assert.assertTrue("overall success", result.success());
        Assert.assertEquals(2, result.mNewKeys);
        Assert.assertArrayEquals(new long[] { 111L, 222L }, result.getImportedMasterKeyIds());
    }

    @Test
    public void updatedKeysOnly_setsOkUpdated() {
        KeyImportAccumulator accumulator = new KeyImportAccumulator(1, null);
        accumulator.accumulateKeyImport(
                importResult(OperationResult.RESULT_OK, 0, 1, 0, 0, 0, new long[] { 333L }, emptyLog()));

        ImportKeyResult result = accumulator.getConsolidatedResult();

        Assert.assertTrue("must report updated keys", result.isOkUpdated());
        Assert.assertFalse("must not report new keys", result.isOkNew());
        Assert.assertTrue("overall success", result.success());
        Assert.assertEquals(1, result.mUpdatedKeys);
    }

    @Test
    public void newAndBad_setsWithErrorsButNotOverallError() {
        KeyImportAccumulator accumulator = new KeyImportAccumulator(2, null);
        accumulator.accumulateKeyImport(
                importResult(OperationResult.RESULT_OK, 1, 0, 0, 0, 0, new long[] { 1L }, emptyLog()));
        accumulator.accumulateKeyImport(
                importResult(OperationResult.RESULT_OK, 0, 0, 0, 1, 0, new long[] {}, emptyLog()));

        ImportKeyResult result = accumulator.getConsolidatedResult();

        Assert.assertTrue("partial success still reports new keys", result.isOkNew());
        Assert.assertTrue("must report errors", result.isOkWithErrors());
        Assert.assertTrue("partial success is still overall success", result.success());
        Assert.assertEquals(1, result.mNewKeys);
        Assert.assertEquals(1, result.mBadKeys);
    }

    @Test
    public void badOnly_setsOverallError() {
        KeyImportAccumulator accumulator = new KeyImportAccumulator(1, null);
        accumulator.accumulateKeyImport(
                importResult(OperationResult.RESULT_OK, 0, 0, 0, 2, 0, new long[] {}, emptyLog()));

        ImportKeyResult result = accumulator.getConsolidatedResult();

        Assert.assertTrue("must report errors", result.isOkWithErrors());
        Assert.assertFalse("only-bad import is an overall failure", result.success());
        Assert.assertFalse("not the 'nothing to import' case", result.isFailNothing());
        Assert.assertEquals(2, result.mBadKeys);
    }

    @Test
    public void aggregatesCountsAndMasterKeyIdsAcrossResults() {
        KeyImportAccumulator accumulator = new KeyImportAccumulator(2, null);
        accumulator.accumulateKeyImport(
                importResult(OperationResult.RESULT_OK, 1, 0, 1, 0, 0, new long[] { 10L }, emptyLog()));
        accumulator.accumulateKeyImport(
                importResult(OperationResult.RESULT_OK, 0, 2, 0, 1, 1, new long[] { 20L, 30L }, emptyLog()));

        ImportKeyResult result = accumulator.getConsolidatedResult();

        Assert.assertEquals(1, result.mNewKeys);
        Assert.assertEquals(2, result.mUpdatedKeys);
        Assert.assertEquals(1, result.mMissingKeys);
        Assert.assertEquals(1, result.mBadKeys);
        Assert.assertEquals(1, result.mSecret);
        Assert.assertArrayEquals(new long[] { 10L, 20L, 30L }, result.getImportedMasterKeyIds());
        Assert.assertTrue("both new and updated present", result.isOkBoth());
        Assert.assertTrue("bad key present", result.isOkWithErrors());
        Assert.assertTrue("partial success is overall success", result.success());
    }

    @Test
    public void emptyAndNotCancelled_isFailNothing() {
        KeyImportAccumulator accumulator = new KeyImportAccumulator(1, null);
        accumulator.accumulateKeyImport(
                importResult(OperationResult.RESULT_OK, 0, 0, 0, 0, 0, new long[] {}, emptyLog()));

        ImportKeyResult result = accumulator.getConsolidatedResult();

        Assert.assertTrue("nothing imported -> fail nothing", result.isFailNothing());
        Assert.assertFalse("fail nothing is not success", result.success());
        Assert.assertFalse("no missing keys here", result.isFailMissing());
    }

    @Test
    public void emptyWithMissingKeys_isFailMissing() {
        KeyImportAccumulator accumulator = new KeyImportAccumulator(1, null);
        accumulator.accumulateKeyImport(
                importResult(OperationResult.RESULT_OK, 0, 0, 1, 0, 0, new long[] {}, emptyLog()));

        ImportKeyResult result = accumulator.getConsolidatedResult();

        Assert.assertTrue("nothing imported -> fail nothing", result.isFailNothing());
        Assert.assertTrue("missing keys -> fail missing", result.isFailMissing());
        Assert.assertEquals(1, result.mMissingKeys);
    }

    /**
     * Invariant: unlike the serial import path (which overwrites the result type to FAIL_NOTHING),
     * the accumulator must keep the CANCELLED bit and must NOT report FAIL_NOTHING when an empty
     * import was cancelled.
     */
    @Test
    public void emptyButCancelled_keepsCancelledAndIsNotFailNothing() {
        KeyImportAccumulator accumulator = new KeyImportAccumulator(1, null);
        accumulator.accumulateKeyImport(
                importResult(OperationResult.RESULT_CANCELLED, 0, 0, 0, 0, 0, new long[] {}, emptyLog()));

        ImportKeyResult result = accumulator.getConsolidatedResult();

        Assert.assertTrue("cancelled bit must be preserved", result.cancelled());
        Assert.assertFalse("cancelled empty import is not 'fail nothing'", result.isFailNothing());
        Assert.assertTrue("cancellation alone is not an overall error", result.success());
    }

    @Test
    public void logWithWarning_setsWarningsBit() {
        KeyImportAccumulator accumulator = new KeyImportAccumulator(1, null);
        accumulator.accumulateKeyImport(
                importResult(OperationResult.RESULT_OK, 1, 0, 0, 0, 0, new long[] { 7L }, logWithWarning()));

        ImportKeyResult result = accumulator.getConsolidatedResult();

        Assert.assertTrue("new key still reported", result.isOkNew());
        Assert.assertTrue("warning in log -> warnings bit set",
                (result.getResult() & OperationResult.RESULT_WARNINGS) != 0);
    }

    @Test
    public void nullResult_advancesProgressCountWithoutChangingTallies() {
        KeyImportAccumulator accumulator = new KeyImportAccumulator(2, null);
        accumulator.accumulateKeyImport(
                importResult(OperationResult.RESULT_OK, 1, 0, 0, 0, 0, new long[] { 42L }, emptyLog()));

        Assert.assertFalse("not finished after first of two", accumulator.isImportFinished());

        accumulator.accumulateKeyImport(null); // e.g. a cancelled worker returns null

        Assert.assertTrue("null result still advances the imported count", accumulator.isImportFinished());

        ImportKeyResult result = accumulator.getConsolidatedResult();
        Assert.assertEquals("null result must not change new count", 1, result.mNewKeys);
        Assert.assertEquals("null result must not add bad keys", 0, result.mBadKeys);
        Assert.assertArrayEquals(new long[] { 42L }, result.getImportedMasterKeyIds());
    }
}
