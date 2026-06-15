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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.sufficientlysecure.keychain.operations.importOperation.ImportResultBuilder;
import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogType;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.pgp.CanonicalizedKeyRing;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


/**
 * Pure unit tests for {@link ImportResultBuilder} — no Android/Robolectric
 * dependency. Verifies counter accumulation and result-type bitmask
 * computation for both the direct-recording (serial) and accumulation
 * (multi-threaded) paths.
 */
@RunWith(JUnit4.class)
public class ImportResultBuilderTest {

    private OperationLog log;

    @Before
    public void setUp() {
        log = new OperationLog();
    }

    // --- Empty builder ---

    @Test
    public void emptyBuilder_shouldReturnFailNothing() {
        ImportResultBuilder builder = new ImportResultBuilder(true);

        ImportKeyResult result = builder.build(0, log);

        assertEquals("result type should be FAIL_NOTHING",
                ImportKeyResult.RESULT_FAIL_NOTHING, result.getResult());
        assertEquals(0, result.mNewKeys);
        assertEquals(0, result.mUpdatedKeys);
        assertEquals(0, result.mBadKeys);
        assertEquals(0, result.mMissingKeys);
        assertEquals(0, result.mSecret);
        assertEquals(0, result.mImportedMasterKeyIds.length);
    }

    // --- Only new keys ---

    @Test
    public void onlyNewKeys_shouldSetOkNewkeys() {
        ImportResultBuilder builder = new ImportResultBuilder(true);
        builder.recordNewKey(100L, false);
        builder.recordNewKey(200L, false);

        ImportKeyResult result = builder.build(0, log);

        assertTrue("should have OK_NEWKEYS", result.isOkNew());
        assertFalse("should not have OK_UPDATED", result.isOkUpdated());
        assertEquals(2, result.mNewKeys);
        assertEquals(0, result.mUpdatedKeys);
        assertEquals(0, result.mSecret);
        assertArrayEquals(new long[]{100L, 200L}, result.mImportedMasterKeyIds);
    }

    @Test
    public void newSecretKey_shouldCountSecretAndTrackId() {
        ImportResultBuilder builder = new ImportResultBuilder(true);
        builder.recordNewKey(100L, true);

        ImportKeyResult result = builder.build(0, log);

        assertEquals(1, result.mNewKeys);
        assertEquals(1, result.mSecret);
        assertArrayEquals(new long[]{100L}, result.mImportedMasterKeyIds);
        assertEquals(1, builder.getSecretMasterKeyIds().size());
        assertEquals(Long.valueOf(100L), builder.getSecretMasterKeyIds().get(0));
    }

    // --- Only updated keys ---

    @Test
    public void onlyUpdatedKeys_shouldSetOkUpdated() {
        ImportResultBuilder builder = new ImportResultBuilder(true);
        builder.recordUpdatedKey(100L);

        ImportKeyResult result = builder.build(0, log);

        assertTrue("should have OK_UPDATED", result.isOkUpdated());
        assertFalse("should not have OK_NEWKEYS", result.isOkNew());
        assertEquals(0, result.mNewKeys);
        assertEquals(1, result.mUpdatedKeys);
        assertArrayEquals(new long[]{100L}, result.mImportedMasterKeyIds);
    }

    // --- New + updated ---

    @Test
    public void newAndUpdatedKeys_shouldSetOkBoth() {
        ImportResultBuilder builder = new ImportResultBuilder(true);
        builder.recordNewKey(100L, false);
        builder.recordUpdatedKey(200L);

        ImportKeyResult result = builder.build(0, log);

        assertTrue("should have OK_BOTH", result.isOkBoth());
        assertEquals(1, result.mNewKeys);
        assertEquals(1, result.mUpdatedKeys);
        assertArrayEquals(new long[]{100L, 200L}, result.mImportedMasterKeyIds);
    }

    // --- Only bad keys ---

    @Test
    public void onlyBadKeys_shouldSetErrorAndWithErrors() {
        ImportResultBuilder builder = new ImportResultBuilder(true);
        builder.recordBadKey();

        ImportKeyResult result = builder.build(0, log);

        assertTrue("should have RESULT_WITH_ERRORS", result.isOkWithErrors());
        assertFalse("should not have success", result.success());
        assertEquals(1, result.mBadKeys);
        assertEquals(0, result.mNewKeys);
        assertEquals(0, result.mUpdatedKeys);
    }

    // --- Good + bad (partial success) ---

    @Test
    public void goodAndBadKeys_shouldSetWithErrorsButStillSuccess() {
        ImportResultBuilder builder = new ImportResultBuilder(true);
        builder.recordNewKey(100L, false);
        builder.recordBadKey();

        ImportKeyResult result = builder.build(0, log);

        assertTrue("should be success (no RESULT_ERROR bit)", result.success());
        assertTrue("should have RESULT_WITH_ERRORS", result.isOkWithErrors());
        assertTrue("should have OK_NEWKEYS", result.isOkNew());
        assertEquals(1, result.mNewKeys);
        assertEquals(1, result.mBadKeys);
    }

    // --- Missing keys ---

    @Test
    public void missingKeys_shouldCountButNotFailAlone() {
        ImportResultBuilder builder = new ImportResultBuilder(true);
        builder.recordMissingKey(null, null);
        builder.recordMissingKey(null, null);

        ImportKeyResult result = builder.build(0, log);

        // Missing keys alone: badKeys=0, newKeys=0, updatedKeys=0 → FAIL_NOTHING
        assertEquals(ImportKeyResult.RESULT_FAIL_NOTHING, result.getResult());
        assertEquals(2, result.mMissingKeys);
    }

    @Test
    public void missingAndGoodKeys_shouldNotAffectSuccess() {
        ImportResultBuilder builder = new ImportResultBuilder(true);
        builder.recordNewKey(100L, false);
        builder.recordMissingKey(null, null);

        ImportKeyResult result = builder.build(0, log);

        assertTrue("should have OK_NEWKEYS", result.isOkNew());
        assertEquals(1, result.mNewKeys);
        assertEquals(1, result.mMissingKeys);
    }

    // --- RESULT_CANCELLED ---

    @Test
    public void cancelledWithKeys_shouldPreserveCancelledBit() {
        ImportResultBuilder builder = new ImportResultBuilder(true);
        builder.recordNewKey(100L, false);

        ImportKeyResult result = builder.build(ImportKeyResult.RESULT_CANCELLED, log);

        assertTrue("should have CANCELLED", result.cancelled());
        assertTrue("should have OK_NEWKEYS", result.isOkNew());
    }

    @Test
    public void cancelledWithNoKeys_shouldPreserveCancelledBit() {
        ImportResultBuilder builder = new ImportResultBuilder(true);

        ImportKeyResult result = builder.build(ImportKeyResult.RESULT_CANCELLED, log);

        // With the unified builder, cancelled bit is preserved even when all counters are zero.
        // (The serial path caller handles the legacy overwrite-to-FAIL_NOTHING if needed.)
        assertTrue("should have CANCELLED", result.cancelled());
    }

    // --- Warnings in log ---

    @Test
    public void warningsInLog_shouldSetWarningsBit() {
        ImportResultBuilder builder = new ImportResultBuilder(true);
        builder.recordNewKey(100L, false);
        // Add a WARN-level log entry
        log.add(LogType.MSG_IMPORT_FETCH_ERROR_KEYSERVER, 2, "test warning");

        ImportKeyResult result = builder.build(0, log);

        assertTrue("should have RESULT_WARNINGS",
                (result.getResult() & OperationResult.RESULT_WARNINGS) != 0);
    }

    // --- Summary log entries ---

    @Test
    public void serialPath_successLog_shouldAddImportSuccess() {
        ImportResultBuilder builder = new ImportResultBuilder(true);
        builder.recordNewKey(100L, false);

        builder.addFinalLog(log, false);

        // Verify log contains MSG_IMPORT_SUCCESS
        boolean found = false;
        for (OperationResult.LogEntryParcel entry : log) {
            if (entry.mType == LogType.MSG_IMPORT_SUCCESS) {
                found = true;
                break;
            }
        }
        assertTrue("should contain MSG_IMPORT_SUCCESS", found);
    }

    @Test
    public void serialPath_partialLog_shouldAddImportPartial() {
        ImportResultBuilder builder = new ImportResultBuilder(true);
        builder.recordNewKey(100L, false);
        builder.recordBadKey();

        builder.addFinalLog(log, false);

        boolean found = false;
        for (OperationResult.LogEntryParcel entry : log) {
            if (entry.mType == LogType.MSG_IMPORT_PARTIAL) {
                found = true;
                break;
            }
        }
        assertTrue("should contain MSG_IMPORT_PARTIAL", found);
    }

    @Test
    public void serialPath_errorLog_shouldAddImportError() {
        ImportResultBuilder builder = new ImportResultBuilder(true);
        builder.recordBadKey();

        builder.addFinalLog(log, false);

        boolean found = false;
        for (OperationResult.LogEntryParcel entry : log) {
            if (entry.mType == LogType.MSG_IMPORT_ERROR) {
                found = true;
                break;
            }
        }
        assertTrue("should contain MSG_IMPORT_ERROR", found);
    }

    @Test
    public void serialPath_cancelled_shouldNotAddSummaryLog() {
        ImportResultBuilder builder = new ImportResultBuilder(true);
        builder.recordNewKey(100L, false);

        builder.addFinalLog(log, true);

        boolean foundSuccess = false, foundPartial = false, foundError = false;
        for (OperationResult.LogEntryParcel entry : log) {
            if (entry.mType == LogType.MSG_IMPORT_SUCCESS) foundSuccess = true;
            if (entry.mType == LogType.MSG_IMPORT_PARTIAL) foundPartial = true;
            if (entry.mType == LogType.MSG_IMPORT_ERROR) foundError = true;
        }
        assertFalse("should not contain MSG_IMPORT_SUCCESS when cancelled", foundSuccess);
        assertFalse("should not contain MSG_IMPORT_PARTIAL when cancelled", foundPartial);
        assertFalse("should not contain MSG_IMPORT_ERROR when cancelled", foundError);
    }

    @Test
    public void accumulatorPath_shouldNotAddSummaryLog() {
        ImportResultBuilder builder = new ImportResultBuilder(false);
        builder.recordNewKey(100L, false);

        builder.addFinalLog(log, false);

        boolean found = false;
        for (OperationResult.LogEntryParcel entry : log) {
            if (entry.mType == LogType.MSG_IMPORT_SUCCESS
                    || entry.mType == LogType.MSG_IMPORT_PARTIAL
                    || entry.mType == LogType.MSG_IMPORT_ERROR) {
                found = true;
                break;
            }
        }
        assertFalse("accumulator should not add summary log", found);
    }

    // --- Accumulation mode ---

    @Test
    public void accumulateFrom_singleResult() {
        ImportResultBuilder builder = new ImportResultBuilder(false);

        OperationLog subLog = new OperationLog();
        ImportKeyResult subResult = new ImportKeyResult(
                ImportKeyResult.RESULT_OK_NEWKEYS, subLog,
                1, 0, 0, 0, 0, new long[]{100L});
        subResult.setCanonicalizedKeyRings(new ArrayList<CanonicalizedKeyRing>());

        builder.accumulateFrom(subResult);
        ImportKeyResult result = builder.build(0, log);

        assertEquals(1, result.mNewKeys);
        assertArrayEquals(new long[]{100L}, result.mImportedMasterKeyIds);
    }

    @Test
    public void accumulateFrom_multipleMixedResults() {
        ImportResultBuilder builder = new ImportResultBuilder(false);

        // Result 1: 1 new key
        OperationLog log1 = new OperationLog();
        ImportKeyResult r1 = new ImportKeyResult(
                ImportKeyResult.RESULT_OK_NEWKEYS, log1,
                1, 0, 0, 0, 0, new long[]{100L});
        r1.setCanonicalizedKeyRings(new ArrayList<>());

        // Result 2: 1 updated key
        OperationLog log2 = new OperationLog();
        ImportKeyResult r2 = new ImportKeyResult(
                ImportKeyResult.RESULT_OK_UPDATED, log2,
                0, 1, 0, 0, 0, new long[]{200L});
        r2.setCanonicalizedKeyRings(new ArrayList<>());

        // Result 3: 1 bad key
        OperationLog log3 = new OperationLog();
        ImportKeyResult r3 = new ImportKeyResult(
                ImportKeyResult.RESULT_WITH_ERRORS | OperationResult.RESULT_ERROR, log3,
                0, 0, 0, 1, 0, new long[]{});
        r3.setCanonicalizedKeyRings(new ArrayList<>());

        // Result 4: 1 secret key
        OperationLog log4 = new OperationLog();
        ImportKeyResult r4 = new ImportKeyResult(
                ImportKeyResult.RESULT_OK_NEWKEYS, log4,
                1, 0, 0, 0, 1, new long[]{300L});
        r4.setCanonicalizedKeyRings(new ArrayList<>());

        builder.accumulateFrom(r1);
        builder.accumulateFrom(r2);
        builder.accumulateFrom(r3);
        builder.accumulateFrom(r4);

        ImportKeyResult result = builder.build(0, log);

        assertEquals(2, result.mNewKeys);
        assertEquals(1, result.mUpdatedKeys);
        assertEquals(1, result.mBadKeys);
        assertEquals(1, result.mSecret);
        assertTrue("should have OK_BOTH", result.isOkBoth());
        assertTrue("should have WITH_ERRORS", result.isOkWithErrors());
        assertTrue("should still be success", result.success());
        assertArrayEquals(new long[]{100L, 200L, 300L}, result.mImportedMasterKeyIds);
    }

    @Test
    public void accumulateFrom_withNullCanonicalizedRings_shouldNotCrash() {
        ImportResultBuilder builder = new ImportResultBuilder(false);

        OperationLog subLog = new OperationLog();
        ImportKeyResult subResult = new ImportKeyResult(
                ImportKeyResult.RESULT_OK_NEWKEYS, subLog,
                1, 0, 0, 0, 0, new long[]{100L});
        // mCanonicalizedKeyRings is null by default (not set)

        builder.accumulateFrom(subResult);
        ImportKeyResult result = builder.build(0, log);

        assertEquals(1, result.mNewKeys);
        assertNotNull(result.mCanonicalizedKeyRings);
    }

    // --- Import start log ---

    @Test
    public void addImportStartLog_shouldAddMsgImport() {
        ImportResultBuilder builder = new ImportResultBuilder(true);

        builder.addImportStartLog(log, 5);

        boolean found = false;
        for (OperationResult.LogEntryParcel entry : log) {
            if (entry.mType == LogType.MSG_IMPORT) {
                found = true;
                break;
            }
        }
        assertTrue("should contain MSG_IMPORT", found);
    }

    // --- hasAnyGoodKeys ---

    @Test
    public void hasAnyGoodKeys_empty_shouldReturnFalse() {
        ImportResultBuilder builder = new ImportResultBuilder(true);
        assertFalse(builder.hasAnyGoodKeys());
    }

    @Test
    public void hasAnyGoodKeys_onlyBad_shouldReturnFalse() {
        ImportResultBuilder builder = new ImportResultBuilder(true);
        builder.recordBadKey();
        assertFalse(builder.hasAnyGoodKeys());
    }

    @Test
    public void hasAnyGoodKeys_withNewKey_shouldReturnTrue() {
        ImportResultBuilder builder = new ImportResultBuilder(true);
        builder.recordNewKey(100L, false);
        assertTrue(builder.hasAnyGoodKeys());
    }
}
