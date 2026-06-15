/*
 * Copyright (C) 2017 Schurmann & Breitmoser GbR
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

package org.sufficientlysecure.keychain.keysync;


import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;


/**
 * Maps ImportKeyResult to a WorkManager-appropriate outcome.
 * This class is stateless and all methods are static to facilitate testing.
 */
public class SyncResultMapper {

    /**
     * Possible outcomes for a sync operation, mapping to WorkManager Result types:
     * - RETRY: transient failure (e.g., Orbot not running), worker should be retried
     * - FAILURE: permanent failure or cancellation, worker should not be retried
     * - SUCCESS: sync completed (may include partial failures)
     */
    public enum SyncOutcome {
        RETRY,
        FAILURE,
        SUCCESS
    }

    private SyncResultMapper() {
        // Utility class
    }

    /**
     * Determine the outcome of a sync operation based on the import result and worker state.
     *
     * Decision tree:
     * - If result is pending (Orbot required but not running): RETRY
     * - If worker was stopped/cancelled: FAILURE
     * - Otherwise: SUCCESS (even if some keys failed to import)
     *
     * @param result the import result from KeySyncOperation
     * @param isStopped whether the worker was stopped by WorkManager
     * @return the appropriate SyncOutcome
     */
    public static SyncOutcome mapResult(ImportKeyResult result, boolean isStopped) {
        if (result.isPending()) {
            return SyncOutcome.RETRY;
        }
        if (isStopped) {
            return SyncOutcome.FAILURE;
        }
        return SyncOutcome.SUCCESS;
    }

    /**
     * Format a log message describing the sync result.
     *
     * @param result the import result
     * @return a human-readable summary of updated and failed key counts
     */
    public static String formatLogMessage(ImportKeyResult result) {
        return String.format("Keyserver sync completed: Updated: %d, Failed: %d",
                result.mUpdatedKeys, result.mBadKeys);
    }

    /**
     * Check if the result indicates Orbot is required but not running.
     *
     * @param result the import result
     * @return true if the result is pending due to Orbot not being started
     */
    public static boolean isOrbotRequired(ImportKeyResult result) {
        return result.isPending();
    }
}
