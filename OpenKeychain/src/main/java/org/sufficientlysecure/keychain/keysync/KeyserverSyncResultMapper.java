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

package org.sufficientlysecure.keychain.keysync;


import androidx.annotation.NonNull;
import androidx.work.ListenableWorker.Result;

import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;


/**
 * Maps the {@link ImportKeyResult} produced by a keyserver sync onto a WorkManager
 * {@link Result}. This logic used to live inline in {@code KeyserverSyncWorker}; it is extracted
 * here so the (Android-free) decision can be unit tested without instantiating a Worker.
 *
 * <p>The classification intentionally preserves the historical precedence and semantics:
 * <ul>
 *     <li>a <em>pending</em> result (Orbot required but not running) takes precedence over
 *         everything else and results in a {@link Result#retry()} – even if the worker has been
 *         stopped in the meantime;</li>
 *     <li>otherwise, if the worker was stopped/cancelled the run is reported as
 *         {@link Result#failure()};</li>
 *     <li>otherwise the run is a {@link Result#success()}. Note this includes the case where the
 *         import completed with per-key errors (bad keys / keyserver lookup failures): those are
 *         logged but must <em>not</em> fail the WorkManager job, to avoid pointless retries of a
 *         periodic best-effort refresh.</li>
 * </ul>
 */
final class KeyserverSyncResultMapper {

    private KeyserverSyncResultMapper() {
    }

    enum SyncDecision {
        RETRY,
        CANCELLED,
        SUCCESS
    }

    @NonNull
    static SyncDecision classify(@NonNull ImportKeyResult result, boolean stopped) {
        if (result.isPending()) {
            return SyncDecision.RETRY;
        } else if (stopped) {
            return SyncDecision.CANCELLED;
        } else {
            return SyncDecision.SUCCESS;
        }
    }

    @NonNull
    static Result toWorkerResult(@NonNull SyncDecision decision) {
        switch (decision) {
            case RETRY:
                return Result.retry();
            case CANCELLED:
                return Result.failure();
            case SUCCESS:
            default:
                return Result.success();
        }
    }
}
