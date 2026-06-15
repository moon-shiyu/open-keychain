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

package org.sufficientlysecure.keychain.remote;


import android.app.PendingIntent;
import android.content.Intent;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.openintents.openpgp.OpenPgpError;
import org.openintents.openpgp.util.OpenPgpApi;
import org.sufficientlysecure.keychain.KeychainTestRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;


/**
 * Verifies that {@link OpenPgpApiResult} emits exactly the result-Intent extras that the inline
 * OpenPGP result builds used to emit (the sign/encrypt/decrypt/verify handlers all funnel through
 * these three factories), so wire compatibility is preserved.
 */
@RunWith(KeychainTestRunner.class)
public class OpenPgpApiResultTest {

    @Test
    public void success_setsSuccessResultCodeOnly() {
        Intent result = OpenPgpApiResult.success();

        assertEquals(OpenPgpApi.RESULT_CODE_SUCCESS,
                result.getIntExtra(OpenPgpApi.RESULT_CODE, -1));
        assertFalse(result.hasExtra(OpenPgpApi.RESULT_INTENT));
        assertFalse(result.hasExtra(OpenPgpApi.RESULT_ERROR));
    }

    @Test
    public void userInteractionRequired_setsResultCodeAndIntent() {
        PendingIntent pendingIntent = mock(PendingIntent.class);

        Intent result = OpenPgpApiResult.userInteractionRequired(pendingIntent);

        assertEquals(OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED,
                result.getIntExtra(OpenPgpApi.RESULT_CODE, -1));
        assertSame(pendingIntent, result.getParcelableExtra(OpenPgpApi.RESULT_INTENT));
    }

    @Test
    public void error_setsResultCodeAndError() {
        Intent result = OpenPgpApiResult.error(OpenPgpError.GENERIC_ERROR, "boom");

        assertEquals(OpenPgpApi.RESULT_CODE_ERROR,
                result.getIntExtra(OpenPgpApi.RESULT_CODE, -1));

        OpenPgpError error = result.getParcelableExtra(OpenPgpApi.RESULT_ERROR);
        assertEquals(OpenPgpError.GENERIC_ERROR, error.getErrorId());
        assertEquals("boom", error.getMessage());
    }
}
