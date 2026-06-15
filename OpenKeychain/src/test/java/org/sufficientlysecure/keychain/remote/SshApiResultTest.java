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
import org.openintents.ssh.authentication.SshAuthenticationApi;
import org.openintents.ssh.authentication.SshAuthenticationApiError;
import org.sufficientlysecure.keychain.KeychainTestRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;


/**
 * Verifies that {@link SshApiResult} emits exactly the result-Intent extras that the inline SSH
 * authentication result builds used to emit (the public-key and signing handlers funnel error and
 * user-interaction results through these factories), so wire compatibility is preserved.
 */
@RunWith(KeychainTestRunner.class)
public class SshApiResultTest {

    @Test
    public void error_setsResultCodeAndError() {
        Intent result = SshApiResult.error(SshAuthenticationApiError.NO_KEY_ID, "no key");

        assertEquals(SshAuthenticationApi.RESULT_CODE_ERROR,
                result.getIntExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, -1));

        SshAuthenticationApiError error =
                result.getParcelableExtra(SshAuthenticationApi.EXTRA_ERROR);
        assertEquals(SshAuthenticationApiError.NO_KEY_ID, error.getError());
        assertEquals("no key", error.getMessage());
    }

    @Test
    public void userInteractionRequired_setsResultCodeAndPendingIntent() {
        PendingIntent pendingIntent = mock(PendingIntent.class);

        Intent result = SshApiResult.userInteractionRequired(pendingIntent);

        assertEquals(SshAuthenticationApi.RESULT_CODE_USER_INTERACTION_REQUIRED,
                result.getIntExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, -1));
        assertSame(pendingIntent,
                result.getParcelableExtra(SshAuthenticationApi.EXTRA_PENDING_INTENT));
    }
}
