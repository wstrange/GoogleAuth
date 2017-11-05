/*
 * Copyright (c) 2014-2017 Enrico M. Crisostomo
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *   * Neither the name of the author nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.warrenstrange.googleauth;

import java.util.List;

/**
 * A no-op implementation of the <code>#ICredentialRepository</code> interface.
 *
 * @author Enrico M. Crisostomo
 */
public class CredentialRepositoryMock implements ICredentialRepository {
    /**
     * Name of the environment property used by this mock to retrieve the fake
     * secret key returned by <code>#getSecretKey</code>.
     */
    public static final String MOCK_SECRET_KEY_NAME =
            "com.warrenstrange.googleauth.CredentialRepositoryMock.secret.name";

    /**
     * This method returns the value of the system property named
     * <code>#MOCK_SECRET_KEY_NAME</code>.
     *
     * @param userName the user whose private key shall be retrieved.
     * @return the value of the environment property named
     * <code>#MOCK_SECRET_KEY_NAME</code>.
     */
    @Override
    public String getSecretKey(String userName) {
        final String key = System.getProperty(MOCK_SECRET_KEY_NAME);

        System.out.println(
                String.format(
                        "getSecretKey invoked with user name %s returning %s.",
                        userName,
                        key));

        return key;
    }

    /**
     * This method does nothing.
     *
     * @param userName the user whose data shall be saved.
     * @param secretKey the generated key.
     * @param validationCode the validation code.
     * @param scratchCodes the list of scratch codes.
     */
    @Override
    public void saveUserCredentials(
            String userName,
            String secretKey,
            int validationCode,
            List<Integer> scratchCodes) {
        System.out.println("saveUserCredentials invoked with user name " + userName);
    }
}
