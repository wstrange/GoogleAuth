/*
 * Copyright (c) 2014, Enrico Maria Crisostomo
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
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

/**
 * Google Authenticator library interface.
 */
@SuppressWarnings("UnusedDeclaration")
public interface IGoogleAuthenticator {
    /**
     * This method generates a new set of credentials including:
     * <ol>
     * <li>Secret key.</li>
     * <li>Validation code.</li>
     * <li>A list of scratch codes.</li>
     * </ol>
     * <p/>
     * <p/>
     * The user must register this secret on their device.
     *
     * @return secret key
     */
    GoogleAuthenticatorKey createCredentials();

    /**
     * This method generates a new set of credentials invoking the
     * <code>#createCredentials</code> method with no arguments. The generated
     * credentials are then saved using the configured
     * <code>#ICredentialRepository</code> service.
     * <p/>
     * The user must register this secret on their device.
     *
     * @return secret key
     */
    GoogleAuthenticatorKey createCredentials(String userName);

    /**
     * Get the default window size used by this instance when an explicit value
     * is not specified.
     *
     * @return the current window size.
     */
    int getWindowSize();

    /**
     * Set the default window size used by this instance when an explicit value
     * is not specified. This is an integer value representing the number of 30
     * second windows that are checked during the validation process, to account
     * for differences between the server and the client clocks.
     * The bigger the window, the more tolerant the library code is about clock
     * skews.
     *
     * @param s window size - must be >=1 and <=17.  Other values are ignored
     */
    void setWindowSize(int s);

    /**
     * Checks a verification code against a secret key using the current time.
     * The algorithm also checks in a time window whose size determined by the
     * <code>windowSize</code> property of this class.
     * <p/>
     * The default value of 30 seconds recommended by RFC 6238 is used for the
     * interval size.
     *
     * @param secret           the Base32 encoded secret key.
     * @param verificationCode the verification code.
     * @return <code>true</code> if the validation code is valid,
     * <code>false</code> otherwise.
     * @throws GoogleAuthenticatorException if a failure occurs during the
     *                                      calculation of the validation code.
     *                                      The only failures that should occur
     *                                      are related with the cryptographic
     *                                      functions provided by the JCE.
     * @see #getWindowSize()
     */
    boolean authorize(String secret, int verificationCode)
            throws GoogleAuthenticatorException;

    /**
     * This method validates a verification code of the specified user whose
     * private key is retrieved from the configured credential repository. This
     * method delegates the validation to the <code>#authorize</code> method.
     *
     * @param userName         The user whose verification code is to be
     *                         validated.
     * @param verificationCode The validation code.
     * @return <code>true</code> if the validation code is valid,
     * <code>false</code> otherwise.
     * @throws GoogleAuthenticatorException
     * @see #authorize(String, int)
     */
    boolean authorizeUser(String userName, int verificationCode)
            throws GoogleAuthenticatorException;

    /**
     * This method validates a verification code of the specified user whose
     * private key is retrieved from the configured credential repository. This
     * method delegates the validation to the <code>#authorize</code> method.
     *
     * @param userName         The user whose verification code is to be
     *                         validated.
     * @param verificationCode The validation code.
     * @param window           the window size to use during the validation
     *                         process.
     * @return <code>true</code> if the validation code is valid,
     * <code>false</code> otherwise.
     * @throws GoogleAuthenticatorException
     * @see GoogleAuthenticator#MAX_WINDOW
     * @see #authorize(String, int, int)
     */
    @SuppressWarnings("UnusedDeclaration")
    boolean authorizeUser(
            String userName,
            int verificationCode,
            int window)
            throws GoogleAuthenticatorException;

    /**
     * Checks a verification code against a secret key using the current time.
     * The algorithm also checks in a time window whose size is fixed to a value
     * of [-(window - 1)/2, +(window - 1)/2] time intervals. The maximum size of
     * the window is specified by the <code>MAX_WINDOW</code> constant and
     * cannot be overridden.
     * <p/>
     * The default value of 30 seconds recommended by RFC 6238 is used for the
     * interval size.
     *
     * @param secret           the Base32 encoded secret key.
     * @param verificationCode the verification code.
     * @param window           the window size to use during the validation
     *                         process.
     * @return <code>true</code> if the validation code is valid,
     * <code>false</code> otherwise.
     * @throws GoogleAuthenticatorException if a failure occurs during the
     *                                      calculation of the validation code.
     *                                      The only failures that should occur
     *                                      are related with the cryptographic
     *                                      functions provided by the JCE.
     * @see GoogleAuthenticator#MAX_WINDOW
     */
    boolean authorize(
            String secret,
            int verificationCode,
            int window)
            throws GoogleAuthenticatorException;
}
