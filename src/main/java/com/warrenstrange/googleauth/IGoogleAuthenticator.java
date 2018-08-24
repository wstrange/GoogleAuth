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

/**
 * Google Authenticator library interface.
 */
@SuppressWarnings("UnusedDeclaration")
public interface IGoogleAuthenticator
{
    /**
     * This method generates a new set of credentials including:
     * <ol>
     * <li>Secret key.</li>
     * <li>Validation code.</li>
     * <li>A list of scratch codes.</li>
     * </ol>
     * <p/>
     * The user must register this secret on their device.
     *
     * @return secret key
     */
    GoogleAuthenticatorKey createCredentials();

    /**
     * This method generates the current TOTP password.
     *
     * @param secret the encoded secret key.
     * @return the current TOTP password.
     * @since 1.1.0
     */
    int getTotpPassword(String secret);

    /**
     * This method generates the TOTP password at the specified time.
     *
     * @param secret The encoded secret key.
     * @param time   The time to use to calculate the password.
     * @return the TOTP password at the specified time.
     * @since 1.1.0
     */
    int getTotpPassword(String secret, long time);

    /**
     * Checks a verification code against a secret key using the current time.
     *
     * @param secret           the encoded secret key.
     * @param verificationCode the verification code.
     * @return <code>true</code> if the validation code is valid,
     * <code>false</code> otherwise.
     * @throws GoogleAuthenticatorException if a failure occurs during the
     *                                      calculation of the validation code.
     *                                      The only failures that should occur
     *                                      are related with the cryptographic
     *                                      functions provided by the JCE.
     * @see #authorize(String, int, long)
     */
    boolean authorize(String secret, int verificationCode)
            throws GoogleAuthenticatorException;

    /**
     * Checks a verification code against a secret key using the specified time.
     * The algorithm also checks in a time window whose size determined by the
     * {@code windowSize} property of this class.
     * <p/>
     * The default value of 30 seconds recommended by RFC 6238 is used for the
     * interval size.
     *
     * @param secret           The encoded secret key.
     * @param verificationCode The verification code.
     * @param time             The time to use to calculate the TOTP password..
     * @return {@code true} if the validation code is valid, {@code false}
     * otherwise.
     * @throws GoogleAuthenticatorException if a failure occurs during the
     *                                      calculation of the validation code.
     *                                      The only failures that should occur
     *                                      are related with the cryptographic
     *                                      functions provided by the JCE.
     * @since 0.6.0
     */
    boolean authorize(String secret, int verificationCode, long time)
            throws GoogleAuthenticatorException;
}
