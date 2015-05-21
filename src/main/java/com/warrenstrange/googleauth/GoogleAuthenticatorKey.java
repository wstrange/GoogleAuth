/*
 * Copyright (c) 2014-2015 Enrico M. Crisostomo
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

import java.util.ArrayList;
import java.util.List;

/**
 * This class is a JavaBean used by the GoogleAuthenticator library to represent
 * a secret key.
 * <p/>
 * This class is immutable.
 * <p/>
 * Instance of this class should only be constructed by the GoogleAuthenticator
 * library.
 *
 * @author Enrico M. Crisostomo
 * @version 1.0
 * @see GoogleAuthenticator
 * @since 1.0
 */
public final class GoogleAuthenticatorKey {

    /**
     * The format string to generate the URL of a Google-provided QR bar code.
     *
     * @deprecated Use GoogleAuthenticatorQRGenerator instead.
     */
    private static final String QR_FORMAT =
            "https://chart.googleapis.com/chart?chs=200x200&chld=M%%7C0&cht=qr&"
                    + "chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s";

    /**
     * The secret key in Base32 encoding.
     */
    private final String key;

    /**
     * The verification code at time = 0 (the UNIX epoch).
     */
    private final int verificationCode;

    /**
     * The list of scratch codes.
     */
    private final List<Integer> scratchCodes;

    /**
     * The constructor with package visibility.
     *
     * @param secretKey    the secret key in Base32 encoding.
     * @param code         the verification code at time = 0 (the UNIX epoch).
     * @param scratchCodes the list of scratch codes.
     */
    /* package */ GoogleAuthenticatorKey(
            String secretKey, int code,
            List<Integer> scratchCodes) {
        key = secretKey;
        verificationCode = code;
        this.scratchCodes = new ArrayList<>(scratchCodes);
    }

    /**
     * Returns the URL of a Google-provided QR barcode to be loaded into the
     * Google Authenticator application. The user scans this bar code with the
     * application on their smart phones or manually enter the secret manually.
     *
     * @param user   the user to assign the secret key to.
     * @param host   the host to assign the secret key to.
     * @param secret the secret key in Base32 encoding.
     * @return the URL of a Google-provided QR barcode to be loaded into the
     * Google Authenticator application.
     * @deprecated Use GoogleAuthenticatorQRGenerator##getOtpAuthURL instead.
     */
    @SuppressWarnings("deprecation, unused")
    public static String getQRBarcodeURL(String user, String host, String secret) {
        return String.format(QR_FORMAT, user, host, secret);
    }

    /**
     * Get the list of scratch codes.
     *
     * @return the list of scratch codes.
     */
    public List<Integer> getScratchCodes() {
        return scratchCodes;
    }

    /**
     * Returns the secret key in Base32 encoding.
     *
     * @return the secret key in Base32 encoding.
     */
    public String getKey() {
        return key;
    }

    /**
     * Returns the verification code at time = 0 (the UNIX epoch).
     *
     * @return the verificationCode at time = 0 (the UNIX epoch).
     */
    public int getVerificationCode() {
        return verificationCode;
    }
}
