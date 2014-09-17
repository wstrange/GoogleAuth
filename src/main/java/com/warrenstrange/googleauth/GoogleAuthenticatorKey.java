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

import javax.ws.rs.core.UriBuilder;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
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
     * @deprecated Use GoogleAuthenticatorKey##TOTP_URI_FORMAT
     */
    private static final String QR_FORMAT =
            "https://chart.googleapis.com/chart?chs=200x200&chld=M%%7C0&cht=qr&"
                    + "chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s";

    /**
     * The format string to generate the Google Chart HTTP API call.
     */
    private static final String TOTP_URI_FORMAT =
            "https://chart.googleapis.com/chart?chs=200x200&chld=M%%7C0&cht=qr&"
                    + "chl=%s";

    /**
     * The format string to generate the basic otpauth TOTP URI.
     *
     * @see <a href="https://code.google.com/p/google-authenticator/wiki/KeyUriFormat">Google Authenticator - KeyUriFormat</a>
     */
    private static final String OTP_AUTH_TOTP_URI_BASE = "otpauth://totp/%s?secret=%s";

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
     * This method wraps the invocation of <code>URLEncoder##encode</code>
     * method using the "UTF-8" encoding.  This call also wraps the
     * <code>UnsupportedEncodingException</code> thrown by
     * <code>URLEncoder##encode</code> into a <code>RuntimeException</code>.
     * Such an exception should never be thrown.
     *
     * @param s The string to URL-encode.
     * @return the URL-encoded string.
     */
    private static String internalURLEncode(String s) {
        try {
            return URLEncoder.encode(s, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding is not supported by URLEncoder.", e);
        }
    }

    /**
     * The label is used to identify which account a key is associated with.
     * It contains an account name, which is a URI-encoded string, optionally
     * prefixed by an issuer string identifying the provider or service managing
     * that account.  This issuer prefix can be used to prevent collisions
     * between different accounts with different providers that might be
     * identified using the same account name, e.g. the user's email address.
     * The issuer prefix and account name should be separated by a literal or
     * url-encoded colon, and optional spaces may precede the account name.
     * Neither issuer nor account name may themselves contain a colon.
     * Represented in ABNF according to RFC 5234:
     * <p/>
     * label = accountname / issuer (“:” / “%3A”) *”%20” accountname
     *
     * @see <a href="https://code.google.com/p/google-authenticator/wiki/KeyUriFormat">Google Authenticator - KeyUriFormat</a>
     */
    private static String formatLabel(String issuer, String accountName) {
        if (accountName == null || accountName.trim().length() == 0) {
            throw new IllegalArgumentException("Account name must not be empty.");
        }

        StringBuilder sb = new StringBuilder();

        if (issuer != null) {
            if (issuer.contains(":")) {
                throw new IllegalArgumentException("Issuer cannot contain the \':\' character.");
            }

            // Using UriBuilder to URI-encode the strings (RFC 3986)
            sb.append(UriBuilder.fromPath(issuer).build().toString());
            sb.append(":");
        }

        sb.append(UriBuilder.fromPath(accountName).build().toString());

        return sb.toString();
    }

    private static String formatIssuerParameter(String issuer) {
        if (issuer != null) {
            if (issuer.contains(":")) {
                throw new IllegalArgumentException("Issuer cannot contain the \':\' character.");
            }

            return String.format("&issuer=%s", internalURLEncode(issuer));
        }

        return "";
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
     * @deprecated Use GoogleAuthenticatorKey##getOtpAuthURL instead.
     */
    @SuppressWarnings("deprecation, unused")
    public static String getQRBarcodeURL(String user, String host, String secret) {
        return String.format(QR_FORMAT, user, host, secret);
    }

    /**
     * Returns the URL of a Google Chart API call to generate a QR barcode to
     * be loaded into the Google Authenticator application. The user scans this
     * bar code with the application on their smart phones or manually enter the
     * secret manually.
     * <p/>
     * The current implementation supports the following features:
     * <ul>
     * <li>Label, made up of an optional issuer and an account name.</li>
     * <li>Secret parameter.</li>
     * <li>Issuer parameter.</li>
     * </ul>
     *
     * @param issuer      The issuer name. This parameter cannot contain the colon
     *                    (:) character. This parameter can be null.
     * @param accountName The account name. This parameter shall not be null.
     * @param secret      The secret. This parameter shall not be null.
     * @return the Google Chart API call URL to generate a QR code containing
     * the provided information.
     * @see <a href="https://code.google.com/p/google-authenticator/wiki/KeyUriFormat">Google Authenticator - KeyUriFormat</a>
     */
    public static String getOtpAuthURL(String issuer, String accountName, Object secret) {

        return String.format(
                TOTP_URI_FORMAT,
                internalURLEncode(
                        String.format(
                                OTP_AUTH_TOTP_URI_BASE,
                                formatLabel(issuer, accountName),
                                secret) + formatIssuerParameter(issuer)));
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
