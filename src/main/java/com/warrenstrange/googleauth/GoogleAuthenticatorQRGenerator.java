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

import org.apache.http.client.utils.URIBuilder;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

/**
 * This class provides helper methods to create a QR code containing the
 * provided credential.  The generated QR code can be fed to the Google
 * Authenticator application so that it can configure itself with the data
 * contained therein.
 */
public final class GoogleAuthenticatorQRGenerator
{
    /**
     * The format string to generate the Google Chart HTTP API call.
     */
    private static final String TOTP_URI_FORMAT =
            "https://chart.googleapis.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl=%s";

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
    private static String internalURLEncode(String s)
    {
        try
        {
            return URLEncoder.encode(s, "UTF-8");
        }
        catch (UnsupportedEncodingException e)
        {
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
    private static String formatLabel(String issuer, String accountName)
    {
        if (accountName == null || accountName.trim().length() == 0)
        {
            throw new IllegalArgumentException("Account name must not be empty.");
        }

        StringBuilder sb = new StringBuilder();

        if (issuer != null)
        {
            if (issuer.contains(":"))
            {
                throw new IllegalArgumentException("Issuer cannot contain the \':\' character.");
            }

            sb.append(issuer);
            sb.append(":");
        }

        sb.append(accountName);

        return sb.toString();
    }

    /**
     * Returns the URL of a Google Chart API call to generate a QR barcode to
     * be loaded into the Google Authenticator application.  The user scans this
     * bar code with the application on their smart phones or enters the
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
     * @param credentials The generated credentials.  This parameter shall not be null.
     * @return the Google Chart API call URL to generate a QR code containing
     * the provided information.
     * @see <a href="https://code.google.com/p/google-authenticator/wiki/KeyUriFormat">Google Authenticator - KeyUriFormat</a>
     */
    public static String getOtpAuthURL(String issuer,
                                       String accountName,
                                       GoogleAuthenticatorKey credentials)
    {

        return String.format(
                TOTP_URI_FORMAT,
                internalURLEncode(getOtpAuthTotpURL(issuer, accountName, credentials)));
    }

    /**
     * Returns the basic otpauth TOTP URI. This URI might be sent to the user via email, QR code or some other method.
     * Use a secure transport since this URI contains the secret.
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
     * @param credentials The generated credentials.  This parameter shall not be null.
     * @return an otpauth scheme URI for loading into a client application.
     * @see <a href="https://github.com/google/google-authenticator/wiki/Key-Uri-Format">Google Authenticator - KeyUriFormat</a>
     */
    public static String getOtpAuthTotpURL(String issuer,
                                           String accountName,
                                           GoogleAuthenticatorKey credentials)
    {
        URIBuilder uri = new URIBuilder()
                .setScheme("otpauth")
                .setHost("totp")
                .setPath("/" + formatLabel(issuer, accountName))
                .setParameter("secret", credentials.getKey());

        if (issuer != null)
        {
            if (issuer.contains(":"))
            {
                throw new IllegalArgumentException("Issuer cannot contain the \':\' character.");
            }

            uri.setParameter("issuer", issuer);
        }

        final GoogleAuthenticatorConfig config = credentials.getConfig();
        uri.setParameter("algorithm", getAlgorithmName(config.getHmacHashFunction()));
        uri.setParameter("digits", String.valueOf(config.getCodeDigits()));
        uri.setParameter("period", String.valueOf((int) (config.getTimeStepSizeInMillis() / 1000)));

        return uri.toString();
    }

    private static String getAlgorithmName(HmacHashFunction hashFunction)
    {
        switch (hashFunction)
        {
            case HmacSHA1:
                return "SHA1";

            case HmacSHA256:
                return "SHA256";

            case HmacSHA512:
                return "SHA512";

            default:
                throw new IllegalArgumentException(String.format("Unknown algorithm %s", hashFunction));
        }
    }
}
