package com.warrenstrange.googleauth;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * This class implements the functionality described in RFC 6238 (TOTP: Time
 * based one-time password algorithm) and has been tested again Google's
 * implementation of such algorithm in its Google Authenticator application.
 *
 * This class lets users create a new 16-bit base32-encoded secret key with
 * the validation code calculated at time=0 (the UNIX epoch) and the URL of a
 * Google-provided QR barcode to let an user load the generated information into
 * Google Authenticator.
 *
 * This class doesn't store in any way either the generated keys nor the keys
 * passed during the authorization process.
 *
 * Java Server side class for Google Authenticator's TOTP generator was inspired
 * by an author's blog post.
 *
 * @see <a href="http://thegreyblog.blogspot.com/2011/12/google-authenticator-using-it-in-your.html" />
 * @see <a href="http://code.google.com/p/google-authenticator" />
 * @see <a href="http://tools.ietf.org/id/draft-mraihi-totp-timebased-06.txt" />
 * @version 1.0
 *
 * @since 1.0
 */
public class GoogleAuthenticator {

    // taken from Google pam docs - we probably don't need to mess with these
    private static final int SECRET_SIZE = 10;
    private static final String SEED = "g8GjEvTbW5oVSV7avLBdwIHqGlUYNzKFI7izOF8GwLDVKs2m0QN7vxRs2im5MDaNCWGmcD2rvcZx";
    private static final String RANDOM_NUMBER_ALGORITHM = "SHA1PRNG";
    private int windowSize = 3;  // default 3 - max 17 (from google docs)

    /**
     * Generate a random secret key. This must be saved by the server and
     * associated with the users account to verify the code displayed by
     * Google Authenticator.
     *
     * The user must register this secret on their device.
     *
     * @return secret key
     */
    public static String generateSecretKey() {

        try {
            SecureRandom sr = SecureRandom.getInstance(RANDOM_NUMBER_ALGORITHM);
            sr.setSeed(Base64.decodeBase64(SEED));
            byte[] buffer = sr.generateSeed(SECRET_SIZE);
            Base32 codec = new Base32();
            byte[] bEncodedKey = codec.encode(buffer);

            return new String(bEncodedKey);
        } catch (NoSuchAlgorithmException e) {
            // should never occur... configuration error
        }
        return null;
    }

    /**
     * Return a URL that generates and displays a QR barcode. The user scans this bar code with the
     * Google Authenticator application on their smart phones to register the auth code. They can also manually enter
     * the secret manually if desired.
     *
     * @param user   the user identifier.
     * @param host   host or system that the code is associated to.
     * @param secret the secret that was previously generated for this user.
     * @return the URL for the QR code to scan.
     */
    public static String getQRBarcodeURL(String user, String host, String secret) {
        String format = "https://www.google.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s";
        return String.format(format, user, host, secret);
    }

    private static int verify_code(byte[] key, long t)
            throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = new byte[8];
        long value = t;
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }

        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);
        byte[] hash = mac.doFinal(data);

        int offset = hash[20 - 1] & 0xF;

        // We're using a long because Java hasn't got unsigned int.
        long truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            // We are dealing with signed bytes:
            // we just keep the first byte.
            truncatedHash |= (hash[offset + i] & 0xFF);
        }

        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;

        return (int) truncatedHash;
    }

    /**
     * set the windows size. This is an integer value representing the number of 30 second windows we allow
     * The bigger the window, the more tolerant of clock skew we are.
     *
     * @param s window size - must be >=1 and <=17.  Other values are ignored
     */
    public void setWindowSize(int s) {
        if (s >= 1 && s <= 17)
            windowSize = s;
    }

    /**
     * Check the code entered by the user to see if it is valid
     *
     * @param secret   The users secret.
     * @param code     The code displayed on the users device
     * @param timeMsec The time in msec (System.currentTimeMillis() for example)
     * @return <code>true</code> if validation succeeds, <code>false</code> otherwise.
     */
    public boolean check_code(String secret, long code, long timeMsec) {
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);

        // convert unix msec time into a 30 second "window"
        // this is per the TOTP spec (see the RFC for details)
        long t = (timeMsec / 1000L) / 30L;
        // Window is used to check codes generated in the near past.
        // You can use this value to tune how far you're willing to go.

        for (int i = -windowSize; i <= windowSize; ++i) {
            long hash;
            try {
                hash = verify_code(decodedKey, t + i);
            } catch (Exception e) {
                // Yes, this is bad form - but
                // the exceptions thrown would be rare and a static configuration problem
                e.printStackTrace();
                throw new RuntimeException(e.getMessage());
                //return false;
            }

            if (hash == code) {
                return true;
            }
        }

        // The validation code is invalid.
        return false;
    }
}
