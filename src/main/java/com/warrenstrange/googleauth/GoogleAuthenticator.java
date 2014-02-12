package com.warrenstrange.googleauth;

import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class implements the functionality described in RFC 6238 (TOTP: Time
 * based one-time password algorithm) and has been tested again Google's
 * implementation of such algorithm in its Google Authenticator application.
 * <p/>
 * This class lets users create a new 16-bit base32-encoded secret key with
 * the validation code calculated at time=0 (the UNIX epoch) and the URL of a
 * Google-provided QR barcode to let an user load the generated information into
 * Google Authenticator.
 * <p/>
 * This class doesn't store in any way either the generated keys nor the keys
 * passed during the authorization process.
 * <p/>
 * Java Server side class for Google Authenticator's TOTP generator was inspired
 * by an author's blog post.
 *
 * @version 1.0
 * @see <a href="http://thegreyblog.blogspot.com/2011/12/google-authenticator-using-it-in-your.html" />
 * @see <a href="http://code.google.com/p/google-authenticator" />
 * @see <a href="http://tools.ietf.org/id/draft-mraihi-totp-timebased-06.txt" />
 * @since 1.0
 */
public final class GoogleAuthenticator {

    /**
     * The logger for this class.
     */
    private static final Logger LOGGER =
            Logger.getLogger(GoogleAuthenticator.class.getName());

    /**
     * The number of bits of a secret key in binary form. Since the Base32
     * encoding with 8 bit characters introduces an 160% overhead, we just need
     * 80 bits (8 bytes) to generate a 16 bytes Base32-encoded secret key.
     */
    private static final int SECRET_BITS = 80;

    /**
     * Number of scratch codes to generate during the key generation.
     * We are using Google's default of providing 5 scratch codes.
     */
    private static final int SCRATCH_CODES = 5;

    /**
     * Length in bytes of each scratch code. We're using Google's default of
     * using 4 bytes per scratch code.
     */
    private static final int BYTES_PER_SCRATCH_CODE = 4;

    /**
     * The size of the seed which is fed to the SecureRandom instance, in bytes.
     */
    private static final int SEED_SIZE = 128;

    /**
     * The SecureRandom algorithm to use.
     *
     * @see java.security.SecureRandom#getInstance(String)
     */
    private static final String RANDOM_NUMBER_ALGORITHM = "SHA1PRNG";

    /**
     * The initial windowSize used when validating the codes. We are using
     * Google's default behaviour of using a window size equal to 3. The maximum
     * window size is 17.
     */
    private int windowSize = 3;

    /**
     * The internal SecureRandom instance used by this class. Since as of Java 7
     * Random instances are required to be thread-safe, no synchronisation is
     * required in the methods of this class using this instance. Thread-safety
     * of this class was a de-facto standard in previous versions of Java so
     * that it is expected to work correctly in previous versions of the Java
     * platform as well.
     */
    private SecureRandom secureRandom;

    /**
     * Cryptographic hash function used to calculate the HMAC (Hash-based
     * Message Authentication Code). This implementation uses the SHA1 hash
     * function.
     */
    public static final String HMAC_HASH_FUNCTION = "HmacSHA1";

    /**
     * Modulus of the secret key.
     */
    public static final int SECRET_KEY_MODULE = 1000 * 1000;

    public GoogleAuthenticator() {

        try {
            secureRandom = SecureRandom.getInstance(RANDOM_NUMBER_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new GoogleAuthenticatorException(
                    String.format(
                            "Could not initialise SecureRandom " +
                                    "with the specified algorithm: %s",
                            RANDOM_NUMBER_ALGORITHM), e);
        }

        reSeed();
    }

    public void reSeed() {
        secureRandom.setSeed(secureRandom.generateSeed(SEED_SIZE));
    }

    /**
     * Generate a random secret key. This must be saved by the server and
     * associated with the users account to verify the code displayed by
     * Google Authenticator.
     * <p/>
     * The user must register this secret on their device.
     *
     * @return secret key
     */
    public GoogleAuthenticatorKey generateSecretKey() {

        // Allocating a buffer sufficiently large to hold the bytes required by
        // the secret key and the scratch codes.
        byte[] buffer =
                new byte[SECRET_BITS / 8 + SCRATCH_CODES * BYTES_PER_SCRATCH_CODE];

        secureRandom.nextBytes(buffer);

        // Extracting the bytes making up the secret key.
        byte[] secretKey = Arrays.copyOf(buffer, SECRET_BITS / 8);

        Base32 codec = new Base32();
        byte[] encodedKey = codec.encode(secretKey);

        // Creating a string with the Base32 encoded bytes.
        final String generatedKey = new String(encodedKey);

        // Generating the verification code at time = 0.
        int generateCode;

        try {
            generateCode = calculateCode(secretKey, 0);
        } catch (NoSuchAlgorithmException ex) {
            // Logging the exception.
            LOGGER.log(Level.SEVERE, ex.getMessage(), ex);

            // We're not disclosing internal error details to our clients.
            throw new GoogleAuthenticatorException("The operation cannot be "
                    + "performed now.");
        } catch (InvalidKeyException ex) {
            // Logging the exception
            LOGGER.log(Level.SEVERE, ex.getMessage(), ex);

            // We're not disclosing internal error details to our clients.
            throw new GoogleAuthenticatorException("The operation cannot be "
                    + "performed now.");
        }

        return new GoogleAuthenticatorKey(generatedKey, generateCode);
    }

    /**
     * Calculates the verification code of the provided key at the specified
     * instant of time using the algorithm specified in RFC 6238.
     *
     * @param key the secret key in binary format.
     * @param tm  the instant of time.
     * @return the validation code for the provided key at the specified instant
     * of time.
     * @throws NoSuchAlgorithmException if the algorithm using during the
     *                                  validation process (HmacSHA1) is not
     *                                  available.
     * @throws InvalidKeyException      if the secret key specification is
     *                                  invalid.
     */
    private static int calculateCode(byte[] key, long tm)
            throws NoSuchAlgorithmException, InvalidKeyException {
        // Allocating an array of bytes to represent the specified instant
        // of time.
        byte[] data = new byte[8];
        long value = tm;

        // Converting the instant of time from the long representation to an
        // array of bytes.
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }

        // Building the secret key specification for the HmacSHA1 algorithm.
        SecretKeySpec signKey = new SecretKeySpec(key, HMAC_HASH_FUNCTION);

        // Getting an HmacSHA1 algorithm implementation from the JCE.
        Mac mac = Mac.getInstance(HMAC_HASH_FUNCTION);

        // Initializing the MAC algorithm.
        mac.init(signKey);

        // Processing the instant of time and getting the encrypted data.
        byte[] hash = mac.doFinal(data);

        // Building the validation code.
        int offset = hash[20 - 1] & 0xF;
        long truncatedHash = 0;

        for (int i = 0; i < 4; ++i) {
            //truncatedHash = (truncatedHash * 256) & 0xFFFFFFFF;
            truncatedHash <<= 8;

            // Java bytes are signed but we need an unsigned one:
            // cleaning off all but the LSB.
            truncatedHash |= (hash[offset + i] & 0xFF);
        }

        // Cleaning bits higher than 32nd and calculating the module with the
        // maximum validation code value.
        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= SECRET_KEY_MODULE;

        // Returning the validation code to the caller.
        return (int) truncatedHash;
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
