package com.warrenstrange.googleauth;

/**
 * An interface for {@link com.warrenstrange.googleauth.GoogleAuthenticator} which implements the functionality
 * described in RFC 6238 (TOTP: Time based one-time password algorithm).
 *
 * @see <a href="http://tools.ietf.org/html/rfc6238">RFC 6238</a>
 */
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
     * Set the default window size used by this instance when an explicit value
     * is not specified. This is an integer value representing the number of 30
     * second windows we check during the validation process, to account for
     * differences between the server and the client clocks.
     * The bigger the window, the more tolerant we are about clock skews.
     *
     * @param s window size - must be >=1 and <=17.  Other values are ignored
     */
    void setWindowSize(int s);

    /**
     * Get the default window size used by this instance when an explicit value
     * is not specified.
     *
     * @return the current window size.
     */
    int getWindowSize();

    /**
     * Checks a verification code against a secret key using the current time.
     * The algorithm also checks in a time window whose size determined by the
     * <code>windowSize</code> property of this class.
     * <p/>
     * We are using Google's default value of 30 seconds for the interval size.
     *
     * @param secret           the Base32 encoded secret key.
     * @param verificationCode the verification code.
     * @return <code>true</code> if the validation code is valid,
     * <code>false</code> otherwise.
     * @throws com.warrenstrange.googleauth.GoogleAuthenticatorException if a failure occurs during the
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
     * @throws com.warrenstrange.googleauth.GoogleAuthenticatorException
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
     * @throws com.warrenstrange.googleauth.GoogleAuthenticatorException
     * @see com.warrenstrange.googleauth.GoogleAuthenticator#MAX_WINDOW
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
     * We are using Google's default value of 30 seconds for the interval size.
     *
     * @param secret           the Base32 encoded secret key.
     * @param verificationCode the verification code.
     * @param window           the window size to use during the validation
     *                         process.
     * @return <code>true</code> if the validation code is valid,
     * <code>false</code> otherwise.
     * @throws com.warrenstrange.googleauth.GoogleAuthenticatorException if a failure occurs during the
     *                                      calculation of the validation code.
     *                                      The only failures that should occur
     *                                      are related with the cryptographic
     *                                      functions provided by the JCE.
     * @see com.warrenstrange.googleauth.GoogleAuthenticator#MAX_WINDOW
     */
    boolean authorize(
            String secret,
            int verificationCode,
            int window)
            throws GoogleAuthenticatorException;
}
