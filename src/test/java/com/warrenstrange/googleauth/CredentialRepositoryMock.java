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
