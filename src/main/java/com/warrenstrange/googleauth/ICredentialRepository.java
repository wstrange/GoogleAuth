package com.warrenstrange.googleauth;

import java.util.List;

/**
 * @author Enrico M. Crisosotomo
 */
public interface ICredentialRepository {
    /** This method retrieves the Base32-encoded private key of the given user.
     *
     * @param userName the user whose private key shall be retrieved.
     * @return the private key of the specified user.
     */
    String getSecretKey(String userName);

    /**
     * This method saves the user credentials.
     *
     * @param userName the user whose data shall be saved.
     * @param secretKey the generated key.
     * @param validationCode the validation code.
     * @param scratchCodes the list of scratch codes.
     */
    void saveUserCredentials(String userName,
                             String secretKey,
                             int validationCode,
                             List<Integer> scratchCodes);
}
