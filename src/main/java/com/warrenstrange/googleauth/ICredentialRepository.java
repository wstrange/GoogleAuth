package com.warrenstrange.googleauth;

/**
 * @author Enrico M. Crisosotomo
 */
public interface ICredentialRepository {
    /** This method retrieves the Base32-encoded private key of the given user.
     *
     * @param username the user whose private key shall be retrieved.
     * @return the private key of the specified user.
     */
    String getUserKey(String username);
}
