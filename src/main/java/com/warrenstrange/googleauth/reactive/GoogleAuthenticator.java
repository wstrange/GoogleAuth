/*
 * Copyright (c) 2014-2018 Enrico M. Crisostomo
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

package com.warrenstrange.googleauth.reactive;

import java.util.Date;
import java.util.ServiceLoader;

import com.warrenstrange.googleauth.BaseGoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorException;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import reactor.core.publisher.Mono;

/**
 * This class implements the functionality described in RFC 6238 (TOTP: Time
 * based one-time password algorithm) and has been tested again Google's
 * implementation of such algorithm in its Google Authenticator application.
 * <p/>
 * This class lets users create a new 16-bit base32-encoded secret key with
 * the validation code calculated at {@code time = 0} (the UNIX epoch) and the
 * URL of a Google-provided QR barcode to let an user load the generated
 * information into Google Authenticator.
 * <p/>
 * The random number generator used by this class uses the default algorithm and
 * provider.  Users can override them by setting the following system properties
 * to the algorithm and provider name of their choice:
 * <ul>
 * <li>{@link #RNG_ALGORITHM}.</li>
 * <li>{@link #RNG_ALGORITHM_PROVIDER}.</li>
 * </ul>
 * <p/>
 * This class does not store in any way either the generated keys nor the keys
 * passed during the authorization process.
 * <p/>
 * Java Server side class for Google Authenticator's TOTP generator was inspired
 * by an author's blog post.
 *
 * @author Enrico M. Crisostomo
 * @author Warren Strange
 * @version 1.1.4
 * @see <a href="http://thegreyblog.blogspot.com/2011/12/google-authenticator-using-it-in-your.html" />
 * @see <a href="http://code.google.com/p/google-authenticator" />
 * @see <a href="http://tools.ietf.org/id/draft-mraihi-totp-timebased-06.txt" />
 * @since 0.3.0
 */
public final class GoogleAuthenticator extends BaseGoogleAuthenticator
    implements IPersistableGoogleAuthenticator
{

    private ICredentialRepository credentialRepository;
    private boolean credentialRepositorySearched;

    public GoogleAuthenticator()
    {
        super();
    }

    public GoogleAuthenticator(GoogleAuthenticatorConfig config)
    {
        super(config);
    }

    @Override
    public Mono<GoogleAuthenticatorKey> createCredentials(String userName)
    {
        // Further validation will be performed by the configured provider.
        if (userName == null)
        {
            throw new IllegalArgumentException("User name cannot be null.");
        }

        GoogleAuthenticatorKey key = createCredentials();

        ICredentialRepository repository = getValidCredentialRepository();
        return repository
            .saveUserCredentials(
                userName,
                key.getKey(),
                key.getVerificationCode(),
                key.getScratchCodes()
            )
            .thenReturn(key);
    }

    public Mono<Integer> getTotpPasswordOfUser(String userName)
    {
        return getTotpPasswordOfUser(userName, new Date().getTime());
    }

    public Mono<Integer> getTotpPasswordOfUser(String userName, long time)
    {
        ICredentialRepository repository = getValidCredentialRepository();

        return repository.getSecretKey(userName)
                         .map(sc -> calculateCode(
                             decodeSecret(sc),
                             getTimeWindowFromTime(time)
                         ));
    }

    @Override
    public Mono<Boolean> authorizeUser(String userName, int verificationCode)
            throws GoogleAuthenticatorException
    {
        return authorizeUser(userName, verificationCode, new Date().getTime());
    }

    @Override
    public Mono<Boolean> authorizeUser(String userName, int verificationCode, long time)
    {
        ICredentialRepository repository = getValidCredentialRepository();

        return repository.getSecretKey(userName)
                         .map(sc -> authorize(sc, verificationCode, time));
    }

    /**
     * This method loads the first available and valid ICredentialRepository
     * registered using the Java service loader API.
     *
     * @return the first registered ICredentialRepository.
     * @throws UnsupportedOperationException if no valid service is
     *                                                 found.
     */
    private ICredentialRepository getValidCredentialRepository()
    {
        ICredentialRepository repository = getCredentialRepository();

        if (repository == null)
        {
            throw new UnsupportedOperationException(
                    String.format("An instance of the %s service must be " +
                                    "configured in order to use this feature.",
                            ICredentialRepository.class.getName()
                    )
            );
        }

        return repository;
    }

    /**
     * This method loads the first available ICredentialRepository
     * registered using the Java service loader API.
     *
     * @return the first registered ICredentialRepository or <code>null</code>
     * if none is found.
     */
    public ICredentialRepository getCredentialRepository()
    {
        if (this.credentialRepositorySearched) return this.credentialRepository;

        this.credentialRepositorySearched = true;

        ServiceLoader<ICredentialRepository> loader =
                ServiceLoader.load(ICredentialRepository.class);

        //noinspection LoopStatementThatDoesntLoop
        for (ICredentialRepository repository : loader)
        {
            this.credentialRepository = repository;
            break;
        }

        return this.credentialRepository;
    }

    @Override
    public void setCredentialRepository(ICredentialRepository repository)
    {
        this.credentialRepository = repository;
        this.credentialRepositorySearched = true;
    }
}
