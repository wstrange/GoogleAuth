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
 * @version 1.1.4
 * @see GoogleAuthenticator
 * @since 1.0.0
 */
public final class GoogleAuthenticatorKey
{
    /**
     * The configuration of this key.
     */
    private final GoogleAuthenticatorConfig config;

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
     * The private constructor of this class.
     *
     * @param config           the configuration of the TOTP algorithm.
     * @param key              the secret key in Base32 encoding.
     * @param verificationCode the verification code at time = 0 (the UNIX epoch).
     * @param scratchCodes     the list of scratch codes.
     */
    private GoogleAuthenticatorKey(GoogleAuthenticatorConfig config,
                                   String key,
                                   int verificationCode,
                                   List<Integer> scratchCodes)
    {
        if (key == null)
        {
            throw new IllegalArgumentException("Key cannot be null");
        }

        if (config == null)
        {
            throw new IllegalArgumentException("Configuration cannot be null");
        }

        if (scratchCodes == null)
        {
            throw new IllegalArgumentException("Scratch codes cannot be null");
        }

        this.config = config;
        this.key = key;
        this.verificationCode = verificationCode;
        this.scratchCodes = new ArrayList<>(scratchCodes);
    }

    /**
     * Get the list of scratch codes.
     *
     * @return the list of scratch codes.
     */
    public List<Integer> getScratchCodes()
    {
        return scratchCodes;
    }

    /**
     * Get the config of this key.
     *
     * @return the config of this key.
     */
    public GoogleAuthenticatorConfig getConfig()
    {
        return config;
    }

    /**
     * Returns the secret key in Base32 encoding.
     *
     * @return the secret key in Base32 encoding.
     */
    public String getKey()
    {
        return key;
    }

    /**
     * Returns the verification code at time = 0 (the UNIX epoch).
     *
     * @return the verificationCode at time = 0 (the UNIX epoch).
     */
    public int getVerificationCode()
    {
        return verificationCode;
    }

    /**
     * This class is a builder to create instances of the {@link GoogleAuthenticatorKey} class.
     */
    public static class Builder
    {
        private GoogleAuthenticatorConfig config = new GoogleAuthenticatorConfig();
        private String key;
        private int verificationCode;
        private List<Integer> scratchCodes = new ArrayList<>();

        /**
         * Creates an instance of the builder.
         *
         * @param key the secret key in Base32 encoding.
         * @see GoogleAuthenticatorKey#GoogleAuthenticatorKey(GoogleAuthenticatorConfig, String, int, List)
         */
        public Builder(String key)
        {
            this.key = key;
        }

        /**
         * Creates an instance of the {@link GoogleAuthenticatorKey} class.
         *
         * @return an instance of the {@link GoogleAuthenticatorKey} class initialized with the properties set in this builder.
         * @see GoogleAuthenticatorKey#GoogleAuthenticatorKey(GoogleAuthenticatorConfig, String, int, List)
         */
        public GoogleAuthenticatorKey build()
        {
            return new GoogleAuthenticatorKey(config, key, verificationCode, scratchCodes);
        }

        /**
         * Sets the config of the TOTP algorithm for this key.
         *
         * @param config the config of the TOTP algorithm for this key.
         * @see GoogleAuthenticatorKey#GoogleAuthenticatorKey(GoogleAuthenticatorConfig, String, int, List)
         */
        public Builder setConfig(GoogleAuthenticatorConfig config)
        {
            this.config = config;
            return this;
        }

        /**
         * Sets the secret key.
         *
         * @param key the secret key.
         * @see GoogleAuthenticatorKey#GoogleAuthenticatorKey(GoogleAuthenticatorConfig, String, int, List)
         */
        public Builder setKey(String key)
        {
            this.key = key;
            return this;
        }

        /**
         * Sets the verification code.
         *
         * @param verificationCode the verification code.
         * @see GoogleAuthenticatorKey#GoogleAuthenticatorKey(GoogleAuthenticatorConfig, String, int, List)
         */
        public Builder setVerificationCode(int verificationCode)
        {
            this.verificationCode = verificationCode;
            return this;
        }

        /**
         * Sets the scratch codes.
         *
         * @param scratchCodes the scratch codes.
         * @see GoogleAuthenticatorKey#GoogleAuthenticatorKey(GoogleAuthenticatorConfig, String, int, List)
         */
        public Builder setScratchCodes(List<Integer> scratchCodes)
        {
            this.scratchCodes = scratchCodes;
            return this;
        }
    }
}
