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

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Date: 08/04/14
 * Time: 15:21
 *
 * @author Enrico M. Crisostomo
 */
class ReseedingSecureRandom {
    private static final int MAX_OPERATIONS = 1_000_000;
    private final String provider;
    private final String algorithm;
    private final Lock lock = new ReentrantLock();
    private final AtomicInteger count = new AtomicInteger(0);
    private SecureRandom secureRandom;

    @SuppressWarnings("UnusedDeclaration")
    ReseedingSecureRandom() {
        this.algorithm = null;
        this.provider = null;

        buildSecureRandom();
    }

    @SuppressWarnings("UnusedDeclaration")
    ReseedingSecureRandom(String algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm cannot be null.");
        }

        this.algorithm = algorithm;
        this.provider = null;

        buildSecureRandom();
    }

    ReseedingSecureRandom(String algorithm, String provider) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm cannot be null.");
        }

        if (provider == null) {
            throw new IllegalArgumentException("Provider cannot be null.");
        }

        this.algorithm = algorithm;
        this.provider = provider;

        buildSecureRandom();
    }

    private void buildSecureRandom() {
        try {
            if (this.algorithm == null && this.provider == null) {
                this.secureRandom = new SecureRandom();
            } else if (this.provider == null) {
                this.secureRandom = SecureRandom.getInstance(this.algorithm);
            } else {
                this.secureRandom = SecureRandom.getInstance(this.algorithm, this.provider);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new GoogleAuthenticatorException(
                    String.format(
                            "Could not initialise SecureRandom " +
                                    "with the specified algorithm: %s",
                            this.algorithm
                    ), e
            );
        } catch (NoSuchProviderException e) {
            throw new GoogleAuthenticatorException(
                    String.format(
                            "Could not initialise SecureRandom " +
                                    "with the specified provider: %s",
                            this.provider
                    ), e
            );
        }
    }

    void nextBytes(byte[] bytes) {
        int currentCount = count.incrementAndGet();
        if (currentCount > MAX_OPERATIONS) {
            lock.lock();
            try {
                currentCount = count.get();
                if (currentCount > MAX_OPERATIONS) {
                    buildSecureRandom();
                    count.set(0);
                }
            } finally {
                lock.unlock();
            }
        }
        this.secureRandom.nextBytes(bytes);
    }
}
