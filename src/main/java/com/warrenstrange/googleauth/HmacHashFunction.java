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

import javax.crypto.Mac;
import java.security.NoSuchAlgorithmException;

public enum HmacHashFunction
{
    HmacSHA1,
    HmacSHA256,
    HmacSHA512
    ;

    static Mac getInstance(HmacHashFunction hmacHashFunction) {
        switch (hmacHashFunction) {
            case HmacSHA1:
                return HmacHashThreadLocals.hmacSHA1ThreadLocal.get();
            case HmacSHA256:
                return HmacHashThreadLocals.hmacSHA256ThreadLocal.get();
            case HmacSHA512:
                return HmacHashThreadLocals.hmacSHA512ThreadLocal.get();
            default:
                return HmacHashThreadLocals.hmacSHA1ThreadLocal.get();
        }
    }

    private static class HmacHashThreadLocals {
        static final ThreadLocal<Mac> hmacSHA1ThreadLocal = new ThreadLocal<Mac>() {
            @Override
            protected Mac initialValue() {
                try {
                    return Mac.getInstance(HmacSHA1.toString());
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                    return null;
                }
            }
        };

        static final ThreadLocal<Mac> hmacSHA256ThreadLocal = new ThreadLocal<Mac>() {
            @Override
            protected Mac initialValue() {
                try {
                    return Mac.getInstance(HmacSHA256.toString());
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                    return null;
                }
            }
        };

        static final ThreadLocal<Mac> hmacSHA512ThreadLocal = new ThreadLocal<Mac>() {
            @Override
            protected Mac initialValue() {
                try {
                    return Mac.getInstance(HmacSHA512.toString());
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                    return null;
                }
            }
        };
    }
}
