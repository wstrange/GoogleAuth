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

import java.util.concurrent.TimeUnit;

import static com.google.common.base.Preconditions.checkArgument;

public class GoogleAuthenticatorConfig {
    private final long timeStepSizeInMillis;
    private final int windowSize;

    /**
     * Builds an instance of this class and sets the timeStepSizeInMillis
     * and windowSize properties to the corresponding values.
     *
     * @param timeStepSizeInMillis the time step size (see
     *                             #timeStepSizeInMillis).
     * @param windowSize           The window size (see #windowSize).
     */
    @SuppressWarnings("UnusedDeclaration")
    public GoogleAuthenticatorConfig(long timeStepSizeInMillis, int windowSize) {
        checkArgument(timeStepSizeInMillis > 0, "Time step size must be positive.");
        checkArgument(windowSize > 0, "Window number must be positive.");

        this.timeStepSizeInMillis = timeStepSizeInMillis;
        this.windowSize = windowSize;
    }

    /**
     * Builds an instance of this class setting its properties to their
     * default values.
     */
    public GoogleAuthenticatorConfig() {
        windowSize = 3;
        timeStepSizeInMillis = TimeUnit.SECONDS.toMillis(30);
    }

    /**
     * The time step size, in milliseconds, as specified by RFC 6238.
     * The default value is 30.000.
     *
     * @return the time step size in milliseconds.
     */
    public long getTimeStepSizeInMillis() {
        return timeStepSizeInMillis;
    }

    /**
     * This is an integer value representing the number of windows of size
     * timeStepSizeInMillis that are checked during the validation process,
     * to account for differences between the server and the client clocks.
     * The bigger the window, the more tolerant the library code is about
     * clock skews.
     * <p/>
     * We are using Google's default behaviour of using a window size equal
     * to 3.  The limit on the maximum window size, present in older
     * versions of this library, has been removed.
     *
     * @return the window size.
     * @see #timeStepSizeInMillis
     */
    public int getWindowSize() {
        return windowSize;
    }
}
