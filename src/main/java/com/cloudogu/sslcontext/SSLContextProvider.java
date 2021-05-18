/*
 * MIT License
 *
 * Copyright (c) 2020-present Cloudogu GmbH and Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.cloudogu.sslcontext;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.net.ssl.SSLContext;
import java.security.GeneralSecurityException;

class SSLContextProvider implements Provider<SSLContext> {

  private final CapturingTrustManager capturingSslTrustManager;

  @Inject
  public SSLContextProvider(CapturingTrustManager trustManager) {
    this.capturingSslTrustManager = trustManager;
  }

  @Override
  public SSLContext get() {
    try {
      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(null, new CapturingTrustManager[]{capturingSslTrustManager}, null);
      return sslContext;
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException();
    }
  }
}
