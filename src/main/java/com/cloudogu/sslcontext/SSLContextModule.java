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

import com.google.inject.AbstractModule;
import com.google.inject.name.Names;
import org.mapstruct.factory.Mappers;
import sonia.scm.plugin.Extension;

import javax.inject.Singleton;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

@Extension
public class SSLContextModule extends AbstractModule {

  @Override
  protected void configure() {
    bind(CertificateMapper.class).to(Mappers.getMapperClass(CertificateMapper.class));
    bind(SSLContext.class).annotatedWith(Names.named("default")).toProvider(SSLContextProvider.class).in(Singleton.class);
    bind(X509TrustManager.class).annotatedWith(Names.named("chain")).to(TrustManagerChain.class);
    bind(TrustManager.class).annotatedWith(Names.named("default")).to(CapturingTrustManager.class).in(Singleton.class);
  }
}
