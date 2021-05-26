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

import org.apache.commons.lang.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Named;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Named("chain")
class TrustManagerChain implements X509TrustManager {

  private static final Logger LOG = LoggerFactory.getLogger(TrustManagerChain.class);

  private final Iterable<X509TrustManager> platformTrustManagers;
  private Iterable<X509TrustManager> storedTrustManagers;

  @Inject
  TrustManagerChain(TrustedCertificatesStore store) {
    platformTrustManagers = createTrustManagers(null);
    storedTrustManagers = createTrustManagers(store.getKeyStore());
    store.onChange(keyStore -> storedTrustManagers = createTrustManagers(keyStore));
  }

  private Iterable<X509TrustManager> createTrustManagers(@Nullable KeyStore keyStore) {
    TrustManagerFactory trustManagerFactory;
    try {
      trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      trustManagerFactory.init(keyStore);
    } catch (NoSuchAlgorithmException | KeyStoreException e) {
      throw new com.cloudogu.sslcontext.CertificateException("Could not initialize trust manager", e);
    }

    List<X509TrustManager> trustManagers = new ArrayList<>();
    for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
      trustManagers.add((X509TrustManager) trustManager);
    }

    return trustManagers;
  }

  @Override
  public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
    try {
      for (X509TrustManager trustManager : platformTrustManagers) {
        trustManager.checkServerTrusted(x509Certificates, s);
      }
    } catch (CertificateException platformException) {
      try {
        for (X509TrustManager trustManager : storedTrustManagers) {
          trustManager.checkServerTrusted(x509Certificates, s);
        }
      } catch (Exception storeException) {
        LOG.trace("store trust manager returns error", storeException);
        throw platformException;
      }
    }
  }

  @Override
  public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
    try {
      for (X509TrustManager trustManager : platformTrustManagers) {
        trustManager.checkClientTrusted(x509Certificates, s);
      }
    } catch (CertificateException platformException) {
      try {
        for (X509TrustManager trustManager : storedTrustManagers) {
          trustManager.checkClientTrusted(x509Certificates, s);
        }
      } catch (Exception storeException) {
        LOG.trace("store trust manager returns error", storeException);
        throw platformException;
      }
    }
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    Set<X509Certificate> acceptedIssuers = new HashSet<>();
    for (X509TrustManager tm : platformTrustManagers) {
      acceptedIssuers.addAll(Arrays.asList(tm.getAcceptedIssuers()));
    }
    for (X509TrustManager tm : storedTrustManagers) {
      acceptedIssuers.addAll(Arrays.asList(tm.getAcceptedIssuers()));
    }

    return acceptedIssuers.toArray(new X509Certificate[0]);
  }
}
