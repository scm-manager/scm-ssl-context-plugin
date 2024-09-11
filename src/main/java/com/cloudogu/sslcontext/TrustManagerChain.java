/*
 * Copyright (c) 2020 - present Cloudogu GmbH
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see https://www.gnu.org/licenses/.
 */

package com.cloudogu.sslcontext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import jakarta.inject.Inject;
import jakarta.inject.Named;
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
