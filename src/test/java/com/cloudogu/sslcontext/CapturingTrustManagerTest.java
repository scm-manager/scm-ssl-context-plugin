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

import org.github.sdorra.jse.ShiroExtension;
import org.github.sdorra.jse.SubjectAware;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import sonia.scm.store.InMemoryDataStoreFactory;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static com.cloudogu.sslcontext.CertTestUtil.createKeyPair;
import static com.cloudogu.sslcontext.CertTestUtil.createX509Cert;
import static com.cloudogu.sslcontext.Certificate.Error.EXPIRED;
import static com.cloudogu.sslcontext.Certificate.Error.NOT_YET_VALID;
import static com.cloudogu.sslcontext.Certificate.Error.UNKNOWN;
import static com.cloudogu.sslcontext.Certificate.Status.REJECTED;
import static org.assertj.core.api.Assertions.assertThat;

@SubjectAware(value = "trillian", permissions = "sslContext:read")
@ExtendWith({ShiroExtension.class, SecureEchoServerExtension.class})
class CapturingTrustManagerTest {

  private static final char[] PASSWORD = "test".toCharArray();

  private CertificateStore store;

  @BeforeEach
  void setUpStore() {
    store = new CertificateStore(new InMemoryDataStoreFactory(), new TrustedCertificatesStore(new InMemoryBlobStoreFactory()));
  }

  @Test
  void shouldStoreUnknownCertificate(EchoServer echoServer) throws Exception {
    KeyStore keyStore = createKeyStore(
      Instant.now().minus(1, ChronoUnit.MINUTES),
      Instant.now().plus(1, ChronoUnit.MINUTES)
    );

    echoServer.start(keyStore, PASSWORD);

    SSLContextProvider sslContextProvider = createSSLContextProvider(keyStore);
    echoServer.send(sslContextProvider, "hi");

    assertRejected(UNKNOWN);
  }

  @Test
  void shouldStoreNotYetValidCertificate(EchoServer echoServer) throws Exception {
    KeyStore keyStore = createKeyStore(
      Instant.now().plus(1, ChronoUnit.MINUTES),
      Instant.now().plus(2, ChronoUnit.MINUTES)
    );

    echoServer.start(keyStore, PASSWORD);

    SSLContextProvider sslContextProvider = createSSLContextProvider(keyStore);
    echoServer.send(sslContextProvider, "hello");

    assertRejected(NOT_YET_VALID);
  }

  @Test
  void shouldStoreExpiredCertificate(EchoServer echoServer) throws Exception {
    KeyStore keyStore = createKeyStore(
      Instant.now().minus(2, ChronoUnit.MINUTES),
      Instant.now().minus(1, ChronoUnit.MINUTES)
    );

    echoServer.start(keyStore, PASSWORD);

    SSLContextProvider sslContextProvider = createSSLContextProvider(keyStore);
    echoServer.send(sslContextProvider, "hello");

    assertRejected(EXPIRED);
  }

  private void assertRejected(Certificate.Error unknown) {
    Certificate cert = store.getAllRejected().iterator().next();
    assertThat(cert.getStatus()).isEqualTo(REJECTED);
    assertThat(cert.getError()).isEqualTo(unknown);
  }

  private SSLContextProvider createSSLContextProvider(KeyStore trustStore) throws NoSuchAlgorithmException, KeyStoreException {
    return new SSLContextProvider(
      new CapturingTrustManager(store, getTrustManager(trustStore))
    );
  }

  private SSLContextProvider createSSLContextProvider() throws NoSuchAlgorithmException, KeyStoreException {
    return createSSLContextProvider(null);
  }

  private X509TrustManager getTrustManager(KeyStore trustStore) throws NoSuchAlgorithmException, KeyStoreException {
    if (trustStore == null) {
      return null;
    }
    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(trustStore);
    return (X509TrustManager) trustManagerFactory.getTrustManagers()[0];
  }

  private KeyStore createKeyStore(Instant start, Instant end) throws Exception {
    KeyPair keyPair = createKeyPair();
    X509Certificate cert = createX509Cert(keyPair, start, end);
    return saveCert(cert, keyPair.getPrivate());
  }

  private KeyStore saveCert(X509Certificate cert, PrivateKey key) throws Exception {
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);
    keyStore.setKeyEntry("hitchhiker_cert", key, PASSWORD, new java.security.cert.Certificate[]{cert});
    return keyStore;
  }
}
