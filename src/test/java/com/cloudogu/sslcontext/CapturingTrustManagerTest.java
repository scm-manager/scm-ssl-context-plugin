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
    store = new CertificateStore(new InMemoryDataStoreFactory());
  }

  @Test
  void shouldStoreUnknownCertificate(EchoServer echoServer) throws Exception {
    KeyStore keyStore = createKeyStore(
      Instant.now().minus(1, ChronoUnit.MINUTES),
      Instant.now().plus(1, ChronoUnit.MINUTES)
    );

    echoServer.start(keyStore, PASSWORD);

    SSLContextProvider sslContextProvider = createSSLContextProvider();
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
    Certificate cert = store.getAll().iterator().next();
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
