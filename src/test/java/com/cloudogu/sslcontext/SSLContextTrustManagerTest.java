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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.github.sdorra.jse.ShiroExtension;
import org.github.sdorra.jse.SubjectAware;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import sonia.scm.store.InMemoryDataStore;
import sonia.scm.store.InMemoryDataStoreFactory;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;

import static com.cloudogu.sslcontext.CertTestUtil.createKeyPair;
import static com.cloudogu.sslcontext.CertTestUtil.createX509Cert;
import static com.cloudogu.sslcontext.Certificate.Error.NOT_YET_VALID;
import static com.cloudogu.sslcontext.Certificate.Error.UNKNOWN;
import static com.cloudogu.sslcontext.Certificate.Status.REJECTED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SubjectAware(value = "trillian", permissions = "sslContext:read")
@ExtendWith({MockitoExtension.class, ShiroExtension.class})
class SSLContextTrustManagerTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private ServerSocket serverSocket;
  private static final char[] PASSWORD = "test".toCharArray();

  private final InMemoryDataStore<Certificate> dataStore = new InMemoryDataStore<>();

  @Nested
  class withUnknownCert {

    @Test
    void shouldStoreUnknownCertificate() throws Exception {
      KeyManager[] keyManagers = getKeyManagers(createKeyStore(0, 40000));
      SSLServerSocketFactory serverSocketFactory = createSSLContext(keyManagers).getServerSocketFactory();
      serverSocket = serverSocketFactory.createServerSocket(0);
      new Thread(() -> {
        try {
          Socket accept = serverSocket.accept();
          BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(accept.getInputStream()));

          String line = bufferedReader.readLine();

          while (line != null) {
            System.out.println(line);
            line = bufferedReader.readLine();
          }

          bufferedReader.close();
          accept.close();

        } catch (IOException e) {
          e.printStackTrace();
        }
      }).start();

      SSLContextProvider sslContextProvider = new SSLContextProvider(new SSLContextTrustManager(new CertificateStore(new InMemoryDataStoreFactory(dataStore))));
      SSLSocket localhost = ((SSLSocket) sslContextProvider.get().getSocketFactory().createSocket("localhost", serverSocket.getLocalPort()));

      assertThrows(SSLHandshakeException.class, localhost::startHandshake);

      Certificate cert = dataStore.getAll().values().iterator().next();
      assertThat(cert.getStatus()).isEqualTo(REJECTED);
      assertThat(cert.getError()).isEqualTo(UNKNOWN);

      serverSocket.close();
    }
  }

  @Nested
  class withNotYetValidCert {
    @Test
    void shouldStoreNotYetValidCertificate() throws Exception {
      KeyManager[] keyManagers = getKeyManagers(createKeyStore(0, 40000));
      SSLServerSocketFactory serverSocketFactory = createSSLContext(keyManagers).getServerSocketFactory();
      SSLContextProvider sslContextProvider =
        new SSLContextProvider(
          new SSLContextTrustManager(
            new CertificateStore(
              new InMemoryDataStoreFactory(dataStore)
            )
          ),
          keyManagers
        );

      serverSocket = serverSocketFactory.createServerSocket(0);
      new Thread(() -> {
        try {
          Socket accept = serverSocket.accept();
          BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(accept.getInputStream()));

          String line = bufferedReader.readLine();

          while (line != null) {
            System.out.println(line);
            line = bufferedReader.readLine();
          }

          bufferedReader.close();
          accept.close();

        } catch (IOException e) {
          e.printStackTrace();
        }
      }).start();


      Socket localhost = sslContextProvider.get().getSocketFactory().createSocket("localhost", serverSocket.getLocalPort());

      localhost.getOutputStream().write("test".getBytes());

      Certificate cert = dataStore.getAll().values().iterator().next();
      assertThat(cert.getStatus()).isEqualTo(REJECTED);
      assertThat(cert.getError()).isEqualTo(NOT_YET_VALID);

      serverSocket.close();
    }
  }

  SSLContext createSSLContext(KeyManager[] keyManagers) throws Exception {
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(keyManagers, null, null);
    return sslContext;
  }

  private KeyManager[] getKeyManagers(KeyStore keyStore) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, PASSWORD);
    return keyManagerFactory.getKeyManagers();
  }

  KeyStore createKeyStore(long start, long end) throws Exception {
    KeyPair keyPair = createKeyPair();
    X509Certificate cert = createX509Cert(keyPair, start, end);
    return saveCert(cert, keyPair.getPrivate());
  }

  private KeyStore saveCert(X509Certificate cert, PrivateKey key) throws Exception {
    KeyStore keyStore = KeyStore.getInstance("JKS");
    keyStore.load(null, null);
    keyStore.setKeyEntry("hitchhiker_cert", key, PASSWORD, new java.security.cert.Certificate[]{cert});
    return keyStore;
  }
}
