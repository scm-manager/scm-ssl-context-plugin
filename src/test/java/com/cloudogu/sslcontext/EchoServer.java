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

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class EchoServer {

  private final ExecutorService executorService;
  private ServerSocket serverSocket;

  EchoServer() {
    this.executorService = Executors.newSingleThreadExecutor();
  }

  public void start(KeyStore keyStore, char[] password) {
    try {
      KeyManager[] keyManagers = getKeyManagers(keyStore, password);
      SSLServerSocketFactory serverSocketFactory = createSSLContext(keyManagers).getServerSocketFactory();

      serverSocket = serverSocketFactory.createServerSocket(0);
      executorService.execute(() -> {
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
          // e.printStackTrace();
        }
      });
    } catch (GeneralSecurityException | IOException ex) {
      throw new IllegalStateException("failed to start echoserver", ex);
    }
  }

  public void send(SSLContextProvider provider, String message) {
    send(provider.get(), message);
  }

  public void send(SSLContext context, String message) {
    try (Socket localhost = connect(context)) {
      localhost.getOutputStream().write(message.getBytes());
    } catch (IOException ex) {
      // do nothing, we know there comes a exception
    }
  }

  private Socket connect(SSLContext context) throws IOException {
    return context.getSocketFactory().createSocket(
      "localhost", serverSocket.getLocalPort()
    );
  }

  void close() {
    try {
      serverSocket.close();
    } catch (IOException e) {
      e.printStackTrace();
    }
    executorService.shutdown();
  }

  private SSLContext createSSLContext(KeyManager[] keyManagers) throws GeneralSecurityException {
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(keyManagers, null, null);
    return sslContext;
  }

  private KeyManager[] getKeyManagers(KeyStore keyStore, char[] password) throws GeneralSecurityException {
    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, password);
    return keyManagerFactory.getKeyManagers();
  }
}
