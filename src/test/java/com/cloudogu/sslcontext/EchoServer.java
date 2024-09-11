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
