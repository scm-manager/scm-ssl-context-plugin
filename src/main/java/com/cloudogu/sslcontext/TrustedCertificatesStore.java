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

import sonia.scm.store.Blob;
import sonia.scm.store.BlobStore;
import sonia.scm.store.BlobStoreFactory;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.function.BiConsumer;

@Singleton
public class TrustedCertificatesStore {

  private static final String STORE_NAME = "Trusted_Certificates";
  private static final String NAME = "trusted_certs";
  private static final char[] PASSWORD = "password".toCharArray();

  private final BlobStore store;

  @Inject
  public TrustedCertificatesStore(BlobStoreFactory storeFactory) {
    this.store = storeFactory.withName(STORE_NAME).build();
  }

  KeyStore getKeyStore() {
    try (InputStream is = getBlob().getInputStream()) {
      KeyStore keyStore = KeyStore.getInstance("JKS");
      if (is.available() > 0) {
        keyStore.load(is, PASSWORD);
      } else {
        keyStore.load(null, PASSWORD);
      }
      return keyStore;
    } catch (IOException | GeneralSecurityException e) {
      //TODO
      throw new IllegalStateException(e);
    }
  }

  void add(Certificate certificate) {
    updateKeyStore(certificate, (ks, cert) -> {
      try {
        ks.load(null);
        ks.setCertificateEntry(certificate.getFingerprint(), toX509(certificate));
      } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
        //TODO
        throw new IllegalStateException(e);
      } catch (IOException e) {
        e.printStackTrace();
      }
    });
  }

  void remove(Certificate certificate) {
    updateKeyStore(certificate, (ks, cert) -> {
      try {
        ks.deleteEntry(cert.getFingerprint());
      } catch (KeyStoreException e) {
        //TODO
        throw new IllegalStateException(e);
      }
    });
  }

  private void updateKeyStore(Certificate certificate, BiConsumer<KeyStore, Certificate> consumer) {
    KeyStore keyStore = getKeyStore();
    try (OutputStream os = getBlob().getOutputStream()) {
      consumer.accept(keyStore, certificate);
      keyStore.store(os, PASSWORD);
    } catch (GeneralSecurityException | IOException e) {
      //TODO
      throw new IllegalStateException(e);
    }
  }

  private X509Certificate toX509(Certificate certificate) {
    try {
      return certificate.toX509();
    } catch (CertificateException e) {
      //TODO
      throw new IllegalStateException(e);
    }
  }

  private Blob getBlob() {
    return store.getOptional(NAME).orElseGet(() -> store.create(NAME));
  }
}
