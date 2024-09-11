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

import sonia.scm.store.Blob;
import sonia.scm.store.BlobStore;
import sonia.scm.store.BlobStoreFactory;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

@Singleton
class TrustedCertificatesStore {

  private static final String STORE_NAME = "trust-store";
  private static final String NAME = "trusted_certs";
  private static final char[] PASSWORD = "password".toCharArray();

  private final BlobStore blobStore;
  private final KeyStore keyStore;

  private final List<Consumer<KeyStore>> listeners = new ArrayList<>();

  @Inject
  TrustedCertificatesStore(BlobStoreFactory storeFactory) {
    this.blobStore = storeFactory.withName(STORE_NAME).build();
    this.keyStore = loadKeyStore();
  }

  public void onChange(Consumer<KeyStore> listener) {
    listeners.add(listener);
  }

  private KeyStore loadKeyStore() {
    try {
      KeyStore ks = KeyStore.getInstance("JKS");
      Optional<Blob> optionalBlob = blobStore.getOptional(NAME);
      if (optionalBlob.isPresent()) {
        try (InputStream is = optionalBlob.get().getInputStream()) {
          ks.load(is, PASSWORD);
        }
      } else {
        ks.load(null, PASSWORD);
      }
      return ks;
    } catch (IOException | GeneralSecurityException e) {
      throw new com.cloudogu.sslcontext.CertificateException(
        "Could not load stored trust store",
        e
      );
    }
  }

  void add(Certificate certificate) {
    updateKeyStore(certificate, (ks, cert) -> {
      try {
        ks.setCertificateEntry(certificate.getFingerprint(), toX509(certificate));
      } catch (KeyStoreException e) {
        throw new com.cloudogu.sslcontext.CertificateException(
          "Could not add certificate to stored trust store",
          e
        );
      }
    });
  }

  void remove(Certificate certificate) {
    updateKeyStore(certificate, (ks, cert) -> {
      try {
        ks.deleteEntry(cert.getFingerprint());
      } catch (KeyStoreException e) {
        throw new com.cloudogu.sslcontext.CertificateException(
          "Could not remove certificate from stored trust store",
          e
        );
      }
    });
  }

  private void updateKeyStore(Certificate certificate, BiConsumer<KeyStore, Certificate> consumer) {
    try (OutputStream os = getBlob().getOutputStream()) {
      consumer.accept(keyStore, certificate);
      keyStore.store(os, PASSWORD);
      listeners.forEach(c -> c.accept(keyStore));
    } catch (GeneralSecurityException | IOException e) {
      throw new com.cloudogu.sslcontext.CertificateException(
        "Could not modify stored trust store",
        e
      );
    }
  }

  private X509Certificate toX509(Certificate certificate) {
    try {
      return certificate.toX509();
    } catch (CertificateException e) {
      throw new com.cloudogu.sslcontext.CertificateException(
        "Could not deserialize stored certificate byte array to X509Certificate object",
        e
      );
    }
  }

  private Blob getBlob() {
    return blobStore.getOptional(NAME).orElseGet(() -> blobStore.create(NAME));
  }

  public KeyStore getKeyStore() {
    return keyStore;
  }
}
