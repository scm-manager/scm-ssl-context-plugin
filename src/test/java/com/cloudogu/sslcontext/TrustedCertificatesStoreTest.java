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

import com.google.common.io.Resources;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;

import static org.assertj.core.api.Assertions.assertThat;

class TrustedCertificatesStoreTest {

  private TrustedCertificatesStore store;

  @BeforeEach
  void initStore() {
    store = new TrustedCertificatesStore(new InMemoryBlobStoreFactory(new InMemoryBlobStore()));
  }

  @Test
  void shouldAddTrustedCertToKeyStore() throws IOException, KeyStoreException {
    Certificate certificate = readCertificate("com/cloudogu/sslcontext/cert-001");
    KeyStore keyStore = store.getKeyStore();

    assertThat(keyStore.containsAlias(certificate.getFingerprint())).isFalse();

    store.add(certificate);

    assertThat(keyStore.containsAlias(certificate.getFingerprint())).isTrue();
  }

  @Test
  void shouldRemoveTrustedCertFromKeyStore() throws IOException, KeyStoreException {
    Certificate certificate = readCertificate("com/cloudogu/sslcontext/cert-001");
    KeyStore keyStore = store.getKeyStore();

    store.add(certificate);
    assertThat(keyStore.containsAlias(certificate.getFingerprint())).isTrue();

    store.remove(certificate);
    assertThat(keyStore.containsAlias(certificate.getFingerprint())).isFalse();
  }

  @SuppressWarnings("UnstableApiUsage")
  private Certificate readCertificate(String path) throws IOException {
    URL resource = Resources.getResource(path);
    byte[] encoded = Resources.toByteArray(resource);
    return new Certificate(null, encoded, Certificate.Error.UNKNOWN);
  }
}
