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

  @SuppressWarnings("UnstableApiUsage")
  private Certificate readCertificate(String path) throws IOException {
    URL resource = Resources.getResource(path);
    byte[] encoded = Resources.toByteArray(resource);
    return new Certificate(null, encoded, Certificate.Error.UNKNOWN);
  }
}
