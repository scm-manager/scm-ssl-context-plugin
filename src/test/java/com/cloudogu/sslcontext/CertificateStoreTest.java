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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import sonia.scm.store.InMemoryDataStore;
import sonia.scm.store.InMemoryDataStoreFactory;

import java.time.Instant;
import java.util.Map;

import static com.cloudogu.sslcontext.Certificate.CertificateError.CERTIFICATE_UNKNOWN;
import static com.cloudogu.sslcontext.Certificate.CertificateStatus.REJECTED;
import static org.assertj.core.api.Assertions.assertThat;

class CertificateStoreTest {

  private CertificateStore certificateStore;

  @BeforeEach
  void initStore() {
    certificateStore = new CertificateStore(new InMemoryDataStoreFactory(new InMemoryDataStore<Certificate>()));
  }

  @Test
  void shouldStoreCert() {
    byte[] encodedCert = "hitchhiker".getBytes();

    certificateStore.put(new Certificate(encodedCert, REJECTED, CERTIFICATE_UNKNOWN, Instant.now()));

    Map<String, Certificate> allCerts = certificateStore.getAll();
    assertThat(allCerts).hasSize(1);
    assertThat(allCerts).containsKey("6ea1ec02523c727c41cb95ee43b4eb14ee7905ea");
    Certificate singleCert = allCerts.values().iterator().next();
    assertThat(singleCert.getCertificate()).isEqualTo(encodedCert);
    assertThat(singleCert.getStatus()).isEqualTo(REJECTED);
    assertThat(singleCert.getCertificateError()).isEqualTo(CERTIFICATE_UNKNOWN);
  }

  @Test
  void shouldNotStoreCertIfAlreadyStored() {
    byte[] encodedCert = "hitchhiker".getBytes();
    Certificate cert = new Certificate(encodedCert, REJECTED, CERTIFICATE_UNKNOWN, Instant.now());
    certificateStore.put(cert);
    certificateStore.put(cert);
    certificateStore.put(cert);

    Map<String, Certificate> allCerts = certificateStore.getAll();
    assertThat(allCerts).hasSize(1);
    assertThat(allCerts).containsKey("6ea1ec02523c727c41cb95ee43b4eb14ee7905ea");
  }
}
