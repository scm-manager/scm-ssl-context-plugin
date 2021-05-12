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
import org.apache.shiro.authz.AuthorizationException;
import org.github.sdorra.jse.ShiroExtension;
import org.github.sdorra.jse.SubjectAware;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import sonia.scm.NotFoundException;
import sonia.scm.store.InMemoryDataStore;
import sonia.scm.store.InMemoryDataStoreFactory;

import java.io.IOException;
import java.net.URL;
import java.util.Map;

import static com.cloudogu.sslcontext.Certificate.Error.UNKNOWN;
import static com.cloudogu.sslcontext.Certificate.Status.APPROVED;
import static com.cloudogu.sslcontext.Certificate.Status.REJECTED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(ShiroExtension.class)
class CertificateStoreTest {

  private CertificateStore certificateStore;

  @BeforeEach
  void initStore() {
    certificateStore = new CertificateStore(new InMemoryDataStoreFactory(new InMemoryDataStore<Certificate>()), blobStore);
  }

  @Nested
  @SubjectAware(value = "marvin", permissions = "sslContext:read")
  class WithReadPermission {

    @Test
    void shouldStoreCert() {
      byte[] encodedCert = "hitchhiker".getBytes();

      certificateStore.put(new Certificate(encodedCert, UNKNOWN));

      Map<String, Certificate> allCerts = certificateStore.getAll();
      assertThat(allCerts)
        .hasSize(1)
        .containsKey("6ea1ec02523c727c41cb95ee43b4eb14ee7905ea");

      Certificate singleCert = allCerts.values().iterator().next();
      assertThat(singleCert.getEncoded()).isEqualTo(encodedCert);
      assertThat(singleCert.getStatus()).isEqualTo(REJECTED);
      assertThat(singleCert.getError()).isEqualTo(UNKNOWN);
    }

    @Test
    void shouldNotStoreCertIfAlreadyStored() {
      byte[] encodedCert = "hitchhiker".getBytes();
      Certificate cert = new Certificate(encodedCert, UNKNOWN);
      certificateStore.put(cert);
      certificateStore.put(cert);
      certificateStore.put(cert);

      Map<String, Certificate> allCerts = certificateStore.getAll();
      assertThat(allCerts)
        .hasSize(1)
        .containsKey("6ea1ec02523c727c41cb95ee43b4eb14ee7905ea");
    }

  }

  @Nested
  @SubjectAware(value = "arthur", permissions = "sslContext:read,write")
  class WithWritePermission {

    @Test
    void shouldThrowNotFoundExceptionOnApprove() {
      assertThrows(NotFoundException.class, () -> certificateStore.approve("42"));
    }

    @Test
    void shouldThrowNotFoundExceptionOnReject() {
      assertThrows(NotFoundException.class, () -> certificateStore.reject("42"));
    }

    @Test
    void shouldApproveAndRejectCertificate() throws IOException {
      String fingerprint = "89c6032d1d457cde44478919989a4fc5758aca9d";
      URL resource = Resources.getResource("com/cloudogu/sslcontext/cert-001");
      byte[] encoded = Resources.toByteArray(resource);
      certificateStore.put(new Certificate(encoded, UNKNOWN));

      certificateStore.approve(fingerprint);

      Certificate storedCert = getStoredCertById(fingerprint);
      assertThat(storedCert.getEncoded()).isEqualTo(encoded);
      assertThat(storedCert.getStatus()).isEqualTo(APPROVED);

      certificateStore.reject(fingerprint);

      storedCert = getStoredCertById(fingerprint);
      assertThat(storedCert.getEncoded()).isEqualTo(encoded);
      assertThat(storedCert.getStatus()).isEqualTo(REJECTED);
    }
  }

  private Certificate getStoredCertById(String id) {
    Certificate storedCert = certificateStore
      .getAll()
      .entrySet()
      .stream()
      .filter(e -> e.getKey().equals(id))
      .findFirst()
      .get()
      .getValue();
    return storedCert;
  }

  @Nested
  @SubjectAware("slarti")
  class WithoutPermission {

    @Test
    void shouldNotAllowGetAll() {
      assertThrows(AuthorizationException.class, () -> certificateStore.getAll());
    }

  }
}
