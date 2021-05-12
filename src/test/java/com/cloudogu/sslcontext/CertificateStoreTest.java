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

import org.apache.shiro.authz.AuthorizationException;
import org.github.sdorra.jse.ShiroExtension;
import org.github.sdorra.jse.SubjectAware;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import sonia.scm.store.InMemoryDataStore;
import sonia.scm.store.InMemoryDataStoreFactory;

import java.util.List;

import static com.cloudogu.sslcontext.Certificate.Error.EXPIRED;
import static com.cloudogu.sslcontext.Certificate.Error.UNKNOWN;
import static com.cloudogu.sslcontext.Certificate.Status.REJECTED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(ShiroExtension.class)
class CertificateStoreTest {

  private CertificateStore certificateStore;

  @BeforeEach
  void initStore() {
    certificateStore = new CertificateStore(new InMemoryDataStoreFactory(new InMemoryDataStore<Certificate>()));
  }

  @Nested
  @SubjectAware(value = "marvin", permissions = "sslContext:read")
  class Permitted {

    @Test
    void shouldStoreCert() {
      byte[] encodedCert = "hitchhiker".getBytes();

      Certificate certificate = new Certificate(encodedCert, UNKNOWN);
      certificateStore.put(certificate);

      List<Certificate> allCerts = certificateStore.getAll();
      assertThat(allCerts).containsOnly(certificate);

      Certificate singleCert = allCerts.iterator().next();
      assertThat(singleCert.getEncoded()).isEqualTo(encodedCert);
      assertThat(singleCert.getStatus()).isEqualTo(REJECTED);
      assertThat(singleCert.getError()).isEqualTo(UNKNOWN);
    }

    @Test
    void shouldNotStoreCertIfAlreadyStored() {
      byte[] encodedCert = "hitchhiker".getBytes();

      Certificate firstReject = new Certificate(encodedCert, UNKNOWN);
      certificateStore.put(firstReject);
      Certificate secondReject = new Certificate(encodedCert, EXPIRED);
      certificateStore.put(secondReject);
      Certificate thirdReject = new Certificate(encodedCert, UNKNOWN);
      certificateStore.put(thirdReject);

      assertThat(certificateStore.getAll().size()).isEqualTo(1);
      assertThat(certificateStore.getAll().get(0).getFingerprint()).isEqualTo("6ea1ec02523c727c41cb95ee43b4eb14ee7905ea");
    }

  }

  @Nested
  @SubjectAware("slarti")
  class Denied {

    @Test
    void shouldNotAllowGetAll() {
      assertThrows(AuthorizationException.class, () -> certificateStore.getAll());
    }

  }
}
