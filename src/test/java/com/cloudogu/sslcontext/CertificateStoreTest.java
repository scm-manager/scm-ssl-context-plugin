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

import org.apache.shiro.authz.AuthorizationException;
import org.github.sdorra.jse.ShiroExtension;
import org.github.sdorra.jse.SubjectAware;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import sonia.scm.store.InMemoryByteDataStoreFactory;

import java.util.List;

import static com.cloudogu.sslcontext.Certificate.Error.EXPIRED;
import static com.cloudogu.sslcontext.Certificate.Error.UNKNOWN;
import static com.cloudogu.sslcontext.Certificate.Status.APPROVED;
import static com.cloudogu.sslcontext.Certificate.Status.REJECTED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;

@ExtendWith({ShiroExtension.class, MockitoExtension.class})
class CertificateStoreTest {

  @Mock
  private TrustedCertificatesStore trustedCertificatesStore;

  private CertificateStore certificateStore;

  @BeforeEach
  void initStore() {
    certificateStore = new CertificateStore(new InMemoryByteDataStoreFactory(), trustedCertificatesStore);
  }

  @Nested
  @SubjectAware(value = "marvin", permissions = "sslContext:read")
  class ReadPermitted {

    @Test
    void shouldStoreCert() {
      byte[] encodedCert = "hitchhiker".getBytes();

      Certificate certificate = new Certificate(encodedCert, UNKNOWN);
      certificateStore.put(certificate);

      List<Certificate> allCerts = certificateStore.getAllRejected();
      assertThat(allCerts).hasSize(1);
      assertThat(allCerts.get(0)).usingRecursiveComparison().isEqualTo(certificate);

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

      assertThat(certificateStore.getAllRejected()).hasSize(1);
      assertThat(certificateStore.getAllRejected().get(0).getFingerprint()).isEqualTo("6ea1ec02523c727c41cb95ee43b4eb14ee7905ea");
    }

    @Test
    void shouldUploadCert() {
      byte[] encodedCert = "hitchhiker".getBytes();

      Certificate certificate = new Certificate(encodedCert, UNKNOWN);
      assertThrows(AuthorizationException.class, () -> certificateStore.upload(certificate));
    }
  }

  @Nested
  @SubjectAware(value = "arthur", permissions = "sslContext:read,write")
  class ReadWritePermitted {

    @Test
    void shouldUploadCert() {
      byte[] encodedCert = "hitchhiker".getBytes();

      Certificate certificate = new Certificate(encodedCert, UNKNOWN);
      certificateStore.upload(certificate);

      assertThat(certificate.getStatus()).isEqualTo(APPROVED);
      List<Certificate> approvedCerts = certificateStore.getAllApproved();
      assertThat(approvedCerts).hasSize(1);
      assertThat(approvedCerts.get(0)).usingRecursiveComparison().isEqualTo(certificate);
    }

    @Test
    void shouldApproveAndRejectCert() {
      byte[] encodedCert = "hitchhiker".getBytes();
      Certificate certificate = new Certificate(encodedCert, UNKNOWN);
      certificateStore.put(certificate);

      certificateStore.approve(certificate.getFingerprint(), certificate.getFingerprint());

      ArgumentCaptor<Certificate> cert = ArgumentCaptor.forClass(Certificate.class);
      verify(trustedCertificatesStore).add(cert.capture());
      assertThat(cert.getValue().getEncoded()).isEqualTo(certificate.getEncoded());
      assertThat(certificateStore.getAllApproved().get(0).getEncoded()).isEqualTo(certificate.getEncoded());

      certificateStore.reject(certificate.getFingerprint(), certificate.getFingerprint());

      verify(trustedCertificatesStore).remove(cert.capture());
      assertThat(cert.getValue().getEncoded()).isEqualTo(certificate.getEncoded());
      assertThat(certificateStore.getAllApproved()).isEmpty();
    }

    @Test
    void shouldRemoveRejectedCert() {
      byte[] encodedCert = "hitchhiker".getBytes();
      Certificate certificate = new Certificate(encodedCert, UNKNOWN);
      certificateStore.put(certificate);

      assertThat(certificateStore.getAllRejected()).hasSize(1);

      certificateStore.removeRejected(certificate.getFingerprint());

      assertThat(certificateStore.getAllRejected()).isEmpty();
    }
  }

  @Nested
  @SubjectAware("slarti")
  class Denied {

    @Test
    void shouldNotAllowGetAll() {
      assertThrows(AuthorizationException.class, () -> certificateStore.getAllRejected());
    }

  }
}
