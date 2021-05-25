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

import com.google.common.collect.ImmutableList;
import org.apache.shiro.SecurityUtils;
import sonia.scm.store.DataStore;
import sonia.scm.store.DataStoreFactory;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.List;
import java.util.function.Consumer;

@Singleton
public class CertificateStore {

  private static final String REJECTED_STORE_NAME = "Rejected_X509_certificates";
  private static final String APPROVED_STORE_NAME = "Approved_X509_certificates";

  private final DataStore<Certificate> rejectedCertStore;
  private final DataStore<Certificate> approvedCertStore;
  private final TrustedCertificatesStore trustedCertificatesStore;

  @Inject
  public CertificateStore(DataStoreFactory dataStoreFactory, TrustedCertificatesStore trustedCertificatesStore) {
    this.rejectedCertStore = dataStoreFactory.withType(Certificate.class).withName(REJECTED_STORE_NAME).build();
    this.approvedCertStore = dataStoreFactory.withType(Certificate.class).withName(APPROVED_STORE_NAME).build();
    this.trustedCertificatesStore = trustedCertificatesStore;
  }

  public List<Certificate> getAllRejected() {
    SecurityUtils.getSubject().checkPermission("sslcontext:read");
    return ImmutableList.copyOf(rejectedCertStore.getAll().values());
  }

  public List<Certificate> getAllApproved() {
    SecurityUtils.getSubject().checkPermission("sslcontext:read");
    return ImmutableList.copyOf(approvedCertStore.getAll().values());
  }

  void put(Certificate certificate) {
    rejectedCertStore.put(certificate.getFingerprint(), certificate);
  }

  public void approve(String storedId, String fingerprint) {
    manageCertificates(storedId, fingerprint, certificate -> {
      certificate.approve();
      certificate.updateTimestamp();
      approvedCertStore.put(certificate.getFingerprint(), certificate);
      trustedCertificatesStore.add(certificate);
    });
  }

  public void reject(String storedId, String fingerprint) {
    manageCertificates(storedId, fingerprint, certificate -> {
      approvedCertStore.remove(certificate.getFingerprint());
      trustedCertificatesStore.remove(certificate);
    });
  }

  private void manageCertificates(String storedId, String fingerprint, Consumer<Certificate> consumer) {
    SecurityUtils.getSubject().checkPermission("sslContext:write");
    Certificate certificate = rejectedCertStore.get(storedId);
    while (certificate != null) {
      if (fingerprint.equals(certificate.getFingerprint())) {
        consumer.accept(certificate);
        break;
      }
      certificate = certificate.getParent();
    }
  }
}
