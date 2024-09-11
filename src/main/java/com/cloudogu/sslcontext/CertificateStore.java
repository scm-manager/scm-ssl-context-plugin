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

import com.google.common.collect.ImmutableList;
import sonia.scm.store.DataStore;
import sonia.scm.store.DataStoreFactory;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.List;
import java.util.function.Consumer;

@Singleton
public class CertificateStore {

  private static final String REJECTED_STORE_NAME = "rejected-certificates";
  private static final String APPROVED_STORE_NAME = "approved-certificates";

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
    PermissionChecker.checkReadSSLContext();
    return ImmutableList.copyOf(rejectedCertStore.getAll().values());
  }

  public List<Certificate> getAllApproved() {
    PermissionChecker.checkReadSSLContext();
    return ImmutableList.copyOf(approvedCertStore.getAll().values());
  }

  void put(Certificate certificate) {
    rejectedCertStore.put(certificate.getFingerprint(), certificate);
  }

  public void upload(Certificate certificate) {
    PermissionChecker.checkManageSSLContext();
    certificate.setUploaded();
    approveCertificate(certificate);
  }

  public void approve(String serverCertFingerprint, String fingerprint) {
    manageCertificates(serverCertFingerprint, fingerprint, rejectedCertStore, this::approveCertificate);
  }

  private void approveCertificate(Certificate certificate) {
    certificate.approve();
    approvedCertStore.put(certificate.getFingerprint(), certificate);
    trustedCertificatesStore.add(certificate);
    if (rejectedCertStore.get(certificate.getFingerprint()) != null) {
      rejectedCertStore.remove(certificate.getFingerprint());
    }
  }

  public void reject(String serverCertFingerprint, String fingerprint) {
    manageCertificates(serverCertFingerprint, fingerprint, approvedCertStore, certificate -> {
      certificate.reject();
      rejectedCertStore.put(certificate.getFingerprint(), certificate);
      approvedCertStore.remove(certificate.getFingerprint());
      trustedCertificatesStore.remove(certificate);
    });
  }

  public void removeRejected(String id) {
    PermissionChecker.checkManageSSLContext();
    rejectedCertStore.remove(id);
  }

  private void manageCertificates(String serverCertFingerprint, String fingerprint, DataStore<Certificate> store, Consumer<Certificate> consumer) {
    PermissionChecker.checkManageSSLContext();
    Certificate certificate = store.get(serverCertFingerprint);
    while (certificate != null) {
      if (fingerprint.equals(certificate.getFingerprint())) {
        consumer.accept(certificate);
        break;
      }
      certificate = certificate.getParent();
    }
  }
}
