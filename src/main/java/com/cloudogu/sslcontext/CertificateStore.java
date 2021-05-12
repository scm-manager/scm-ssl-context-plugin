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

import org.apache.shiro.SecurityUtils;
import sonia.scm.NotFoundException;
import sonia.scm.store.DataStore;
import sonia.scm.store.DataStoreFactory;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.Map;
import java.util.function.Consumer;

@Singleton
public class CertificateStore {

  private static final String STORE_NAME = "X509_certificates";

  private final DataStore<Certificate> store;
  private final ApprovedCertificateBlobStore blobStore;

  @Inject
  public CertificateStore(DataStoreFactory dataStoreFactory, ApprovedCertificateBlobStore blobStore) {
    this.store = dataStoreFactory.withType(Certificate.class).withName(STORE_NAME).build();
    this.blobStore = blobStore;
  }

  public Map<String, Certificate> getAll() {
    SecurityUtils.getSubject().checkPermission("sslcontext:read");
    return store.getAll();
  }

  void put(Certificate certificate) {
    Map<String, Certificate> allCerts = getAll();
    if (!allCerts.containsKey(certificate.getFingerprint())) {
      store.put(certificate.getFingerprint(), certificate);
    }
  }

  public void approve(String id) {
    Certificate certificate = changeStatus(id, Certificate::approve);
    blobStore.store(certificate);
  }

  public void reject(String id) {
    Certificate certificate = changeStatus(id, Certificate::reject);
    blobStore.remove(certificate.getFingerprint());
  }

  private Certificate changeStatus(String id, Consumer<Certificate> consumer) {
    SecurityUtils.getSubject().checkPermission("sslcontext:write");

    Certificate certificate = store.get(id);
    if (certificate == null) {
      throw new NotFoundException(Certificate.class, id);
    }
    consumer.accept(certificate);
    store.put(id, certificate);
    return certificate;
  }
}
