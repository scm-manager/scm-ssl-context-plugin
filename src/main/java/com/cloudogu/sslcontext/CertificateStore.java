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

import com.google.common.hash.Hashing;
import sonia.scm.store.DataStore;
import sonia.scm.store.DataStoreFactory;

import javax.inject.Inject;
import java.util.Map;

public class CertificateStore {

  private static final String STORE_NAME = "X509_certificates";

  private final DataStore<Certificate> store;

  @Inject
  public CertificateStore(DataStoreFactory dataStoreFactory) {
    this.store = dataStoreFactory.withType(Certificate.class).withName(STORE_NAME).build();;
  }

  public Map<String, Certificate> getAll() {
    return store.getAll();
  }

  public void put(Certificate certificate) {
    String fingerprint = Hashing.sha1().hashBytes(certificate.getCertificate()).toString();
    Map<String, Certificate> allCerts = getAll();
    certificate.setFingerprint(fingerprint);

    if (!allCerts.containsKey(fingerprint)) {
      store.put(fingerprint, certificate);
    }
  }
}
