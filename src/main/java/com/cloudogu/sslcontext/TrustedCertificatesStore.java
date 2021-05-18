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

import org.apache.commons.lang.ArrayUtils;
import sonia.scm.store.BlobStore;
import sonia.scm.store.BlobStoreFactory;

import javax.inject.Inject;
import javax.ws.rs.WebApplicationException;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class TrustedCertificatesStore {

  private static final String STORE_NAME = "Trusted_Certificates";
  private static final String NAME = "trusted_certs";

  private final BlobStore store;

  @Inject
  public TrustedCertificatesStore(BlobStoreFactory storeFactory) {
    this.store = storeFactory.withName(STORE_NAME).build();
  }

  X509Certificate[] getAll() {
    try (DataInputStream is = new DataInputStream(store.get(NAME).getInputStream())) {
      byte[] bytes = new byte[1024];
      is.read(bytes);
      return new X509Certificate[]{};
    } catch (IOException e) {
      throw new IllegalStateException("Could not read trusted certificates", e);
    }
  }

  void add(Certificate certificate) {
    X509Certificate x509Certificate = toX509(certificate);
    X509Certificate[] certs = (X509Certificate[]) ArrayUtils.add(getAll(), x509Certificate);

//    store.get(NAME).getOutputStream().write();
  }

  void remove(Certificate certificate) {

  }

  private X509Certificate toX509(Certificate certificate) {
    try {
      return certificate.toX509();
    } catch (CertificateException e) {
      //TODO
      throw new WebApplicationException(e);
    }
  }
}
