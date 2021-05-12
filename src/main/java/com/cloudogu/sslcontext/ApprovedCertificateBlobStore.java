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

import sonia.scm.store.Blob;
import sonia.scm.store.BlobStore;
import sonia.scm.store.BlobStoreFactory;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

@Singleton
class ApprovedCertificateBlobStore {

  private static final String STORE_NAME = "X509_Certificate_Blobs";

  private final BlobStore blobStore;

  @Inject
  public ApprovedCertificateBlobStore(BlobStoreFactory blobStoreFactory) {
    this.blobStore = blobStoreFactory.withName(STORE_NAME).build();;
  }

  public List<Blob> getAll() {
    return blobStore.getAll();
  }

  void store(Certificate certificate) {
    Blob blob = blobStore.create(certificate.getFingerprint());

    try (OutputStream os = blob.getOutputStream()) {
      os.write(certificate.getEncoded());
      os.flush();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  void remove(String id) {
    blobStore.remove(id);
  }

}
