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

import de.otto.edison.hal.Embedded;
import de.otto.edison.hal.HalRepresentation;
import sonia.scm.api.v2.resources.LinkBuilder;
import sonia.scm.api.v2.resources.ScmPathInfoStore;

import javax.inject.Inject;
import javax.inject.Provider;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import static de.otto.edison.hal.Links.linkingTo;

public class CertificateCollectionMapper {

  private final CertificateMapper mapper;
  private final Provider<ScmPathInfoStore> scmPathInfoStore;

  @Inject
  public CertificateCollectionMapper(CertificateMapper mapper, Provider<ScmPathInfoStore> scmPathInfoStore) {
    this.mapper = mapper;
    this.scmPathInfoStore = scmPathInfoStore;
  }

  public HalRepresentation map(Collection<Certificate> certificates, Certificate.Status status) {
    List<CertificateDto> dtos = certificates.stream().map(mapper::map).collect(Collectors.toList());
    return new HalRepresentation(linkingTo().self(selfLink(status)).build(), Embedded.embedded("chain", dtos));
  }

  private String selfLink(Certificate.Status status) {
    return new LinkBuilder(scmPathInfoStore.get().get(), SSLContextResource.class)
      .method(resolveLinkMethodName(status))
      .parameters()
      .href();
  }

  private String resolveLinkMethodName(Certificate.Status status) {
    return status == Certificate.Status.REJECTED ? "getAllRejected" : "getAllApproved";
  }
}
