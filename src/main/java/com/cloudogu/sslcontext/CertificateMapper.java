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

import de.otto.edison.hal.Links;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ObjectFactory;
import sonia.scm.api.v2.resources.BaseMapper;
import sonia.scm.api.v2.resources.LinkBuilder;
import sonia.scm.api.v2.resources.ScmPathInfoStore;

import javax.inject.Inject;
import javax.inject.Provider;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static de.otto.edison.hal.Link.link;
import static de.otto.edison.hal.Links.emptyLinks;
import static de.otto.edison.hal.Links.linkingTo;

@Mapper
public abstract class CertificateMapper extends BaseMapper<Certificate, CertificateDto> {

  @Inject
  Provider<ScmPathInfoStore> scmPathInfoStore;

  @Mapping(target = "attributes", ignore = true)
  public abstract CertificateDto map(Certificate certificate);

  @ObjectFactory
  CertificateDto createDto(Certificate certificate) {

    // Prepared for the next development iteration
    // Links links = createLinks(certificate);
    CertificateDto dto = new CertificateDto(emptyLinks());

    try {
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
      X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certificate.getCertificate()));

      dto.setFingerprint(certificate.getFingerprint());
      dto.setIssuerDN(cert.getIssuerDN().getName());
      dto.setSubjectDN(cert.getSubjectDN().getName());
      dto.setNotAfter(cert.getNotAfter().toInstant());
      dto.setNotBefore(cert.getNotBefore().toInstant());
      dto.setSignAlg(cert.getSigAlgName());

    } catch (CertificateException ex) {
      throw new IllegalStateException("Could not resolve stored certificate", ex);
    }

    return dto;
  }

  private Links createLinks(Certificate certificate) {
    Links.Builder linksBuilder = linkingTo();
    if (certificate.getCertificateError() == Certificate.CertificateError.CERTIFICATE_UNKNOWN) {
      if (certificate.getStatus() == Certificate.CertificateStatus.REJECTED) {
        linksBuilder.single(link("approve", createLink("approve")));
      } else {
        linksBuilder.single(link("reject", createLink("reject")));
      }
    }
    return linksBuilder.build();
  }

  private String createLink(String name) {
    return new LinkBuilder(scmPathInfoStore.get().get(), SSLContextResource.class)
      .method(name)
      .parameters()
      .href();
  }
}
