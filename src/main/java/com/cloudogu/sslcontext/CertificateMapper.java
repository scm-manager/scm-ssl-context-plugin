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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static de.otto.edison.hal.Link.link;
import static de.otto.edison.hal.Links.linkingTo;

@Mapper
public abstract class CertificateMapper extends BaseMapper<Certificate, CertificateDto> {

  @Inject
  Provider<ScmPathInfoStore> scmPathInfoStore;

  @Mapping(target = "attributes", ignore = true)
  public abstract CertificateDto map(Certificate certificate);

  @ObjectFactory
  CertificateDto createDto(Certificate certificate) {

    Links links = createLinks(certificate);
    CertificateDto dto = new CertificateDto(links);

    try {
      X509Certificate x509Certificate = certificate.toX509();

      dto.setFingerprint(certificate.getFingerprint());
      dto.setIssuerDN(x509Certificate.getIssuerDN().getName());
      dto.setSubjectDN(x509Certificate.getSubjectDN().getName());
      dto.setNotAfter(x509Certificate.getNotAfter().toInstant());
      dto.setNotBefore(x509Certificate.getNotBefore().toInstant());
      dto.setSignAlg(x509Certificate.getSigAlgName());

    } catch (CertificateException ex) {
      throw new IllegalStateException("Could not resolve stored certificate", ex);
    }

    return dto;
  }

  private Links createLinks(Certificate certificate) {
    Links.Builder linksBuilder = linkingTo();
    if (certificate.getError() == Certificate.Error.UNKNOWN) {
      if (certificate.getStatus() == Certificate.Status.REJECTED) {
        linksBuilder.single(link("approve", createLink("approve", certificate.getFingerprint())));
      } else {
        linksBuilder.single(link("reject", createLink("reject", certificate.getFingerprint())));
      }
    }
    return linksBuilder.build();
  }

  private String createLink(String name, String id) {
    return new LinkBuilder(scmPathInfoStore.get().get(), SSLContextResource.class)
      .method(name)
      .parameters(id)
      .href();
  }
}
