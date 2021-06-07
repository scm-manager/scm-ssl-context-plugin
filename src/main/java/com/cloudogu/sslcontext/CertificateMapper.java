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
import java.util.ArrayList;
import java.util.List;

import static de.otto.edison.hal.Embedded.emptyEmbedded;
import static de.otto.edison.hal.Link.link;
import static de.otto.edison.hal.Links.linkingTo;

@Mapper
public abstract class CertificateMapper extends BaseMapper<Certificate, CertificateDto> {

  @Inject
  Provider<ScmPathInfoStore> scmPathInfoStore;

  @Mapping(target = "subjectDN", ignore = true)
  @Mapping(target = "signAlg", ignore = true)
  @Mapping(target = "notBefore", ignore = true)
  @Mapping(target = "notAfter", ignore = true)
  @Mapping(target = "issuerDN", ignore = true)
  @Mapping(target = "attributes", ignore = true)
  @Mapping(target = "parent", ignore = true)
  public abstract CertificateDto map(Certificate certificate);

  @ObjectFactory
  CertificateDto createDto(Certificate certificate) {
    Links links = createLinks(certificate, certificate.getFingerprint());
    List<CertificateDto> chainCerts = mapChainCerts(certificate);

    CertificateDto dto = new CertificateDto(links, Embedded.embeddedBuilder().with("chain", chainCerts).build());
    if (!chainCerts.isEmpty()) {
      dto.setParent(chainCerts.get(0).getFingerprint());
    }
    setCertFieldsToDto(certificate, dto);

    return dto;
  }

  private List<CertificateDto> mapChainCerts(Certificate certificate) {
    List<CertificateDto> chainCerts = new ArrayList<>();

    Certificate chainCert = certificate.getParent();
    while (chainCert != null) {
      CertificateDto chainCertDto = new CertificateDto(createLinks(chainCert, certificate.getFingerprint()), emptyEmbedded());
      chainCertDto.setParent(certificate.getFingerprint());
      chainCertDto.setStatus(certificate.getStatus());
      chainCertDto.setError(certificate.getError());
      chainCertDto.setTimestamp(certificate.getTimestamp());
      setCertFieldsToDto(chainCert, chainCertDto);
      chainCerts.add(chainCertDto);
      chainCert = chainCert.getParent();
    }
    return chainCerts;
  }

  private void setCertFieldsToDto(Certificate certificate, CertificateDto dto) {
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
  }

  private Links createLinks(Certificate certificate, String storedId) {
    Links.Builder linksBuilder = linkingTo();
    if (certificate.getError() == Certificate.Error.UNKNOWN) {
      if (certificate.getStatus() == Certificate.Status.REJECTED) {
        linksBuilder.single(link("approve", createLink("approve", storedId, certificate.getFingerprint())));
      } else {
        linksBuilder.single(link("reject", createLink("reject", storedId, certificate.getFingerprint())));
      }
    }
    return linksBuilder.build();
  }

  private String createLink(String name, String parentId, String id) {
    return new LinkBuilder(scmPathInfoStore.get().get(), SSLContextResource.class)
      .method(name)
      .parameters(parentId, id)
      .href();
  }
}
