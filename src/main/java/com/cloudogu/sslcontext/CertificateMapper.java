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

import de.otto.edison.hal.Embedded;
import de.otto.edison.hal.Links;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ObjectFactory;
import sonia.scm.api.v2.resources.BaseMapper;
import sonia.scm.api.v2.resources.LinkBuilder;
import sonia.scm.api.v2.resources.ScmPathInfoStore;

import jakarta.inject.Inject;
import jakarta.inject.Provider;
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
    if (PermissionChecker.mayManageSSLContext()) {
      if (certificate.getStatus() == Certificate.Status.REJECTED) {
        linksBuilder.single(link("remove", createLink("removeRejected", storedId)));
        if (certificate.getError() == Certificate.Error.UNKNOWN) {
          linksBuilder.single(link("approve", createLink("approve", storedId, certificate.getFingerprint())));
        }
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

  private String createLink(String name, String id) {
    return new LinkBuilder(scmPathInfoStore.get().get(), SSLContextResource.class)
      .method(name)
      .parameters(id)
      .href();
  }
}
