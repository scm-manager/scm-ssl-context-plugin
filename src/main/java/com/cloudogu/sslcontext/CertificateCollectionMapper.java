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
import de.otto.edison.hal.HalRepresentation;
import sonia.scm.api.v2.resources.LinkBuilder;
import sonia.scm.api.v2.resources.ScmPathInfoStore;

import jakarta.inject.Inject;
import jakarta.inject.Provider;
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
