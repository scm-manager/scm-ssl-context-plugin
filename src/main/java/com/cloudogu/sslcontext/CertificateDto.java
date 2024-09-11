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
import de.otto.edison.hal.Links;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
@SuppressWarnings("java:S2160") // we need not equals for dto's
public class CertificateDto extends HalRepresentation {
  private String parent;
  private String subjectDN;
  private String issuerDN;
  private Instant notBefore;
  private Instant notAfter;
  private String signAlg;
  private String fingerprint;
  private boolean uploaded;

  private Certificate.Status status;
  private Certificate.Error error;
  private Instant timestamp;

  public CertificateDto(Links links, Embedded embedded) {
    super(links, embedded);
  }
}
