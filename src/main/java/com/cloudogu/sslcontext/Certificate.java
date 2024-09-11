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

import com.google.common.hash.Hashing;
import lombok.Getter;
import sonia.scm.xml.XmlInstantAdapter;

import javax.annotation.Nullable;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;

@Getter
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Certificate {

  @Nullable
  private Certificate parent;
  private byte[] encoded;

  private Status status;
  private Error error;
  private boolean uploaded = false;
  private String fingerprint;
  @XmlJavaTypeAdapter(XmlInstantAdapter.class)
  private Instant timestamp;

  private Certificate() {}

  public Certificate(byte[] encoded, Error error) {
    this(null, encoded, error);
  }

  public Certificate(@Nullable Certificate parent, byte[] encoded, Error error) {
    this.parent = parent;
    this.encoded = encoded;
    this.error = error;
    this.fingerprint = createFingerprint(encoded);
    this.status = Status.REJECTED;
    this.timestamp = Instant.now();
  }

  @SuppressWarnings({"deprecated", "UnstableApiUsage", "java:S1874"})
  private String createFingerprint(byte[] certificate) {
    return Hashing.sha1().hashBytes(certificate).toString();
  }

  public void approve() {
    if (status == Status.REJECTED) {
      status = Status.APPROVED;
      timestamp = Instant.now();
    } else {
      throw new IllegalStateException("certificate is already approved");
    }
  }

  public void reject() {
    if (status == Status.APPROVED) {
      status = Status.REJECTED;
      timestamp = Instant.now();
    } else {
      throw new IllegalStateException("certificate is already rejected");
    }
  }

  public void setUploaded() {
    this.uploaded = true;
  }

  public X509Certificate toX509() throws CertificateException {
    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(encoded));
  }

  enum Status {
    REJECTED,
    APPROVED
  }

  enum Error {
    UNKNOWN,
    EXPIRED,
    NOT_YET_VALID,
    REVOKED
  }
}
