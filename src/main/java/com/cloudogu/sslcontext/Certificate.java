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

import lombok.Getter;
import lombok.Setter;
import sonia.scm.xml.XmlInstantAdapter;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.time.Instant;

@Getter
@Setter
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Certificate {
  private byte[] certificate;
  private CertificateStatus status;
  private CertificateError certificateError;
  private String fingerprint;
  @XmlJavaTypeAdapter(XmlInstantAdapter.class)
  private Instant timestamp;

  private Certificate() {
  }

  public Certificate(byte[] certificate, CertificateStatus status, CertificateError certificateError, Instant timestamp) {
    this.certificate = certificate;
    this.status = status;
    this.certificateError = certificateError;
    this.timestamp = timestamp;
  }

  public Certificate(String fingerprint, byte[] certificate, CertificateStatus status, CertificateError certificateError, Instant timestamp) {
    this(certificate, status, certificateError, timestamp);
    this.fingerprint = fingerprint;
  }

  enum CertificateStatus {
    REJECTED,
    APPROVED
  }

  enum CertificateError {
    CERTIFICATE_UNKNOWN,
    CERTIFICATE_EXPIRED,
    CERTIFICATE_NOT_YET_VALID,
    CERTIFICATE_REVOKED
  }
}
