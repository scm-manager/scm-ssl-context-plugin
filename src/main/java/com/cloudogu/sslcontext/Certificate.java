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

import com.google.common.hash.Hashing;
import lombok.Getter;
import sonia.scm.xml.XmlInstantAdapter;

import javax.annotation.Nullable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
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
