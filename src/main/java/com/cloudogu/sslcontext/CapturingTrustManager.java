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

import jakarta.inject.Inject;
import jakarta.inject.Named;
import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateRevokedException;
import java.security.cert.X509Certificate;

import static com.cloudogu.sslcontext.Certificate.Error.EXPIRED;
import static com.cloudogu.sslcontext.Certificate.Error.NOT_YET_VALID;
import static com.cloudogu.sslcontext.Certificate.Error.REVOKED;
import static com.cloudogu.sslcontext.Certificate.Error.UNKNOWN;

public class CapturingTrustManager implements X509TrustManager {

  private final X509TrustManager delegate;
  private final CertificateStore store;

  @Inject
  public CapturingTrustManager(CertificateStore store, @Named("chain") X509TrustManager delegate) {
    this.store = store;
    this.delegate = delegate;
  }

  @Override
  public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
    try {
      delegate.checkClientTrusted(x509Certificates, s);
    } catch (CertificateException ex) {
      storeRejectedCerts(x509Certificates, error(ex));
      throw ex;
    }
  }

  @Override
  public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
    try {
      delegate.checkServerTrusted(x509Certificates, s);
    } catch (CertificateException ex) {
      storeRejectedCerts(x509Certificates, error(ex));
      throw ex;
    }
  }

  private Certificate.Error error(Throwable ex) {
    if (ex instanceof CertificateExpiredException) {
      return EXPIRED;
    } else if (ex instanceof CertificateNotYetValidException) {
      return NOT_YET_VALID;
    } else if (ex instanceof CertificateRevokedException) {
      return REVOKED;
    }
    Throwable cause = ex.getCause();
    if (cause != null) {
      return error(cause);
    }
    return UNKNOWN;
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return delegate.getAcceptedIssuers();
  }

  private void storeRejectedCerts(X509Certificate[] x509Certificates, Certificate.Error error) throws CertificateEncodingException {
    Certificate mainCertificate = wrapNestedCerts(x509Certificates, error);
    store.put(mainCertificate);
  }

  private Certificate wrapNestedCerts(X509Certificate[] x509Certificates, Certificate.Error error) throws CertificateEncodingException {
    Certificate certificate = null;
    for (int i = x509Certificates.length - 1; i >= 0; i--) {
      certificate = new Certificate(certificate, x509Certificates[i].getEncoded(), error);
    }
    return certificate;
  }
}
