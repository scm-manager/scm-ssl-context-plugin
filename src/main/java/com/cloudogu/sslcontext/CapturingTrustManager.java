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

import javax.inject.Inject;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
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
  public CapturingTrustManager(CertificateStore store) {
    this(store, null);
  }

  CapturingTrustManager(CertificateStore store, X509TrustManager delegate) {
    this.store = store;
    this.delegate = delegate != null ? delegate : createDefaultDelegate();
  }

  private X509TrustManager createDefaultDelegate() {
    TrustManagerFactory trustManagerFactory;
    try {
      trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      trustManagerFactory.init(store.getKeyStore());
    } catch (NoSuchAlgorithmException | KeyStoreException e) {
      throw new IllegalStateException("Could not find default trust manager", e);
    }
    return (X509TrustManager) trustManagerFactory.getTrustManagers()[0];
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
