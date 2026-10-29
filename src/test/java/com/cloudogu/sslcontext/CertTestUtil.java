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

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

public class CertTestUtil {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private CertTestUtil() {}

  static KeyPair createKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048, new SecureRandom());
    return keyPairGenerator.generateKeyPair();
  }

  static X509Certificate createX509Cert(KeyPair keyPair, Instant start, Instant end) throws GeneralSecurityException {
    X509Principal subject = new X509Principal("CN=localhost, O=hitchhiker.org, L=L, ST=il, C= c");
    return certificateGenerator(keyPair, start, end, subject, subject).generateX509Certificate(keyPair.getPrivate());
  }

  static X509Certificate createIssuerCertificate(KeyPair keyPair, Instant start, Instant end) throws GeneralSecurityException {
    X509Principal subject = new X509Principal("CN=Test CA");
    X509V3CertificateGenerator generator = certificateGenerator(keyPair, start, end, subject, subject);
    generator.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
    return generator.generateX509Certificate(keyPair.getPrivate());
  }

  static X509Certificate createX509Cert(KeyPair keyPair, Instant start, Instant end,
                                       X509Certificate issuer, PrivateKey issuerKey) throws GeneralSecurityException {
    X509Principal subject = new X509Principal("CN=localhost");
    X509Principal issuerName = new X509Principal(issuer.getSubjectX500Principal().getName());
    return certificateGenerator(keyPair, start, end, subject, issuerName).generateX509Certificate(issuerKey);
  }

  private static X509V3CertificateGenerator certificateGenerator(KeyPair keyPair, Instant start, Instant end,
                                                                X509Principal subject, X509Principal issuer) {
    X509V3CertificateGenerator v3CertGen = new X509V3CertificateGenerator();
    v3CertGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
    v3CertGen.setIssuerDN(issuer);
    v3CertGen.setNotBefore(Date.from(start));
    v3CertGen.setNotAfter(Date.from(end));
    v3CertGen.setSubjectDN(subject);
    v3CertGen.setPublicKey(keyPair.getPublic());
    v3CertGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
    return v3CertGen;
  }
}
