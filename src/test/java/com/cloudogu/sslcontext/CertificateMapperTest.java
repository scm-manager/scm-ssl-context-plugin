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

import com.google.common.io.Resources;
import com.google.inject.util.Providers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import sonia.scm.api.v2.resources.ScmPathInfo;
import sonia.scm.api.v2.resources.ScmPathInfoStore;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;

import static com.cloudogu.sslcontext.CertTestUtil.createKeyPair;
import static com.cloudogu.sslcontext.CertTestUtil.createX509Cert;
import static com.cloudogu.sslcontext.Certificate.Error.EXPIRED;
import static com.cloudogu.sslcontext.Certificate.Error.UNKNOWN;
import static com.cloudogu.sslcontext.Certificate.Status.REJECTED;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class CertificateMapperTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private final CertificateMapper mapper = new CertificateMapperImpl();

  @BeforeEach
  void initMapper() {
    ScmPathInfo pathInfo = () -> URI.create("api/v2/");
    ScmPathInfoStore scmPathInfoStore = new ScmPathInfoStore();
    scmPathInfoStore.set(pathInfo);
    mapper.scmPathInfoStore = Providers.of(scmPathInfoStore);
  }

  @Test
  @SuppressWarnings("UnstableApiUsage")
  void shouldMapToDto() throws IOException {
    URL resource = Resources.getResource("com/cloudogu/sslcontext/cert-001");
    byte[] encoded = Resources.toByteArray(resource);

    Certificate certificate = new Certificate(encoded, UNKNOWN);

    CertificateDto dto = mapper.map(certificate);

    assertThat(dto.getFingerprint()).isEqualTo("89c6032d1d457cde44478919989a4fc5758aca9d");
    assertThat(dto.getIssuerDN()).isEqualTo("C=c, ST=il, L=L, O=hitchhiker.org, CN=localhost");
    assertThat(dto.getSubjectDN()).isEqualTo("C=c, ST=il, L=L, O=hitchhiker.org, CN=localhost");
    assertThat(dto.getSignAlg()).isEqualTo("SHA256withRSA");
    assertThat(dto.getEmbedded().hasItem("chain")).isTrue();
  }

  @Test
  @SuppressWarnings("UnstableApiUsage")
  void shouldMapNestedChainCertsToDto() throws IOException {
    URL resource1 = Resources.getResource("com/cloudogu/sslcontext/cert-001");
    URL resource2 = Resources.getResource("com/cloudogu/sslcontext/cert-002-expired");

    byte[] parentEncoded = Resources.toByteArray(resource1);
    Certificate parent = new Certificate(parentEncoded, UNKNOWN);

    byte[] certEncoded = Resources.toByteArray(resource2);
    Certificate certificate = new Certificate(parent, certEncoded, EXPIRED);

    CertificateDto dto = mapper.map(certificate);

    assertThat(dto.getParent()).isEqualTo("89c6032d1d457cde44478919989a4fc5758aca9d");
    assertThat(dto.getFingerprint()).isEqualTo("404bbd2f1f4cc2fdeef13aabdd523ef61f1c71f3");
    assertThat(dto.getIssuerDN()).isEqualTo("CN=COMODO RSA Domain Validation Secure Server CA, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB");
    assertThat(dto.getSubjectDN()).isEqualTo("CN=*.badssl.com, OU=PositiveSSL Wildcard, OU=Domain Control Validated");
    assertThat(dto.getSignAlg()).isEqualTo("SHA256withRSA");
    assertThat(dto.getEmbedded().getItemsBy("chain").size()).isEqualTo(1);
    assertThat(((CertificateDto)dto.getEmbedded().getItemsBy("chain").get(0)).getFingerprint()).isEqualTo("89c6032d1d457cde44478919989a4fc5758aca9d");
  }

// Prepared for the next development iteration
//  @Test
//  void shouldMapToDtoWithApproveLink() throws GeneralSecurityException {
//    X509Certificate cert = createX509Cert(createKeyPair(),0, 0);
//    Certificate certificate = new Certificate(cert.getEncoded(), REJECTED, CERTIFICATE_UNKNOWN, Instant.now());
//
//    CertificateDto dto = mapper.map(certificate);
//
//    assertThat(dto.getLinks().getLinkBy("approve").get().getHref()).isEqualTo("");
//    assertThat(dto.getLinks().getLinkBy("reject")).isNotPresent();
//
//  }
//
//  @Test
//  void shouldMapToDtoWithRejectLink() throws GeneralSecurityException {
//    X509Certificate cert = createX509Cert(createKeyPair(),0, 0);
//    Certificate certificate = new Certificate(cert.getEncoded(), APPROVED, CERTIFICATE_UNKNOWN, Instant.now());
//
//    CertificateDto dto = mapper.map(certificate);
//
//    assertThat(dto.getLinks().getLinkBy("reject").get().getHref()).isEqualTo("");
//    assertThat(dto.getLinks().getLinkBy("approve")).isNotPresent();
//  }
}
