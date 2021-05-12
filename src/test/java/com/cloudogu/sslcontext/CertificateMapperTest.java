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
    ScmPathInfo pathInfo = () -> URI.create("api/");
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
  }

  @Test
  void shouldMapToDtoWithApproveLink() throws IOException {
    URL resource = Resources.getResource("com/cloudogu/sslcontext/cert-001");
    byte[] encoded = Resources.toByteArray(resource);
    Certificate certificate = new Certificate(encoded, UNKNOWN);

    CertificateDto dto = mapper.map(certificate);

    assertThat(dto.getLinks().getLinkBy("approve").get().getHref()).isEqualTo("api/v2/ssl-context/approve/89c6032d1d457cde44478919989a4fc5758aca9d");
    assertThat(dto.getLinks().getLinkBy("reject")).isNotPresent();
  }

  @Test
  void shouldMapToDtoWithRejectLink() throws IOException {
    URL resource = Resources.getResource("com/cloudogu/sslcontext/cert-001");
    byte[] encoded = Resources.toByteArray(resource);
    Certificate certificate = new Certificate(encoded, UNKNOWN);
    certificate.approve();

    CertificateDto dto = mapper.map(certificate);

    assertThat(dto.getLinks().getLinkBy("reject").get().getHref()).isEqualTo("api/v2/ssl-context/reject/89c6032d1d457cde44478919989a4fc5758aca9d");
    assertThat(dto.getLinks().getLinkBy("approve")).isNotPresent();
  }
}
