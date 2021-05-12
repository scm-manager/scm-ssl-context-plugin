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

import com.google.common.collect.ImmutableList;
import com.google.inject.util.Providers;
import de.otto.edison.hal.HalRepresentation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import sonia.scm.api.v2.resources.ScmPathInfo;
import sonia.scm.api.v2.resources.ScmPathInfoStore;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

import static com.cloudogu.sslcontext.CertTestUtil.createKeyPair;
import static com.cloudogu.sslcontext.CertTestUtil.createX509Cert;
import static com.cloudogu.sslcontext.Certificate.Status.APPROVED;
import static com.cloudogu.sslcontext.Certificate.Status.REJECTED;
import static org.assertj.core.api.Assertions.assertThat;

class CertificateCollectionMapperTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private final CertificateMapper mapper = new CertificateMapperImpl();

  private CertificateCollectionMapper collectionMapper;


  @BeforeEach
  void initMapper() {
    ScmPathInfo pathInfo = () -> URI.create("scm/api/");
    ScmPathInfoStore scmPathInfoStore = new ScmPathInfoStore();
    scmPathInfoStore.set(pathInfo);
    mapper.scmPathInfoStore = Providers.of(scmPathInfoStore);
    collectionMapper = new CertificateCollectionMapper(mapper, Providers.of(scmPathInfoStore));
  }

  @Test
  void shouldMapCollectionWithSelfLink() throws GeneralSecurityException {
    KeyPair keyPair = createKeyPair();
    X509Certificate cert = createX509Cert(keyPair, Instant.now(), Instant.now());

    Certificate one = createCertificate(cert);
    one.approve();
    Certificate two = createCertificate(cert);

    HalRepresentation dto = collectionMapper.map(ImmutableList.of(one, two));

    assertThat(dto.getLinks().getLinkBy("self")).hasValueSatisfying(link -> {
      assertThat(link.getHref()).isEqualTo("scm/api/v2/ssl-context/");
    });
    assertThat(dto.getEmbedded().hasItem("certificates")).isTrue();

    List<HalRepresentation> certificates = dto.getEmbedded().getItemsBy("certificates");
    assertThat(certificates).hasSize(2);

    CertificateDto firstCertDto = (CertificateDto) certificates.get(0);
    assertThat(firstCertDto.getStatus()).isEqualTo(APPROVED);
    assertThat(firstCertDto.getStatus()).isEqualTo(APPROVED);

    CertificateDto secondCertDto = (CertificateDto) certificates.get(1);
    assertThat(secondCertDto.getStatus()).isEqualTo(REJECTED);
  }

  private Certificate createCertificate(X509Certificate cert) throws CertificateEncodingException {
    return new Certificate(cert.getEncoded(), Certificate.Error.UNKNOWN);
  }

}
