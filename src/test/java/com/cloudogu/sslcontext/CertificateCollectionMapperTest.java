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

import com.google.common.collect.ImmutableList;
import com.google.inject.util.Providers;
import de.otto.edison.hal.HalRepresentation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.github.sdorra.jse.ShiroExtension;
import org.github.sdorra.jse.SubjectAware;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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

@SubjectAware(value = "trillian", permissions = "sslContext:read,write")
@ExtendWith(ShiroExtension.class)
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

    HalRepresentation dto = collectionMapper.map(ImmutableList.of(one, two), REJECTED);

    assertThat(dto.getLinks().getLinkBy("self")).hasValueSatisfying(link -> {
      assertThat(link.getHref()).isEqualTo("scm/api/v2/ssl-context/rejected");
    });
    assertThat(dto.getEmbedded().hasItem("chain")).isTrue();

    List<HalRepresentation> certificates = dto.getEmbedded().getItemsBy("chain");
    assertThat(certificates).hasSize(2);

    CertificateDto firstCertDto = (CertificateDto) certificates.get(0);
    assertThat(firstCertDto.getStatus()).isEqualTo(APPROVED);

    CertificateDto secondCertDto = (CertificateDto) certificates.get(1);
    assertThat(secondCertDto.getStatus()).isEqualTo(REJECTED);
  }

  private Certificate createCertificate(X509Certificate cert) throws CertificateEncodingException {
    return new Certificate(cert.getEncoded(), Certificate.Error.UNKNOWN);
  }

}
