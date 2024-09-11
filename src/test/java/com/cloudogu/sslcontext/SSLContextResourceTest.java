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

import com.google.common.io.Resources;
import org.github.sdorra.jse.ShiroExtension;
import org.github.sdorra.jse.SubjectAware;
import org.jboss.resteasy.mock.MockHttpRequest;
import org.jboss.resteasy.mock.MockHttpResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import sonia.scm.web.RestDispatcher;

import jakarta.ws.rs.core.MediaType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.RandomAccessFile;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(ShiroExtension.class)
@ExtendWith(MockitoExtension.class)
@SubjectAware(
  value = "trillian"
)
class SSLContextResourceTest {

  @Mock
  private CertificateStore store;
  @Mock
  private CertificateCollectionMapper collectionMapper;

  private RestDispatcher dispatcher;
  private final MockHttpResponse response = new MockHttpResponse();

  @BeforeEach
  void initResource() {
    SSLContextResource resource = new SSLContextResource(store, collectionMapper);
    dispatcher = new RestDispatcher();
    dispatcher.addSingletonResource(resource);
  }

  @Test
  void shouldGetRejectedCerts() throws URISyntaxException {
    MockHttpRequest request = MockHttpRequest
      .get("/v2/ssl-context/rejected")
      .contentType(SSLContextResource.MEDIA_TYPE);

    dispatcher.invoke(request, response);

    assertThat(response.getStatus()).isEqualTo(200);

    verify(store, times(1)).getAllRejected();
    verify(collectionMapper, times(1)).map(any(), eq(Certificate.Status.REJECTED));
  }

  @Test
  void shouldGetApprovedCerts() throws URISyntaxException {
    MockHttpRequest request = MockHttpRequest
      .get("/v2/ssl-context/approved")
      .contentType(SSLContextResource.MEDIA_TYPE);

    dispatcher.invoke(request, response);

    assertThat(response.getStatus()).isEqualTo(200);

    verify(store, times(1)).getAllApproved();
    verify(collectionMapper, times(1)).map(any(), eq(Certificate.Status.APPROVED));
  }

  @Test
  void shouldApproveCert() throws URISyntaxException {
    MockHttpRequest request = MockHttpRequest
      .post("/v2/ssl-context/approve/42/21")
      .contentType(SSLContextResource.MEDIA_TYPE);

    dispatcher.invoke(request, response);

    assertThat(response.getStatus()).isEqualTo(204);

    verify(store, times(1)).approve("42", "21");
  }

  @Test
  void shouldRejectCert() throws URISyntaxException {
    MockHttpRequest request = MockHttpRequest
      .post("/v2/ssl-context/reject/42/21")
      .contentType(SSLContextResource.MEDIA_TYPE);

    dispatcher.invoke(request, response);

    assertThat(response.getStatus()).isEqualTo(204);

    verify(store, times(1)).reject("42", "21");
  }

  @Test
  void shouldUploadCert() throws URISyntaxException, IOException {
    File certFile = readFile("com/cloudogu/sslcontext/cert-001");

    try (FileInputStream fis = new FileInputStream(certFile)) {
      MockHttpRequest request = MockHttpRequest
        .post("/v2/ssl-context/upload")
        .content(fis)
        .contentType(MediaType.APPLICATION_OCTET_STREAM_TYPE);

      dispatcher.invoke(request, response);
    }

    assertThat(response.getStatus()).isEqualTo(204);
    verify(store).upload(any(Certificate.class));
  }

  @Test
  void shouldNotUploadTooLargeCertFile(@TempDir Path temp) throws URISyntaxException, IOException {
    File certFile = Files.createFile(temp.resolve("cert-too-big")).toFile();

    RandomAccessFile bigCert = new RandomAccessFile(certFile, "rw");
    bigCert.setLength(6000000);
    bigCert.close();

    try (FileInputStream fis = new FileInputStream(certFile)) {
      MockHttpRequest request = MockHttpRequest
        .post("/v2/ssl-context/upload/")
        .contentType(MediaType.APPLICATION_OCTET_STREAM_TYPE)
        .content(fis);

      dispatcher.invoke(request, response);
    }

    assertThat(response.getStatus()).isEqualTo(400);
  }

  @Test
  void shouldNotUploadIfNotValidX509Cert(@TempDir Path temp) throws URISyntaxException, IOException {
    File certFile = Files.createFile(temp.resolve("cert-invalid")).toFile();

    try (FileInputStream fis = new FileInputStream(certFile)) {
      MockHttpRequest request = MockHttpRequest
        .post("/v2/ssl-context/upload")
        .contentType(MediaType.APPLICATION_OCTET_STREAM_TYPE)
        .content(fis);

      dispatcher.invoke(request, response);
    }

    assertThat(response.getStatus()).isEqualTo(400);
  }

  @SuppressWarnings("UnstableApiUsage")
  private File readFile(String path) throws URISyntaxException {
    return Paths.get(Resources.getResource(path).toURI()).toFile();
  }

  /**
   * This method is a slightly adapted copy of Lin Zaho's gist at https://gist.github.com/lin-zhao/9985191
   */
  static void multipartRequest(MockHttpRequest request, Map<String, InputStream> files, String mediaType) throws IOException {
    String boundary = UUID.randomUUID().toString();
    request.contentType("multipart/form-data; boundary=" + boundary);

    //Make sure this is deleted in afterTest()
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (OutputStreamWriter formWriter = new OutputStreamWriter(buffer)) {
      formWriter.append("--").append(boundary);

      for (Map.Entry<String, InputStream> entry : files.entrySet()) {
        formWriter.append("\n");
        formWriter.append(String.format("Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"",
          entry.getKey(), entry.getKey())).append("\n");
        formWriter.append("Content-Type: ").append(mediaType).append("\n\n");

        InputStream stream = entry.getValue();
        int b = stream.read();
        while (b >= 0) {
          formWriter.write(b);
          b = stream.read();
        }
        stream.close();
        formWriter.append("\n").append("--").append(boundary);
      }

      formWriter.append("--");
      formWriter.flush();
    }
    request.setInputStream(new ByteArrayInputStream(buffer.toByteArray()));
  }
}
