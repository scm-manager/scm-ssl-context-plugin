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

import javax.ws.rs.core.MediaType;
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

import static java.util.Collections.singletonMap;
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
