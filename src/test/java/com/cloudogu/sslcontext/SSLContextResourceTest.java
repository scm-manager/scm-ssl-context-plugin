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

import org.github.sdorra.jse.ShiroExtension;
import org.github.sdorra.jse.SubjectAware;
import org.jboss.resteasy.mock.MockHttpRequest;
import org.jboss.resteasy.mock.MockHttpResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import sonia.scm.web.RestDispatcher;

import java.net.URISyntaxException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
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
  @SubjectAware(permissions = "configuration:read:sslContext" )
  void shouldGetCerts() throws URISyntaxException {
    MockHttpRequest request = MockHttpRequest
      .get("/v2/ssl-context/")
      .contentType(SSLContextResource.MEDIA_TYPE);

    dispatcher.invoke(request, response);

    assertThat(response.getStatus()).isEqualTo(200);

    verify(store, times(1)).getAll();
    verify(collectionMapper, times(1)).map(any());
  }


  @Test
  void shouldReturnForbiddenIfNotPermitted() throws URISyntaxException {
    MockHttpRequest request = MockHttpRequest
      .get("/v2/ssl-context/")
      .contentType(SSLContextResource.MEDIA_TYPE);

    dispatcher.invoke(request, response);

    assertThat(response.getStatus()).isEqualTo(403);
  }
}
