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

import com.google.common.io.ByteStreams;
import de.otto.edison.hal.HalRepresentation;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.apache.commons.io.IOUtils;
import sonia.scm.api.v2.resources.ErrorDto;
import sonia.scm.web.VndMediaType;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.util.Collection;

import static sonia.scm.ScmConstraintViolationException.Builder.doThrow;

@OpenAPIDefinition(tags = {
  @Tag(name = "SSL Context Plugin", description = "SSL Context plugin provided endpoints")
})
@Path("v2/ssl-context")
public class SSLContextResource {

  static final String MEDIA_TYPE = VndMediaType.PREFIX + "ssl-context" + VndMediaType.SUFFIX;
  @SuppressWarnings("java:S115")
  private static final int UPLOAD_LIMIT_BYTES = 50000;

  private final CertificateStore store;
  private final CertificateCollectionMapper mapper;

  @Inject
  public SSLContextResource(CertificateStore store, CertificateCollectionMapper mapper) {
    this.store = store;
    this.mapper = mapper;
  }

  @GET
  @Path("rejected")
  @Produces(MEDIA_TYPE)
  @Operation(
    summary = "Get rejected X509 certificate data",
    description = "Returns data for rejected X509 certificates.",
    tags = "SSL Context Plugin",
    operationId = "ssl_context_get_rejected_data"
  )
  @ApiResponse(
    responseCode = "200",
    description = "success",
    content = @Content(
      mediaType = MediaType.APPLICATION_JSON,
      schema = @Schema(implementation = HalRepresentation.class)
    )
  )
  @ApiResponse(responseCode = "401", description = "not authenticated / invalid credentials")
  @ApiResponse(responseCode = "403", description = "not authorized, the current user has no privileges to read the data")
  @ApiResponse(
    responseCode = "500",
    description = "internal server error",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    )
  )
  public Response getAllRejected() {
    Collection<Certificate> certs = store.getAllRejected();
    return Response.ok(mapper.map(certs, Certificate.Status.REJECTED)).build();
  }

  @GET
  @Path("approved")
  @Produces(MEDIA_TYPE)
  @Operation(
    summary = "Get approved X509 certificate data",
    description = "Returns data for approved X509 certificates.",
    tags = "SSL Context Plugin",
    operationId = "ssl_context_get_approved_data"
  )
  @ApiResponse(
    responseCode = "200",
    description = "success",
    content = @Content(
      mediaType = MediaType.APPLICATION_JSON,
      schema = @Schema(implementation = HalRepresentation.class)
    )
  )
  @ApiResponse(responseCode = "401", description = "not authenticated / invalid credentials")
  @ApiResponse(responseCode = "403", description = "not authorized, the current user has no privileges to read the data")
  @ApiResponse(
    responseCode = "500",
    description = "internal server error",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    )
  )
  public Response getAllApproved() {
    Collection<Certificate> certs = store.getAllApproved();
    return Response.ok(mapper.map(certs, Certificate.Status.APPROVED)).build();
  }

  @POST
  @Path("/approve/{storedId}/{id}")
  @Operation(
    summary = "Approve single certificate",
    description = "Approves a single server certificate",
    tags = "SSL Context Plugin",
    operationId = "ssl_context_approve_cert"
  )
  @ApiResponse(
    responseCode = "204",
    description = "success"
  )
  @ApiResponse(responseCode = "401", description = "not authenticated / invalid credentials")
  @ApiResponse(responseCode = "403", description = "not authorized, the current user has no privileges to write the data")
  @ApiResponse(
    responseCode = "500",
    description = "internal server error",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    )
  )
  public Response approve(@PathParam("storedId") String storedId, @PathParam("id") String id) {
    store.approve(storedId, id);
    return Response.noContent().build();
  }

  @POST
  @Path("/reject/{storedId}/{id}")
  @Operation(
    summary = "Reject single approved certificate",
    description = "Rejects a single approved server certificate",
    tags = "SSL Context Plugin",
    operationId = "ssl_context_reject_cert"
  )
  @ApiResponse(
    responseCode = "204",
    description = "success"
  )
  @ApiResponse(responseCode = "401", description = "not authenticated / invalid credentials")
  @ApiResponse(responseCode = "403", description = "not authorized, the current user has no privileges to write the data")
  @ApiResponse(
    responseCode = "500",
    description = "internal server error",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    )
  )
  public Response reject(@PathParam("storedId") String storedId, @PathParam("id") String id) {
    store.reject(storedId, id);
    return Response.noContent().build();
  }

  @DELETE
  @Path("/rejected/{id}")
  @Operation(
    summary = "Remove single rejected certificate",
    description = "Removes a single rejected server certificate",
    tags = "SSL Context Plugin",
    operationId = "ssl_context_remove_rejected_cert"
  )
  @ApiResponse(
    responseCode = "204",
    description = "success"
  )
  @ApiResponse(responseCode = "401", description = "not authenticated / invalid credentials")
  @ApiResponse(responseCode = "403", description = "not authorized, the current user has no privileges to write the data")
  @ApiResponse(
    responseCode = "500",
    description = "internal server error",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    )
  )
  public Response removeRejected(@PathParam("id") String id) {
    store.removeRejected(id);
    return Response.noContent().build();
  }

  @POST
  @Consumes(MediaType.APPLICATION_OCTET_STREAM)
  @Path("upload")
  @Operation(
    summary = "Uploads certificate",
    description = "Uploads a certificate",
    tags = "SSL Context Plugin",
    operationId = "ssl_context_upload_cert"
  )
  @ApiResponse(
    responseCode = "204",
    description = "success"
  )
  @ApiResponse(responseCode = "401", description = "not authenticated / invalid credentials")
  @ApiResponse(responseCode = "403", description = "not authorized, the current user has no privileges to write the data")
  @ApiResponse(
    responseCode = "500",
    description = "internal server error",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    )
  )
  public Response uploadCertificate(InputStream is) throws IOException {
    Certificate cert = extractCertFromInput(is);
    store.upload(cert);
    return Response.noContent().build();
  }

  @SuppressWarnings("UnstableApiUsage")
  private Certificate extractCertFromInput(InputStream is) throws IOException {
    InputStream lis = ByteStreams.limit(is, UPLOAD_LIMIT_BYTES + 1L);
    byte[] encoded = IOUtils.toByteArray(lis);
    doThrow().violation("File too large").when(encoded.length > UPLOAD_LIMIT_BYTES);
    Certificate cert = new Certificate(encoded, Certificate.Error.UNKNOWN);
    validateFileIsX509Cert(cert);
    return cert;
  }

  private void validateFileIsX509Cert(Certificate cert) {
    try {
      cert.toX509();
    } catch (CertificateException e) {
      doThrow().violation("File is not a valid certificate").when(true);
    }
  }
}
