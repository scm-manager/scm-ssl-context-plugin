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

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
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
