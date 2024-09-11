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

import com.google.inject.Provider;
import sonia.scm.api.v2.resources.Enrich;
import sonia.scm.api.v2.resources.HalAppender;
import sonia.scm.api.v2.resources.HalEnricher;
import sonia.scm.api.v2.resources.HalEnricherContext;
import sonia.scm.api.v2.resources.Index;
import sonia.scm.api.v2.resources.LinkBuilder;
import sonia.scm.api.v2.resources.ScmPathInfoStore;
import sonia.scm.plugin.Extension;

import jakarta.inject.Inject;

@Extension
@Enrich(Index.class)
public class IndexLinkEnricher implements HalEnricher {

  private final Provider<ScmPathInfoStore> pathInfoStore;

  @Inject
  public IndexLinkEnricher(Provider<ScmPathInfoStore> pathInfoStore) {
    this.pathInfoStore = pathInfoStore;
  }

  @Override
  public void enrich(HalEnricherContext context, HalAppender appender) {

    if (PermissionChecker.mayReadSSLContext()) {
      HalAppender.LinkArrayBuilder linkArrayBuilder = appender.linkArrayBuilder("sslContext");
      linkArrayBuilder.append("rejected", rejected());
      linkArrayBuilder.append("approved", approved());

      if (PermissionChecker.mayManageSSLContext()) {
        linkArrayBuilder.append("upload", upload());
      }
      linkArrayBuilder.build();
    }
  }

  private String upload() {
    LinkBuilder linkBuilder = new LinkBuilder(pathInfoStore.get().get(), SSLContextResource.class);
    return linkBuilder.method("uploadCertificate").parameters().href();
  }

  private String rejected() {
    LinkBuilder linkBuilder = new LinkBuilder(pathInfoStore.get().get(), SSLContextResource.class);
    return linkBuilder.method("getAllRejected").parameters().href();
  }

  private String approved() {
    LinkBuilder linkBuilder = new LinkBuilder(pathInfoStore.get().get(), SSLContextResource.class);
    return linkBuilder.method("getAllApproved").parameters().href();
  }
}
