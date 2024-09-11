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

import com.google.inject.AbstractModule;
import com.google.inject.name.Names;
import org.mapstruct.factory.Mappers;
import sonia.scm.plugin.Extension;

import jakarta.inject.Singleton;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

@Extension
public class SSLContextModule extends AbstractModule {

  @Override
  protected void configure() {
    bind(CertificateMapper.class).to(Mappers.getMapperClass(CertificateMapper.class));
    bind(SSLContext.class).annotatedWith(Names.named("default")).toProvider(SSLContextProvider.class).in(Singleton.class);
    bind(X509TrustManager.class).annotatedWith(Names.named("chain")).to(TrustManagerChain.class);
    bind(TrustManager.class).annotatedWith(Names.named("default")).to(CapturingTrustManager.class).in(Singleton.class);
  }
}
