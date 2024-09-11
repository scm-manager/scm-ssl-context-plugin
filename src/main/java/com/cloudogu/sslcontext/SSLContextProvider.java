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

import jakarta.inject.Inject;
import jakarta.inject.Provider;
import javax.net.ssl.SSLContext;
import java.security.GeneralSecurityException;

class SSLContextProvider implements Provider<SSLContext> {

  private final CapturingTrustManager capturingSslTrustManager;

  @Inject
  public SSLContextProvider(CapturingTrustManager trustManager) {
    this.capturingSslTrustManager = trustManager;
  }

  @Override
  public SSLContext get() {
    try {
      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(null, new CapturingTrustManager[]{capturingSslTrustManager}, null);
      return sslContext;
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException();
    }
  }
}
