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

import sonia.scm.store.BlobStore;
import sonia.scm.store.BlobStoreFactory;
import sonia.scm.store.StoreParameters;

import java.util.HashMap;
import java.util.Map;

public class InMemoryBlobStoreFactory implements BlobStoreFactory {

  private final Map<String, BlobStore> stores = new HashMap<>();

  private final BlobStore fixedStore;

  public InMemoryBlobStoreFactory() {
    this(null);
  }

  public InMemoryBlobStoreFactory(BlobStore fixedStore) {
    this.fixedStore = fixedStore;
  }

  @Override
  public BlobStore getStore(StoreParameters storeParameters) {
    if (fixedStore == null) {
      return stores.computeIfAbsent(computeKey(storeParameters), key -> new InMemoryBlobStore());
    } else {
      return fixedStore;
    }
  }

  private String computeKey(StoreParameters storeParameters) {
    if (storeParameters.getRepositoryId() == null) {
      return storeParameters.getName();
    } else {
      return storeParameters.getName() + "/" + storeParameters.getRepositoryId();
    }
  }
}
