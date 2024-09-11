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

import { useEffect, useState } from "react";
import { CertificateCollection } from "./certificates";
import { apiClient } from "@scm-manager/ui-components";

export type CertificateCollectionResult = {
  data?: CertificateCollection;
  loading: boolean;
  error?: Error;
  refresh: () => void;
};

const useCertificateCollection = (link: string) => {
  const [data, setData] = useState<CertificateCollection>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | undefined>();
  const [shouldRefresh, setShouldRefresh] = useState(0);

  useEffect(() => {
    apiClient
      .get(link)
      .then(r => r.json())
      .then(r => setData(r))
      .then(() => setLoading(false))
      .catch(setError);
  }, [link, shouldRefresh]);

  return { data, loading, error, refresh: () => setShouldRefresh(shouldRefresh + 1) };
};

export default useCertificateCollection;
