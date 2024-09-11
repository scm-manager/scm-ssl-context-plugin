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

import { useState } from "react";
import { apiClient } from "@scm-manager/ui-components";

export const useManageCertificate = (refresh: () => void, onClose: () => void) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | undefined>();

  const manage = (link: string) => {
    setLoading(true);
    apiClient
      .post(link)
      .then(refresh)
      .then(() => setLoading(false))
      .then(() => onClose())
      .catch(setError);
  };

  return { loading, error, manage };
};
