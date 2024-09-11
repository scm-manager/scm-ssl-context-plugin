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
import { useTranslation } from "react-i18next";

export const useRemoveRejectedCertificate = (refresh: () => void, onClose: (successMessage?: string) => void) => {
  const [t] = useTranslation("plugins");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | undefined>();

  const remove = (link: string) => {
    setLoading(true);
    apiClient
      .delete(link)
      .then(refresh)
      .then(() => setLoading(false))
      .then(() => onClose(t("scm-ssl-context-plugin.table.deleteNotification")))
      .catch(setError);
  };

  return { loading, error, remove };
};
