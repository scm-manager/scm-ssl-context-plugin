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

import { useTranslation } from "react-i18next";
import { useCallback, useEffect, useState } from "react";
import { apiClient } from "@scm-manager/ui-components";
import { CertificateCollection, Certificate } from "./certificates";

export type CertificateCollectionResult = {
  data?: CertificateCollection;
  loading: boolean;
  error?: Error;
  refresh: () => void;
};

export const useCertificateCollection = (link?: string): CertificateCollectionResult => {
  const [data, setData] = useState<CertificateCollection>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error>();
  const [refreshCount, setRefreshCount] = useState(0);

  const refresh = useCallback(() => setRefreshCount((c) => c + 1), []);

  useEffect(() => {
    if (!link) {
      return;
    }
    setLoading(true);
    apiClient
      .get(link)
      .then((r) => r.json())
      .then(setData)
      .catch(setError)
      .finally(() => setLoading(false));
  }, [link, refreshCount]);

  return { data, loading, error, refresh };
};

export const useManageCertificate = (refresh: () => void, onSuccess: () => void) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error>();

  const manage = useCallback(
    (link: string) => {
      setLoading(true);
      setError(undefined);
      apiClient
        .post(link)
        .then(() => {
          refresh();
          onSuccess();
        })
        .catch(setError)
        .finally(() => setLoading(false));
    },
    [refresh, onSuccess],
  );

  return { loading, error, manage };
};

export const useRemoveRejectedCertificate = (refresh: () => void, onClose: (msg?: string) => void) => {
  const [t] = useTranslation("plugins");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error>();

  const remove = useCallback(
    (link: string) => {
      setLoading(true);
      setError(undefined);
      apiClient
        .delete(link)
        .then(() => {
          refresh();
          onClose(t("scm-ssl-context-plugin.table.deleteNotification"));
        })
        .catch(setError)
        .finally(() => setLoading(false));
    },
    [t, refresh, onClose],
  );

  return { loading, error, remove };
};

export const useRejectedCertificateModal = (
  certificate: Certificate,
  refresh: () => void,
  onClose: (successMessage?: string) => void,
) => {
  const [t] = useTranslation("plugins");
  const [selectedCert, setSelectedCert] = useState<Certificate>(certificate);
  const chain = [certificate, ...certificate._embedded.chain].reverse();

  const handleApproveSuccess = useCallback(() => {
    onClose(t("scm-ssl-context-plugin.table.approveNotification"));
  }, [onClose, t]);

  const { loading: manageLoading, error: manageError, manage } = useManageCertificate(refresh, handleApproveSuccess);
  const { loading: removeLoading, error: removeError, remove } = useRemoveRejectedCertificate(refresh, onClose);

  return {
    t,
    chain,
    selectedCert,
    setSelectedCert,
    loading: manageLoading || removeLoading,
    error: manageError || removeError,
    manage,
    remove,
  };
};
