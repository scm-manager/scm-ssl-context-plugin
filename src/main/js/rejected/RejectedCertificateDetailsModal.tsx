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

import React, { FC } from "react";
import { Button, ErrorNotification } from "@scm-manager/ui-core";
import { Link } from "@scm-manager/ui-types";
import { useRejectedCertificateModal } from "../hooks";
import { Certificate, formatAsTimestamp } from "../certificates";
import { ChainEntry, SizedModal } from "../approved/ApprovedCertificateDetailsModal";

type Props = {
  active: boolean;
  onClose: (successMessage?: string) => void;
  certificate: Certificate;
  refresh: () => void;
};

const RejectedCertificateDetailsModal: FC<Props> = ({ onClose, certificate, active, refresh }) => {
  const { t, chain, selectedCert, setSelectedCert, loading, error, manage, remove } = useRejectedCertificateModal(
    certificate,
    refresh,
    onClose,
  );

  const body = (
    <>
      <ErrorNotification error={error} />
      <table className="table">
        <tbody>
          <tr>
            <th>{t("scm-ssl-context-plugin.table.column.certificateError")}</th>
            <td>{selectedCert.error}</td>
          </tr>
          <tr>
            <th>{t("scm-ssl-context-plugin.table.column.timestamp.rejected")}</th>
            <td>{formatAsTimestamp(selectedCert.timestamp)}</td>
          </tr>
          <tr>
            <th>{t("scm-ssl-context-plugin.table.column.chain")}</th>
            <td>
              <ul>
                {chain.map((cert, index) => (
                  <ChainEntry
                    key={cert.fingerprint}
                    certificate={cert}
                    onClick={() => setSelectedCert(cert)}
                    depth={index}
                    selected={selectedCert === cert}
                  />
                ))}
              </ul>
            </td>
          </tr>

          <tr>
            <th>{t("scm-ssl-context-plugin.table.column.subjectDN")}</th>
            <td>{selectedCert.subjectDN}</td>
          </tr>
          <tr>
            <th>{t("scm-ssl-context-plugin.table.column.issuerDN")}</th>
            <td>{selectedCert.issuerDN}</td>
          </tr>
          <tr>
            <th>{t("scm-ssl-context-plugin.table.column.notBefore")}</th>
            <td>{formatAsTimestamp(selectedCert.notBefore)}</td>
          </tr>
          <tr>
            <th>{t("scm-ssl-context-plugin.table.column.notAfter")}</th>
            <td>{formatAsTimestamp(selectedCert.notAfter)}</td>
          </tr>
          <tr>
            <th>{t("scm-ssl-context-plugin.table.column.signAlg")}</th>
            <td>{selectedCert.signAlg}</td>
          </tr>
          <tr>
            <th>{t("scm-ssl-context-plugin.table.column.fingerprint")}</th>
            <td>{selectedCert.fingerprint}</td>
          </tr>
        </tbody>
      </table>
    </>
  );

  const footer =
    selectedCert?._links?.approve || selectedCert?._links?.remove ? (
      <>
        {selectedCert?._links?.approve && (
          <Button
            onClick={() => manage((selectedCert._links.approve as Link).href)}
            className="is-info"
            isLoading={loading}
          >
            {t("scm-ssl-context-plugin.table.approve")}
          </Button>
        )}
        {selectedCert?._links?.remove && (
          <Button
            onClick={() => remove((selectedCert._links.remove as Link).href)}
            className="is-info"
            isLoading={loading}
          >
            {t("scm-ssl-context-plugin.table.delete")}
          </Button>
        )}
      </>
    ) : null;

  return (
    <SizedModal
      closeFunction={onClose}
      title={t("scm-ssl-context-plugin.modal.title")}
      body={body}
      active={active}
      footer={footer}
    />
  );
};

export default RejectedCertificateDetailsModal;
