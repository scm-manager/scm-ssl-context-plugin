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

import React, { FC, useState } from "react";
import { Button, ErrorNotification, Level } from "@scm-manager/ui-components";
import { useTranslation } from "react-i18next";
import { Certificate, formatAsTimestamp } from "../certificates";
import { Link } from "@scm-manager/ui-types";
import { ChainEntry, SizedModal } from "../approved/ApprovedCertificateDetailsModal";
import { useManageCertificate } from "../useManageCertificate";
import { useRemoveRejectedCertificate } from "../useRemoveRejectedCertificate";

type Props = {
  active: boolean;
  onClose: (successMessage?: string) => void;
  certificate: Certificate;
  refresh: () => void;
};

const RejectedCertificateDetailsModal: FC<Props> = ({ onClose, certificate, active, refresh }) => {
  const [t] = useTranslation("plugins");
  const chain = [certificate, ...certificate._embedded.chain].reverse();
  const [selectedCert, setSelectedCert] = useState<Certificate>(certificate);
  const { loading, error, manage } = useManageCertificate(refresh, () =>
    onClose(t("scm-ssl-context-plugin.table.approveNotification"))
  );
  const { loading: loadingRemoved, error: errorRemoved, remove } = useRemoveRejectedCertificate(refresh, onClose);

  const body = (
    <>
      <ErrorNotification error={error || errorRemoved} />
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

  let footer = null;
  if (selectedCert?._links?.approve || selectedCert?._links?.remove) {
    footer = (
      <Level
        right={
          <>
            {selectedCert?._links?.approve ? (
              <Button
                label={t("scm-ssl-context-plugin.table.approve")}
                action={() => manage((selectedCert._links.approve as Link).href)}
                color="info"
                type="button"
                loading={loading}
              />
            ) : null}
            {selectedCert?._links?.remove ? (
              <Button
                label={t("scm-ssl-context-plugin.table.delete")}
                action={() => remove((selectedCert._links.remove as Link).href)}
                color="info"
                type="button"
                loading={loadingRemoved}
              />
            ) : null}
          </>
        }
      />
    );
  }

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
