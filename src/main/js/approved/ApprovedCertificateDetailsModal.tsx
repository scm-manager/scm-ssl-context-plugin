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
import { Button, ErrorNotification, Level, Modal } from "@scm-manager/ui-components";
import { useTranslation } from "react-i18next";
import { Certificate, formatAsTimestamp, parseCommonNameFromDN } from "../certificates";
import styled from "styled-components";
import classNames from "classnames";
import { Link } from "@scm-manager/ui-types";
import { useManageCertificate } from "../useManageCertificate";

export const SizedModal = styled(Modal)`
  .modal-card {
    width: 95%;
    height: auto;
  }

  th {
    width: 20%;
  }
`;

export const StyledTreeElement = styled.li<{ depth: number }>`
  margin-left: ${props => props.depth}rem;
  width: fit-content;
`;

export const ChainButton = styled(Button)`
  background: none !important;
  border: none !important;
  box-shadow: none !important;
  padding: 0;
  text-decoration: none;
  cursor: pointer;
`;

export type ChainEntryProps = {
  certificate: Certificate;
  depth: number;
  selected: boolean;
  onClick: () => void;
};

export const ChainEntry: FC<ChainEntryProps> = ({ certificate, depth, selected, onClick }) => (
  <StyledTreeElement depth={depth * 3} onClick={onClick}>
    <ChainButton icon="certificate" className={classNames("is-inverted", { "is-link": selected })}>
      {parseCommonNameFromDN(certificate.subjectDN)}
    </ChainButton>
  </StyledTreeElement>
);

type Props = {
  active: boolean;
  onClose: (successMessage?: string) => void;
  certificate: Certificate;
  refresh: () => void;
};

const ApprovedCertificateDetailsModal: FC<Props> = ({ onClose, certificate, active, refresh }) => {
  const [t] = useTranslation("plugins");
  const chain = [certificate, ...certificate._embedded.chain].reverse();
  const [selectedCert, setSelectedCert] = useState<Certificate>(certificate);
  const { loading, error, manage } = useManageCertificate(refresh, () => {
    onClose(t("scm-ssl-context-plugin.table.rejectNotification"));
  });

  const body = (
    <>
      <ErrorNotification error={error} />
      <table className="table">
        <tbody>
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
            <th>{t("scm-ssl-context-plugin.table.column.uploaded.label")}</th>
            <td>
              {selectedCert.uploaded
                ? t("scm-ssl-context-plugin.table.column.uploaded.yes")
                : t("scm-ssl-context-plugin.table.column.uploaded.no")}
            </td>
          </tr>
          <tr>
            <th>{t("scm-ssl-context-plugin.table.column.timestamp.approved")}</th>
            <td>{formatAsTimestamp(selectedCert.timestamp)}</td>
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
  if (selectedCert?._links?.reject) {
    footer = (
      <Level
        right={
          <Button
            label={t("scm-ssl-context-plugin.table.reject")}
            action={() => manage((selectedCert._links.reject as Link).href)}
            color="info"
            type="button"
            loading={loading}
          />
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

export default ApprovedCertificateDetailsModal;
