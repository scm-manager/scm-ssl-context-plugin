/*
 * MIT License
 *
 * Copyright (c) 2020-present Cloudogu GmbH and Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
import React, { FC, useState } from "react";
import { Button, Checkbox, ErrorNotification, Level, Modal } from "@scm-manager/ui-components";
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
  onClose: () => void;
  certificate: Certificate;
  refresh: () => void;
};

const ApprovedCertificateDetailsModal: FC<Props> = ({ onClose, certificate, active, refresh }) => {
  const [t] = useTranslation("plugins");
  const chain = [certificate, ...certificate._embedded.chain].reverse();
  const [selectedCert, setSelectedCert] = useState<Certificate>(certificate);
  const { loading, error, manage } = useManageCertificate(refresh, onClose);

  const renderButton = () => {
    if (!!selectedCert._links) {
      if (selectedCert?._links.reject) {
        return (
          <Button
            label={t("scm-ssl-context-plugin.table.reject")}
            action={() => manage((selectedCert._links.reject as Link).href)}
            color="info"
            type="button"
            loading={loading}
          />
        );
      }
    }
  };

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
            <th>{t("scm-ssl-context-plugin.table.column.uploaded")}</th>
            <td>{selectedCert.uploaded && <Checkbox checked={true} />}</td>
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

  const footer = <Level right={renderButton()} />;

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
