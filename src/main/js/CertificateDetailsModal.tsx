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
import React, { FC, ReactNode, useState } from "react";
import { Modal } from "@scm-manager/ui-components";
import { useTranslation } from "react-i18next";
import {Certificate, parseCommonNameFromDN} from "./certificates";
import { formatAsTimestamp } from "./SSLContextTable";
import styled from "styled-components";

type Props = {
  active: boolean;
  onClose: () => void;
  modalData: Certificate;
};

type TreeElementProps = {
  children: ReactNode;
  active: boolean;
  depth: number;
  onClick: () => void;
};

const SizedModal = styled(Modal)`
  .modal-card {
    width: 98%;
    height: auto;
  }
  th {
    width: 20%;
  }
`;

const StyledTreeElement = styled.li<{ active: boolean; depth: number }>`
  margin-left: ${props => props.depth}rem;
  color: ${props => (props.active ? "#33b2e8" : "inherit")};
  cursor: pointer;
  width: fit-content;
`;

const TreeElement: FC<TreeElementProps> = ({ active, depth, onClick, children }) => {
  return (
    <StyledTreeElement active={active} depth={depth * 3} onClick={onClick}>
      {children}
    </StyledTreeElement>
  );
};

const CertificateDetailsModal: FC<Props> = ({ onClose, modalData, active }) => {
  const [t] = useTranslation("plugins");
  const [certs, setCerts] = useState<Certificate[]>([
    modalData,
    ...(modalData?._embedded!.chainCerts as Certificate[])
  ]);
  const [selectedCert, setSelectedCert] = useState<Certificate>(modalData);

  const body = modalData ? (
    <table className="table">
      <tbody>
        <tr>
          <th>{t("scm-ssl-context-plugin.table.column.chain")}</th>
          <td>
            <ul>
              {certs.map((cert, index) => (
                <TreeElement onClick={() => setSelectedCert(cert)} depth={index} active={selectedCert === cert}>
                  {index}: {parseCommonNameFromDN(cert.subjectDN)}
                </TreeElement>
              ))}
            </ul>
          </td>
        </tr>
        <tr>
          <th>{t("scm-ssl-context-plugin.table.column.certificateError")}</th>
          <td>{selectedCert.error}</td>
        </tr>
        <tr>
          <th>{t("scm-ssl-context-plugin.table.column.timestamp")}</th>
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
  ) : null;

  return (
    <SizedModal closeFunction={onClose} title={t("scm-ssl-context-plugin.modal.title")} body={body} active={active} />
  );
};

export default CertificateDetailsModal;
