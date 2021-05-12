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
import React, { FC } from "react";
import { Modal } from "@scm-manager/ui-components";
import { useTranslation } from "react-i18next";
import { Certificate } from "./certificates";
import { formatAsTimestamp } from "./SSLContextTable";

type Props = {
  active: boolean;
  onClose: () => void;
  modalData?: Certificate;
};

const CertificateDetailsModal: FC<Props> = ({ onClose, modalData, active }) => {
  const [t] = useTranslation("plugins");

  const body = modalData ? (
    <table className="table">
      <tbody>
        <tr>
          <th>{t("scm-ssl-context-plugin.table.column.certificateError")}</th>
          <td>{modalData.error}</td>
        </tr>
        <tr>
          <th>{t("scm-ssl-context-plugin.table.column.timestamp")}</th>
          <td>{formatAsTimestamp(modalData.timestamp)}</td>
        </tr>
        <tr>
          <th>{t("scm-ssl-context-plugin.table.column.subjectDN")}</th>
          <td>{modalData.subjectDN}</td>
        </tr>
        <tr>
          <th>{t("scm-ssl-context-plugin.table.column.issuerDN")}</th>
          <td>{modalData.issuerDN}</td>
        </tr>
        <tr>
          <th>{t("scm-ssl-context-plugin.table.column.notBefore")}</th>
          <td>{formatAsTimestamp(modalData.notBefore)}</td>
        </tr>
        <tr>
          <th>{t("scm-ssl-context-plugin.table.column.notAfter")}</th>
          <td>{formatAsTimestamp(modalData.notAfter)}</td>
        </tr>
        <tr>
          <th>{t("scm-ssl-context-plugin.table.column.signAlg")}</th>
          <td>{modalData.signAlg}</td>
        </tr>
        <tr>
          <th>{t("scm-ssl-context-plugin.table.column.fingerprint")}</th>
          <td>{modalData.fingerprint}</td>
        </tr>
      </tbody>
    </table>
  ) : null;

  return <Modal closeFunction={onClose} title={t("scm-ssl-context-plugin.modal.title")} body={body} active={active} />;
};

export default CertificateDetailsModal;
