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
import { Column, comparators, Icon, Table, TextColumn } from "@scm-manager/ui-components";
import { useTranslation } from "react-i18next";
import { format } from "date-fns";
import { Certificate } from "./certificates";
import CertificateDetailsModal from "./CertificateDetailsModal";

type Props = {
  data: Certificate[];
};

export const formatAsTimestamp = (date: Date) => {
  return format(new Date(date), "yyyy-MM-dd HH:mm:ss");
};

const SSLContextTable: FC<Props> = ({ data }) => {
  const [t] = useTranslation("plugins");
  const [showModal, setShowModal] = useState(false);
  const [modalData, setModalData] = useState<Certificate | undefined>();

  const openModal = (certificate: Certificate) => {
    setModalData(certificate);
    setShowModal(true);
  };

  const parseCommonNameFromDN = (dn: string) => {
    const commonName = dn
      .split(",")
      .filter((s: string) => s.includes("CN="))[0]
      .trim();
    return commonName.substr(3, commonName.length + 1);
  };

  return (
    <>
      {showModal && (
        <CertificateDetailsModal onClose={() => setShowModal(false)} modalData={modalData} active={showModal} />
      )}
      <Table data={data} emptyMessage={t("scm-ssl-context-plugin.table.emptyMessage")}>
        <Column
          header={t("scm-ssl-context-plugin.table.column.commonName")}
          createComparator={() => comparators.byKey("subjectDN")}
          ascendingIcon="sort-alpha-down-alt"
          descendingIcon="sort-alpha-down"
        >
          {row => parseCommonNameFromDN(row.subjectDN)}
        </Column>
        <TextColumn header={t("scm-ssl-context-plugin.table.column.error")} dataKey="error" />
        <Column
          header={t("scm-ssl-context-plugin.table.column.status")}
          createComparator={() => comparators.byKey("failed")}
          ascendingIcon="sort"
          descendingIcon="sort"
        >
          {row =>
            row.status === "REJECTED" ? (
              <>
                <Icon color="danger" name="exclamation-triangle" />
                {" " + t("scm-ssl-context-plugin.table.rejected")}
              </>
            ) : (
              <>
                <Icon color="success" name="check-circle" iconStyle="far" />
                {" " + t("scm-ssl-context-plugin.table.approved")}
              </>
            )
          }
        </Column>
        <Column
          header={t("scm-ssl-context-plugin.table.column.timestamp")}
          createComparator={() => comparators.byKey("timestamp")}
          ascendingIcon="sort"
          descendingIcon="sort"
        >
          {row => formatAsTimestamp(row.timestamp)}
        </Column>
        <Column header="">
          {row => <a onClick={() => openModal(row)}>{t("scm-ssl-context-plugin.table.details")}</a>}
        </Column>
      </Table>
    </>
  );
};

export default SSLContextTable;
