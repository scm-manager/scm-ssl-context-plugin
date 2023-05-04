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
import { Certificate, formatAsTimestamp, parseCommonNameFromDN } from "../certificates";
import React, { FC, useState } from "react";
import { useTranslation } from "react-i18next";
import { Column, comparators, NoStyleButton, Subtitle, Table } from "@scm-manager/ui-components";
import ApprovedCertificateDetailsModal from "./ApprovedCertificateDetailsModal";

type Props = {
  chain: Certificate[];
  refresh: () => void;
  successMessage: (successMessage?: string) => void;
};

const SSLContextApprovedTable: FC<Props> = ({ chain, refresh, successMessage }) => {
  const [t] = useTranslation("plugins");
  const [selectedCertificate, setSelectedCertificate] = useState<Certificate>();
  const openModal = (certificate: Certificate) => {
    setSelectedCertificate(certificate);
  };

  const timestampComparator = comparators.byKey("timestamp");
  const initialSorted = chain.sort((a, b) => timestampComparator(a, b) * -1);

  return (
    <>
      {selectedCertificate ? (
        <ApprovedCertificateDetailsModal
          onClose={message => {
            setSelectedCertificate(undefined);
            if (typeof message === "string") {
              successMessage(message);
            }
          }}
          certificate={selectedCertificate}
          active={!!selectedCertificate}
          refresh={refresh}
        />
      ) : null}
      <Subtitle subtitle={t("scm-ssl-context-plugin.table.title.approved")} className="mb-3" />
      <Table data={initialSorted} emptyMessage={t("scm-ssl-context-plugin.table.emptyMessage")} className="mt-4">
        <Column
          header={t("scm-ssl-context-plugin.table.column.commonName")}
          createComparator={() => comparators.byKey("subjectDN")}
          ascendingIcon="sort-alpha-down-alt"
          descendingIcon="sort-alpha-down"
        >
          {row => parseCommonNameFromDN(row.subjectDN)}
        </Column>
        <Column
          header={t("scm-ssl-context-plugin.table.column.timestamp.approved")}
          createComparator={() => timestampComparator}
          ascendingIcon="sort"
          descendingIcon="sort"
        >
          {row => formatAsTimestamp(row.timestamp)}
        </Column>
        <Column header={t("scm-ssl-context-plugin.table.column.uploaded.label")}>
          {row =>
            row.uploaded
              ? t("scm-ssl-context-plugin.table.column.uploaded.yes")
              : t("scm-ssl-context-plugin.table.column.uploaded.no")
          }
        </Column>
        <Column className="has-text-right" header="">
          {row => (
            <NoStyleButton className="has-text-info" onClick={() => openModal(row)}>
              {t("scm-ssl-context-plugin.table.details")}
            </NoStyleButton>
          )}
        </Column>
      </Table>
    </>
  );
};

export default SSLContextApprovedTable;
