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
import { Column, comparators, Subtitle, Table, TextColumn, LinkStyleButton } from "@scm-manager/ui-components";
import { useTranslation } from "react-i18next";
import { Certificate, formatAsTimestamp, parseCommonNameFromDN } from "../certificates";
import RejectedCertificateDetailsModal from "./RejectedCertificateDetailsModal";

type Props = {
  chain: Certificate[];
  refresh: () => void;
};

const SSLContextRejectedTable: FC<Props> = ({ chain, refresh }) => {
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
        <RejectedCertificateDetailsModal
          onClose={() => setSelectedCertificate(undefined)}
          certificate={selectedCertificate}
          active={!!selectedCertificate}
          refresh={refresh}
        />
      ) : null}
      <Subtitle subtitle={t("scm-ssl-context-plugin.table.title.rejected")} className="mb-3" />
      <Table data={initialSorted} emptyMessage={t("scm-ssl-context-plugin.table.emptyMessage")}>
        <Column
          header={t("scm-ssl-context-plugin.table.column.commonName")}
          createComparator={() => comparators.byKey("subjectDN")}
          ascendingIcon="sort-alpha-down-alt"
          descendingIcon="sort-alpha-down"
        >
          {row => parseCommonNameFromDN(row.subjectDN)}
        </Column>
        <TextColumn header={t("scm-ssl-context-plugin.table.column.certificateError")} dataKey="error" />
        <Column
          header={t("scm-ssl-context-plugin.table.column.timestamp.rejected")}
          createComparator={() => timestampComparator}
          ascendingIcon="sort"
          descendingIcon="sort"
        >
          {row => formatAsTimestamp(row.timestamp)}
        </Column>
        <Column header="">
          {row => <LinkStyleButton className="has-text-info" onClick={() => openModal(row)}>{t("scm-ssl-context-plugin.table.details")}</LinkStyleButton>}
        </Column>
      </Table>
    </>
  );
};

export default SSLContextRejectedTable;
