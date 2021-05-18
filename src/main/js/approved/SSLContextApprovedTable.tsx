import { Certificate, formatAsTimestamp, parseCommonNameFromDN } from "../certificates";
import React, { FC, useState } from "react";
import { useTranslation } from "react-i18next";
import { Column, comparators, Subtitle, Table } from "@scm-manager/ui-components";
import ApprovedCertificateDetailsModal from "./ApprovedCertificateDetailsModal";

type Props = {
  chain: Certificate[];
};

const SSLContextApprovedTable: FC<Props> = ({ chain }) => {
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
          onClose={() => setSelectedCertificate(undefined)}
          certificate={selectedCertificate}
          active={!!selectedCertificate}
        />
      ) : null}
      <Subtitle subtitle={t("scm-ssl-context-plugin.table.title.approved")} className="mb-0" />
      <Table data={initialSorted} emptyMessage={t("scm-ssl-context-plugin.table.emptyMessage")}>
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
        <Column header="">
          {row => <a onClick={() => openModal(row)}>{t("scm-ssl-context-plugin.table.details")}</a>}
        </Column>
      </Table>
    </>
  );
};

export default SSLContextApprovedTable;
