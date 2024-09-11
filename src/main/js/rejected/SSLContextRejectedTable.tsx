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
import {
  Column,
  comparators,
  Subtitle,
  Table,
  TextColumn,
  NoStyleButton
} from "@scm-manager/ui-components";
import { useTranslation } from "react-i18next";
import { Certificate, formatAsTimestamp, parseCommonNameFromDN } from "../certificates";
import RejectedCertificateDetailsModal from "./RejectedCertificateDetailsModal";

type Props = {
  chain: Certificate[];
  refresh: () => void;
  successMessage: (successMessage?: string) => void;
};

const SSLContextRejectedTable: FC<Props> = ({ chain, refresh, successMessage }) => {
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

export default SSLContextRejectedTable;
