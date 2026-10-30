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
import { useTranslation } from "react-i18next";
import { Notification, Title, useDocumentTitle } from "@scm-manager/ui-core";
import { Links } from "@scm-manager/ui-types";
import SSLContextApprovedOverview from "./approved/SSLContextApprovedOverview";
import SSLContextRejectedOverview from "./rejected/SSLContextRejectedOverview";
import { useCertificateCollection, CertificateCollectionResult } from "./hooks";
import { getLinkByName } from "./certificates";
import SSLCertificateUpload from "./SSLCertificateUpload";
import { useIndexLinks } from "@scm-manager/ui-api";

const SSLContextOverview: FC = () => {
  const [t] = useTranslation("plugins");
  const links = useIndexLinks() as Links;
  useDocumentTitle(t("scm-ssl-context-plugin.title"));

  const [successMessage, setSuccessMessage] = useState<string | undefined>("");
  const rejectedResult: CertificateCollectionResult = useCertificateCollection(getLinkByName(links, "rejected"));
  const approvedResult: CertificateCollectionResult = useCertificateCollection(getLinkByName(links, "approved"));

  const refresh = () => {
    rejectedResult.refresh();
    approvedResult.refresh();
  };

  return (
    <>
      <Title title={t("scm-ssl-context-plugin.title")} />
      {successMessage && (
        <Notification type="success" onClose={() => setSuccessMessage("")}>
          {successMessage}
        </Notification>
      )}
      <SSLContextApprovedOverview {...approvedResult} refresh={refresh} successMessage={setSuccessMessage} />
      <hr />
      <SSLContextRejectedOverview {...rejectedResult} refresh={refresh} successMessage={setSuccessMessage} />
      <SSLCertificateUpload link={getLinkByName(links, "upload")} refresh={refresh} />
    </>
  );
};

export default SSLContextOverview;
