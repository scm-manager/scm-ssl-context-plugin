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

import React, { FC } from "react";
import { ErrorNotification, Loading } from "@scm-manager/ui-components";
import { Certificate, CertificateCollection } from "../certificates";
import SSLContextApprovedTable from "./SSLContextApprovedTable";

type Props = {
  data?: CertificateCollection;
  loading: boolean;
  error?: Error;
  refresh: () => void;
  successMessage: (successMessage?: string) => void;
};

const SSLContextApprovedOverview: FC<Props> = ({ data, error, loading, refresh, successMessage }) => {
  if (error) {
    return <ErrorNotification error={error} />;
  }

  if (loading) {
    return <Loading />;
  }

  return (
    <SSLContextApprovedTable
      chain={(data?._embedded.chain as Certificate[]) || []}
      refresh={refresh}
      successMessage={successMessage}
    />
  );
};

export default SSLContextApprovedOverview;
