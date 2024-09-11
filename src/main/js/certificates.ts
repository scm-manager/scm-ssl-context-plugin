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

import { HalRepresentation, Link, Links } from "@scm-manager/ui-types";
import { format } from "date-fns";

type CertificateError =
  | "CERTIFICATE_UNKNOWN"
  | "CERTIFICATE_EXPIRED"
  | "CERTIFICATE_NOT_YET_VALID"
  | "CERTIFICATE_REVOKED";

type CertificateStatus = "REJECTED" | "APPROVED";

export type CertificateCollection = HalRepresentation & {
  _embedded: {
    certificates: Certificate[];
  };
};

export type Certificate = HalRepresentation & {
  error: CertificateError;
  fingerprint: string;
  issuerDN: string;
  notAfter: Date;
  notBefore: Date;
  signAlg: string;
  status: CertificateStatus;
  subjectDN: string;
  timestamp: Date;
  uploaded?: boolean;
  _embedded: {
    chain: Certificate[];
  };
};

export const parseCommonNameFromDN = (dn: string) => {
  const commonNames = dn
    .split(",")
    .filter((s: string) => s.includes("CN="));
  if (commonNames.length > 0) {
    const commonName = commonNames[0].trim();
    return commonName.substr(3, commonName.length + 1);
  }
  return "Unknown common name";
};

export const getLinkByName = (links: Links, linkName: string) => {
  return (links.sslContext as Link[]).filter(l => l.name === linkName)[0]?.href;
};

export const formatAsTimestamp = (date: Date) => {
  return format(new Date(date), "yyyy-MM-dd HH:mm:ss");
};
