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
