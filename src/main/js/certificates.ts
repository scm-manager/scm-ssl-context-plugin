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

import { HalRepresentation } from "@scm-manager/ui-types";

type CertificateError =
  | "CERTIFICATE_UNKNOWN"
  | "CERTIFICATE_EXPIRED"
  | "CERTIFICATE_NOT_YET_VALID"
  | "CERTIFICATE_REVOKED";

type CertificateStatus = "REJECTED" | "APPROVED";

export type CertificateCollection = HalRepresentation & {
  _embedded: {
    certificates: Certificate[]
  }
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
  _embedded: {
    chain: Certificate[]
  }
};

export const parseCommonNameFromDN = (dn: string) => {
  const commonName = dn
    .split(",")
    .filter((s: string) => s.includes("CN="))[0]
    .trim();
  return commonName.substr(3, commonName.length + 1);
};
