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
import React, { FC } from "react";
import { Links } from "@scm-manager/ui-types";
import { useTranslation } from "react-i18next";
import { Title } from "@scm-manager/ui-components";
import SSLContextApprovedOverview from "./approved/SSLContextApprovedOverview";
import SSLContextRejectedOverview from "./rejected/SSLContextRejectedOverview";
import useCertificateCollection, { CertificateCollectionResult } from "./useCertificateCollection";
import { getLinkByName } from "./certificates";
import SSLCertificateUpload from "./SSLCertificateUpload";

type Props = {
  links: Links;
};

const SSLContextOverview: FC<Props> = ({ links }) => {
  const [t] = useTranslation("plugins");
  const rejectedResult: CertificateCollectionResult = useCertificateCollection(getLinkByName(links, "rejected"));
  const approvedResult: CertificateCollectionResult = useCertificateCollection(getLinkByName(links, "approved"));

  const refreshApproved = () => {
    approvedResult.refresh();
  };

  return (
    <>
      <Title title={t("scm-ssl-context-plugin.title")} />
      <SSLContextApprovedOverview {...approvedResult} refresh={refreshApproved} />
      <hr />
      <SSLContextRejectedOverview {...rejectedResult} refresh={refreshApproved} />
      <SSLCertificateUpload link={getLinkByName(links, "upload")} refresh={refreshApproved} />
    </>
  );
};

export default SSLContextOverview;
