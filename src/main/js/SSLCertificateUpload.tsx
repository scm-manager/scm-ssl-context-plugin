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

import {
  apiClient,
  ErrorNotification,
  FileInput,
  Level,
  Notification,
  SubmitButton,
  Subtitle
} from "@scm-manager/ui-components";
import React, { ChangeEvent, FC, useState } from "react";
import { useTranslation } from "react-i18next";

type Props = {
  link: string;
  refresh: () => void;
};

const fileSizeLimitBytes = 50000;

const SSLCertificateUpload: FC<Props> = ({ link, refresh }) => {
  const [t] = useTranslation("plugins");
  const [error, setError] = useState<Error | undefined>();
  const [file, setFile] = useState<File>();
  const [submitNotification, setSubmitNotification] = useState(false);

  const notifications = (
    <>
      {submitNotification && (
        <Notification onClose={() => setSubmitNotification(false)}>
          {t("scm-ssl-context-plugin.upload.submitNotification")}
        </Notification>
      )}
      {error && <ErrorNotification error={error} />}
    </>
  );

  const isValid = file && file.size < fileSizeLimitBytes;

  const submit = () => {
    const options: RequestInit = {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: file
    };
    setSubmitNotification(false);
    apiClient
      .httpRequestWithBinaryBody(options, link)
      .then(refresh)
      .then(() => setSubmitNotification(true))
      .catch(setError);
  };

  if (!link) {
    return null;
  }

  return (
    <>
      <hr />
      <Subtitle subtitle={t("scm-ssl-context-plugin.upload.subtitle")} className="mb-3" />
      <FileInput
        onChange={(event: ChangeEvent<HTMLInputElement>) => setFile(event.target?.files?.[0])}
        label={t("scm-ssl-context-plugin.upload.label")}
        helpText={t("scm-ssl-context-plugin.upload.helpText")}
      />
      {file && file.size > fileSizeLimitBytes ? (
        <Notification type="danger">{t("scm-ssl-context-plugin.upload.fileLimit")}</Notification>
      ) : null}
      {notifications}
      <Level
        right={
          <SubmitButton
            disabled={!isValid || !file}
            label={t("scm-ssl-context-plugin.upload.submit")}
            action={() => submit()}
            scrollToTop={false}
          />
        }
      />
    </>
  );
};

export default SSLCertificateUpload;
