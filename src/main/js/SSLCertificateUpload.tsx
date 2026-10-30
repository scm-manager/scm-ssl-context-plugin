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

import React, { ChangeEvent, FC, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { apiClient, FileInput } from "@scm-manager/ui-components";
import { Button, ErrorNotification, Notification, Subtitle } from "@scm-manager/ui-core";

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
  const fileInputRef = useRef<HTMLInputElement>(null);

  const isValid = file && file.size < fileSizeLimitBytes;

  const submit = () => {
    const options: RequestInit = {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: file,
    };
    setError(undefined);
    setSubmitNotification(false);
    apiClient
      .httpRequestWithBinaryBody(options, link)
      .then(refresh)
      .then(() => {
        setSubmitNotification(true);
        if (fileInputRef.current) {
          fileInputRef.current.value = "";
          fileInputRef.current.dispatchEvent(new Event("change", { bubbles: true }));
        }
      })
      .catch(setError);
  };

  if (!link) {
    return null;
  }

  return (
    <>
      <hr />
      <Subtitle subtitle={t("scm-ssl-context-plugin.upload.subtitle")} className="mb-3" />
      {submitNotification && (
        <Notification type="success" onClose={() => setSubmitNotification(false)}>
          {t("scm-ssl-context-plugin.upload.submitNotification")}
        </Notification>
      )}
      {file && file.size > fileSizeLimitBytes ? (
        <Notification type="danger">{t("scm-ssl-context-plugin.upload.fileLimit")}</Notification>
      ) : null}
      {error && <ErrorNotification error={error} />}
      <FileInput
        onChange={(event: ChangeEvent<HTMLInputElement>) => {
          setFile(event.target?.files?.[0]);
          setError(undefined);
        }}
        label={t("scm-ssl-context-plugin.upload.label")}
        helpText={t("scm-ssl-context-plugin.upload.helpText")}
        ref={fileInputRef}
      />
      <Button
        className="is-flex ml-auto"
        variant="primary"
        disabled={!isValid || !file}
        onClick={() => submit()}
        type="submit"
      >
        {t("scm-ssl-context-plugin.upload.submit")}
      </Button>
    </>
  );
};

export default SSLCertificateUpload;
