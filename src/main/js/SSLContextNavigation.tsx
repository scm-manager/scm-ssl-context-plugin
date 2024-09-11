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
import { SecondaryNavigationItem } from "@scm-manager/ui-components";
import { useTranslation } from "react-i18next";
import { useRouteMatch } from "react-router-dom";

const SSLContextNavigation: FC = () => {
  const [t] = useTranslation("plugins");
  const match = useRouteMatch();

  const matchesSslContext = (route: any) => {
    const regex = new RegExp("/admin/ssl-context/.+");
    return !!route.location.pathname.match(regex);
  };

  return (
    <SecondaryNavigationItem
      to={match.url + "/ssl-context/"}
      icon="fas fa-certificate"
      label={t("scm-ssl-context-plugin.navLink")}
      title={t("scm-ssl-context-plugin.navLink")}
      activeWhenMatch={matchesSslContext}
      activeOnlyWhenExact={false}
    />
  );
};

export default SSLContextNavigation;
