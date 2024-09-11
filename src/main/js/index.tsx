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

import { binder } from "@scm-manager/ui-extensions";
import { Links } from "@scm-manager/ui-types";
import React, { FC } from "react";
import { Route } from "react-router-dom";
import SSLContextNavigation from "./SSLContextNavigation";
import SSLContextOverview from "./SSLContextOverview";

type PredicateProps = {
  links: Links;
};

export const predicate = ({ links }: PredicateProps) => {
  return !!(links && links.sslContext);
};

const SSLContextRoute: FC<{ links: Links }> = ({ links }) => {
  return (
    <Route path="/admin/ssl-context">
      <SSLContextOverview links={links} />
    </Route>
  );
};

binder.bind("admin.route", SSLContextRoute, predicate);

binder.bind("admin.navigation", SSLContextNavigation, predicate);
