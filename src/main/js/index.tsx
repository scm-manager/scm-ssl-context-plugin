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
