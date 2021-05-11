package com.cloudogu.sslcontext;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;

public class SecureEchoServerExtension implements ParameterResolver, AfterEachCallback {

  private EchoServer echoServer;

  @Override
  public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext) throws ParameterResolutionException {
    return parameterContext.getParameter().getType().equals(EchoServer.class);
  }

  @Override
  public EchoServer resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) throws ParameterResolutionException {
    echoServer = new EchoServer();
    return echoServer;
  }

  @Override
  public void afterEach(ExtensionContext extensionContext) {
    if (echoServer != null) {
      echoServer.close();
      echoServer = null;
    }
  }
}
