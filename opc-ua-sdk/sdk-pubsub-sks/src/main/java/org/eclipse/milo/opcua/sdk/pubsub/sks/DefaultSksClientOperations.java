/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.sks;

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import org.eclipse.milo.opcua.sdk.client.DiscoveryClient;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.OpcUaClientConfig;
import org.eclipse.milo.opcua.sdk.client.OpcUaClientConfigBuilder;
import org.eclipse.milo.opcua.sdk.client.identity.IdentityProvider;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.security.CertificateValidator;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.transport.client.tcp.OpcTcpClientTransport;
import org.eclipse.milo.opcua.stack.transport.client.tcp.OpcTcpClientTransportConfig;
import org.eclipse.milo.opcua.stack.transport.client.tcp.OpcTcpClientTransportConfigBuilder;
import org.jspecify.annotations.Nullable;

/**
 * Production {@link SksClientOperations} backed by {@link DiscoveryClient} (GetEndpoints over an
 * unsecured discovery channel, per Part 4 §5.5.4.1) and {@link OpcUaClient} (the SignAndEncrypt
 * session GetSecurityKeys is invoked on).
 *
 * <p>Session clients are built with {@code sessionEndpointValidationEnabled}, implementing the Part
 * 4 §6.1.4 comparison of the CreateSession response endpoints against the discovery result, and
 * with the caller-supplied {@link CertificateValidator} as the trust posture. The caller's client
 * customizer runs last, so it can override anything set here — including the selected endpoint
 * (e.g. an {@code EndpointUtil.updateUrl} host rewrite when discovery returns unresolvable
 * hostnames).
 *
 * <p>Only {@code opc.tcp} targets are supported, matching {@link
 * DiscoveryClient#getEndpoints(String)}'s transport mapping; SKS discovery URLs are opc.tcp in
 * practice.
 */
final class DefaultSksClientOperations implements SksClientOperations {

  private final CertificateValidator certificateValidator;
  private final Consumer<OpcUaClientConfigBuilder> clientCustomizer;
  private final Consumer<OpcTcpClientTransportConfigBuilder> transportCustomizer;
  private final @Nullable Duration requestTimeout;

  DefaultSksClientOperations(
      CertificateValidator certificateValidator,
      Consumer<OpcUaClientConfigBuilder> clientCustomizer,
      Consumer<OpcTcpClientTransportConfigBuilder> transportCustomizer,
      @Nullable Duration requestTimeout) {

    this.certificateValidator = certificateValidator;
    this.clientCustomizer = clientCustomizer;
    this.transportCustomizer = transportCustomizer;
    this.requestTimeout = requestTimeout;
  }

  @Override
  public CompletableFuture<List<EndpointDescription>> getEndpoints(String discoveryUrl) {
    return DiscoveryClient.getEndpoints(discoveryUrl, transportCustomizer);
  }

  @Override
  public CompletableFuture<Session> connect(
      EndpointDescription endpoint,
      List<EndpointDescription> discoveredEndpoints,
      IdentityProvider identityProvider) {

    OpcUaClient client;
    try {
      OpcUaClientConfigBuilder configBuilder = OpcUaClientConfig.builder();
      configBuilder.setEndpoint(endpoint);
      configBuilder.setDiscoveryEndpoints(discoveredEndpoints);
      configBuilder.setSessionEndpointValidationEnabled(true);
      configBuilder.setCertificateValidator(certificateValidator);
      configBuilder.setIdentityProvider(identityProvider);
      if (requestTimeout != null) {
        configBuilder.setRequestTimeout(uint(requestTimeout.toMillis()));
      }
      clientCustomizer.accept(configBuilder);

      OpcTcpClientTransportConfigBuilder transportConfigBuilder =
          OpcTcpClientTransportConfig.newBuilder();
      transportCustomizer.accept(transportConfigBuilder);

      client =
          new OpcUaClient(
              configBuilder.build(), new OpcTcpClientTransport(transportConfigBuilder.build()));
    } catch (Exception e) {
      return CompletableFuture.failedFuture(e);
    }

    return client
        .connectAsync()
        .<Session>thenApply(c -> new OpcUaClientSession(client))
        .whenComplete(
            (session, ex) -> {
              if (ex != null) {
                client.disconnectAsync();
              }
            });
  }

  private static final class OpcUaClientSession implements Session {

    private final OpcUaClient client;

    private OpcUaClientSession(OpcUaClient client) {
      this.client = client;
    }

    @Override
    public CompletableFuture<CallMethodResult> call(CallMethodRequest request) {
      return client
          .callAsync(List.of(request))
          .thenCompose(
              response -> {
                CallMethodResult[] results = response.getResults();
                if (results == null || results.length != 1 || results[0] == null) {
                  return CompletableFuture.failedFuture(
                      new UaException(
                          StatusCodes.Bad_UnexpectedError,
                          "CallResponse did not contain exactly one result"));
                }
                return CompletableFuture.completedFuture(results[0]);
              });
    }

    @Override
    public CompletableFuture<Void> disconnect() {
      return client.disconnectAsync().thenApply(c -> null);
    }
  }
}
