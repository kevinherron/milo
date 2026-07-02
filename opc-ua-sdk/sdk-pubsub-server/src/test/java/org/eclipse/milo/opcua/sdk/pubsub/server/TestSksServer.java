/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.server;

import java.net.ServerSocket;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.eclipse.milo.opcua.sdk.server.EndpointConfig;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.OpcUaServerConfig;
import org.eclipse.milo.opcua.sdk.server.OpcUaServerConfigBuilder;
import org.eclipse.milo.opcua.sdk.server.RoleMapper;
import org.eclipse.milo.opcua.stack.core.security.DefaultApplicationGroup;
import org.eclipse.milo.opcua.stack.core.security.DefaultCertificateManager;
import org.eclipse.milo.opcua.stack.core.security.DefaultServerCertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.MemoryCertificateQuarantine;
import org.eclipse.milo.opcua.stack.core.security.MemoryCertificateStore;
import org.eclipse.milo.opcua.stack.core.security.MemoryTrustListManager;
import org.eclipse.milo.opcua.stack.core.security.RsaSha256CertificateFactory;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.transport.TransportProfile;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateBuilder;
import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateGenerator;
import org.eclipse.milo.opcua.stack.transport.server.tcp.OpcTcpServerTransport;
import org.eclipse.milo.opcua.stack.transport.server.tcp.OpcTcpServerTransportConfig;
import org.jspecify.annotations.Nullable;

/**
 * A minimal <b>started</b> embedded {@link OpcUaServer} fixture for the SKS end-to-end tests:
 * unlike {@link TestPubSubServer} (endpoint-less, never started), this fixture binds real {@code
 * opc.tcp} endpoints on {@code 127.0.0.1} with an ephemeral port so real clients — {@code
 * OpcUaClient} sessions and the sdk-pubsub-sks pull provider — can open channels of every {@link
 * MessageSecurityMode} against it.
 *
 * <p>Endpoints (all on one port, path {@code /sks-test}, Anonymous tokens only):
 *
 * <ul>
 *   <li>{@code None}/{@code None}
 *   <li>{@code Basic256Sha256}/{@code Sign}
 *   <li>{@code Basic256Sha256}/{@code SignAndEncrypt}
 * </ul>
 *
 * <p>The server certificate is a generated self-signed certificate whose SAN application URI
 * matches {@link #getApplicationUri()}; clients validate it by adding {@link #getCertificate()} to
 * their own trust lists (the "validating but test-trusting" posture). The server itself validates
 * client certificates against an initially empty trust list: secured clients must be registered via
 * {@link #trustClientCertificate(X509Certificate)} before connecting.
 *
 * <p>Everything is loopback-pinned and in-memory; nothing touches the filesystem or any non-local
 * network. Test-unique application URIs keep concurrently running fixtures distinct.
 */
final class TestSksServer implements AutoCloseable {

  private static final AtomicLong INSTANCE_COUNTER = new AtomicLong();

  private final OpcUaServer server;
  private final MemoryTrustListManager trustListManager;
  private final X509Certificate certificate;
  private final String applicationUri;
  private final String endpointUrl;

  private TestSksServer(
      OpcUaServer server,
      MemoryTrustListManager trustListManager,
      X509Certificate certificate,
      String applicationUri,
      String endpointUrl) {

    this.server = server;
    this.trustListManager = trustListManager;
    this.certificate = certificate;
    this.applicationUri = applicationUri;
    this.endpointUrl = endpointUrl;
  }

  /** A generated client identity: self-signed certificate, key pair, and matching SAN URI. */
  record ClientIdentity(X509Certificate certificate, KeyPair keyPair, String applicationUri) {}

  /** Create and start a {@link TestSksServer} with no {@link RoleMapper} configured. */
  static TestSksServer create() throws Exception {
    return create(null);
  }

  /**
   * Create and start a {@link TestSksServer}, configuring {@code roleMapper} (if non-null) so
   * {@code Session.getRoleIds()} is present for the authorization tests.
   */
  static TestSksServer create(@Nullable RoleMapper roleMapper) throws Exception {
    long instance = INSTANCE_COUNTER.incrementAndGet();
    String applicationUri = "urn:eclipse:milo:pubsub:sks-test-server:" + instance;

    KeyPair keyPair = SelfSignedCertificateGenerator.generateRsaKeyPair(2048);

    X509Certificate certificate =
        new SelfSignedCertificateBuilder(keyPair)
            .setCommonName("Milo PubSub SKS Test Server " + instance)
            .setApplicationUri(applicationUri)
            .addDnsName("localhost")
            .addIpAddress("127.0.0.1")
            .build();

    var certificateFactory =
        new RsaSha256CertificateFactory() {
          @Override
          protected KeyPair createRsaSha256KeyPair() {
            return keyPair;
          }

          @Override
          protected X509Certificate[] createRsaSha256CertificateChain(KeyPair kp) {
            return new X509Certificate[] {certificate};
          }
        };

    var trustListManager = new MemoryTrustListManager();
    var certificateQuarantine = new MemoryCertificateQuarantine();

    var certificateValidator =
        new DefaultServerCertificateValidator(trustListManager, certificateQuarantine);

    DefaultApplicationGroup defaultGroup =
        DefaultApplicationGroup.createAndInitialize(
            trustListManager,
            new MemoryCertificateStore(),
            certificateFactory,
            certificateValidator);

    var certificateManager = new DefaultCertificateManager(certificateQuarantine, defaultGroup);

    int port = freeTcpPort();

    EndpointConfig.Builder base =
        EndpointConfig.newBuilder()
            .setTransportProfile(TransportProfile.TCP_UASC_UABINARY)
            .setBindAddress("127.0.0.1")
            .setBindPort(port)
            .setHostname("127.0.0.1")
            .setPath("/sks-test")
            .setCertificate(certificate)
            .addTokenPolicies(OpcUaServerConfig.USER_TOKEN_POLICY_ANONYMOUS);

    Set<EndpointConfig> endpoints =
        Set.of(
            base.copy()
                .setSecurityPolicy(SecurityPolicy.None)
                .setSecurityMode(MessageSecurityMode.None)
                .build(),
            base.copy()
                .setSecurityPolicy(SecurityPolicy.Basic256Sha256)
                .setSecurityMode(MessageSecurityMode.Sign)
                .build(),
            base.copy()
                .setSecurityPolicy(SecurityPolicy.Basic256Sha256)
                .setSecurityMode(MessageSecurityMode.SignAndEncrypt)
                .build());

    OpcUaServerConfigBuilder configBuilder =
        OpcUaServerConfig.builder()
            .setApplicationUri(applicationUri)
            .setApplicationName(LocalizedText.english("sdk-pubsub-server SKS test server"))
            .setProductUri("urn:eclipse:milo:pubsub:sks-test-server")
            .setEndpoints(endpoints)
            .setCertificateManager(certificateManager);

    if (roleMapper != null) {
      configBuilder.setRoleMapper(roleMapper);
    }

    var server =
        new OpcUaServer(
            configBuilder.build(),
            transportProfile -> {
              if (transportProfile == TransportProfile.TCP_UASC_UABINARY) {
                return new OpcTcpServerTransport(OpcTcpServerTransportConfig.newBuilder().build());
              } else {
                throw new RuntimeException("unexpected TransportProfile: " + transportProfile);
              }
            });

    server.startup().get(30, TimeUnit.SECONDS);

    String endpointUrl = "opc.tcp://127.0.0.1:" + port + "/sks-test";

    return new TestSksServer(server, trustListManager, certificate, applicationUri, endpointUrl);
  }

  /**
   * Generate a fresh client identity (2048-bit RSA self-signed certificate); register it with
   * {@link #trustClientCertificate(X509Certificate)} before opening secured channels.
   */
  static ClientIdentity newClientIdentity() throws Exception {
    long instance = INSTANCE_COUNTER.incrementAndGet();
    String applicationUri = "urn:eclipse:milo:pubsub:sks-test-client:" + instance;

    KeyPair keyPair = SelfSignedCertificateGenerator.generateRsaKeyPair(2048);

    X509Certificate certificate =
        new SelfSignedCertificateBuilder(keyPair)
            .setCommonName("Milo PubSub SKS Test Client " + instance)
            .setApplicationUri(applicationUri)
            .build();

    return new ClientIdentity(certificate, keyPair, applicationUri);
  }

  OpcUaServer getServer() {
    return server;
  }

  /** The server's self-signed certificate; add it to client trust lists. */
  X509Certificate getCertificate() {
    return certificate;
  }

  /** The application URI matching the certificate's SAN URI. */
  String getApplicationUri() {
    return applicationUri;
  }

  /** The loopback endpoint URL all three endpoints share. */
  String getEndpointUrl() {
    return endpointUrl;
  }

  /** Trust {@code certificate} so a client presenting it can open secured channels. */
  void trustClientCertificate(X509Certificate certificate) {
    trustListManager.addTrustedCertificate(certificate);
  }

  @Override
  public void close() throws Exception {
    server.shutdown().get(30, TimeUnit.SECONDS);
  }

  private static int freeTcpPort() throws Exception {
    try (ServerSocket socket = new ServerSocket(0)) {
      return socket.getLocalPort();
    }
  }
}
