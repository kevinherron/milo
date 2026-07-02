/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.internal;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.eclipse.milo.opcua.sdk.pubsub.ComponentType;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetReaderConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.EffectiveMessageSecurity;
import org.eclipse.milo.opcua.sdk.pubsub.config.ReaderGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupRef;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.jspecify.annotations.Nullable;

/**
 * Runtime for one ReaderGroup: holds the DataSetReader runtimes and ensures the connection's
 * subscriber channel is open while the group is active.
 *
 * <p>When the group's effective message security — or any enabled reader's effective override — is
 * secured, activation registers the group with the {@link SecurityKeyManager} for every distinct
 * SecurityGroupRef in use (one atomic {@link SecurityKeyManager#registerAll} call, so a fast
 * provider completing the first ref's fetch can never observe a partial ref set), and the group
 * stays {@code PreOperational} until the initial key fetch of every registered SecurityGroup
 * succeeds (Part 14 §5.4.5.3); its readers are {@code Paused} until then, so no secured traffic is
 * delivered before keys exist. A reader enabled (or added by reconfigure) after the group activated
 * registers its own override's SecurityGroupRef from its activate hook via {@link
 * #ensureReaderSecurityRegistration} — the ctor-time registration map only covers readers enabled
 * when the runtime was built.
 */
final class ReaderGroupRuntime extends AbstractComponentRuntime {

  private final PubSubServiceImpl service;
  private final ConnectionRuntime connection;
  private final ReaderGroupConfig config;

  /**
   * The distinct SecurityGroupRefs the group and its enabled readers' overrides consume keys for,
   * each mapped to (the resolved SecurityGroupConfig, the effective configured policy URI);
   * resolved against the ctor-time config generation. Empty when nothing is secured.
   */
  private final Map<SecurityGroupRef, SecurityRegistration> securityRegistrations;

  /** See {@link WriterGroupRuntime}: consulted by {@link #startupCompletesImmediately()}. */
  private volatile boolean securityKeysReady = false;

  private volatile List<DataSetReaderRuntime> readers;

  ReaderGroupRuntime(
      PubSubServiceImpl service, ConnectionRuntime connection, ReaderGroupConfig config) {

    super(
        ComponentType.READER_GROUP,
        connection.path() + "/" + config.getName(),
        connection,
        config.isEnabled());

    this.service = service;
    this.connection = connection;
    this.config = config;

    var readers = new ArrayList<DataSetReaderRuntime>();
    for (DataSetReaderConfig readerConfig : config.getDataSetReaders()) {
      readers.add(new DataSetReaderRuntime(service, connection, this, readerConfig));
    }
    this.readers = List.copyOf(readers);

    var registrations = new LinkedHashMap<SecurityGroupRef, SecurityRegistration>();
    addSecurityRegistration(
        registrations, EffectiveMessageSecurity.of(service.getConfig(), config));
    for (DataSetReaderRuntime reader : this.readers) {
      if (reader.isEnabled()) {
        addSecurityRegistration(registrations, reader.effectiveSecurity());
      }
    }
    this.securityRegistrations = Map.copyOf(registrations);
  }

  private static void addSecurityRegistration(
      Map<SecurityGroupRef, SecurityRegistration> registrations,
      EffectiveMessageSecurity security) {

    SecurityGroupConfig securityGroup = security.securityGroup();
    if (security.isSecured() && securityGroup != null) {
      registrations.putIfAbsent(
          new SecurityGroupRef(securityGroup.getName()),
          new SecurityRegistration(securityGroup, security.securityPolicyUri()));
    }
  }

  private record SecurityRegistration(
      SecurityGroupConfig securityGroup, @Nullable String securityPolicyUri) {}

  ReaderGroupConfig config() {
    return config;
  }

  List<DataSetReaderRuntime> readerRuntimes() {
    return readers;
  }

  @Override
  List<? extends AbstractComponentRuntime> children() {
    return readers;
  }

  @Override
  void activate() throws UaException {
    checkMessageSecurity();

    // the channel opens BEFORE key registration: activation steps after registering would, on
    // failure, leave an Error group registered as a key consumer with no channel behind it
    connection.ensureSubscriberChannel();

    if (!securityRegistrations.isEmpty()) {
      var registrations =
          new ArrayList<SecurityKeyManager.Registration>(securityRegistrations.size());
      for (Map.Entry<SecurityGroupRef, SecurityRegistration> registration :
          securityRegistrations.entrySet()) {
        registrations.add(
            new SecurityKeyManager.Registration(
                registration.getValue().securityGroup(),
                registration.getKey(),
                registration.getValue().securityPolicyUri()));
      }
      // one atomic call: the manager records the COMPLETE ref set before scheduling any fetch,
      // so a fetch completing mid-registration cannot complete this group's startup while a
      // later ref still lacks keys
      service.getSecurityKeyManager().registerAll(registrations, this);

      securityKeysReady = service.getSecurityKeyManager().allKeysAvailable(this);
    }
  }

  /**
   * Register the SecurityGroupRef of {@code reader}'s effective security with the key manager, with
   * this group as the consuming component (group-level PreOperational gating). Called from the
   * reader's activate hook: a reader enabled — or added by reconfigure — after this group activated
   * may carry an override selecting a SecurityGroup the group's own activation never registered;
   * without registering it here that ref would never fetch keys and every matching secured message
   * would drop as unknown-token forever, silently (fetch-at-startup for the reader-override case).
   * Idempotent for already-registered refs.
   *
   * <p>The ref stays registered until the group deactivates (disabling the reader again does not
   * unregister it — the group is the consumer); {@link #deactivate} removes every ref this group
   * registered, ctor-time and late alike.
   *
   * @throws UaException with {@code Bad_ConfigurationError} if no provider is bound for the ref or
   *     keys are already held under a mismatching policy (the policy registration gate).
   */
  void ensureReaderSecurityRegistration(DataSetReaderRuntime reader) throws UaException {
    EffectiveMessageSecurity security = reader.effectiveSecurity();
    SecurityGroupConfig securityGroup = security.securityGroup();
    if (!security.isSecured() || securityGroup == null) {
      return;
    }
    service
        .getSecurityKeyManager()
        .register(
            securityGroup,
            new SecurityGroupRef(securityGroup.getName()),
            this,
            security.securityPolicyUri());
  }

  /**
   * A secured reader group completes startup only when key material is available for every
   * SecurityGroup it registered for (Part 14 §5.4.5.3); until then it stays {@code PreOperational}
   * and its readers {@code Paused}. The key manager completes startup on the first successful fetch
   * of the last outstanding SecurityGroup.
   */
  @Override
  boolean startupCompletesImmediately() {
    return securityRegistrations.isEmpty() || securityKeysReady;
  }

  @Override
  void deactivate() {
    service.getSecurityKeyManager().unregister(this);
    securityKeysReady = false;
  }

  /** Release all resources of this runtime. The runtime is unusable afterwards. */
  void dispose() {
    service.getSecurityKeyManager().unregister(this);
    readers.forEach(DataSetReaderRuntime::dispose);
  }

  void addReaderRuntime(DataSetReaderRuntime reader) {
    var readers = new ArrayList<>(this.readers);
    readers.add(reader);
    this.readers = List.copyOf(readers);
  }

  void removeReaderRuntime(DataSetReaderRuntime reader) {
    var readers = new ArrayList<>(this.readers);
    readers.remove(reader);
    this.readers = List.copyOf(readers);
  }

  @Nullable DataSetReaderRuntime findReaderRuntime(String name) {
    for (DataSetReaderRuntime reader : readers) {
      if (reader.config().getName().equals(name)) {
        return reader;
      }
    }
    return null;
  }

  /**
   * Re-run the message security validation at activation (the activation-time backstop precedent):
   * a secured JSON-mapped reader, or a secured group/reader without a resolvable SecurityGroupRef,
   * a supported policy, or a bound SecurityKeyProvider, fails into {@code PubSubState.Error} with
   * {@code Bad_ConfigurationError}. Startup/reconfigure validation only sees enabled components, so
   * this closes the disabled-at-startup-then-enabled gap.
   */
  private void checkMessageSecurity() throws UaException {
    String error = service.messageSecurityConfigError(service.getConfig(), config, path());
    if (error != null) {
      var e = new UaException(StatusCodes.Bad_ConfigurationError, error);
      service.getDiagnostics().error(path(), e.getStatusCode(), e.getMessage(), e);
      throw e;
    }
  }
}
