/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.config;

import java.util.List;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.jspecify.annotations.Nullable;

/**
 * The effective message security of a PubSub component after applying the Part 14 inheritance
 * rules: the {@code PubSubConfig} root supplies default Security Key Services (§6.2.12.4 / Table
 * 232), groups carry the security parameters (§6.2.5.2–6.2.5.4), and a DataSetReader may override
 * its reader group (§6.2.9.9–6.2.9.11, active iff the reader's {@code SecurityMode} is not {@code
 * Invalid}).
 *
 * <p>Resolution is pure config-level bookkeeping (no I/O, no key fetching), intended for the
 * runtime and {@code SecurityKeyProvider} implementations that need one answer to "which mode,
 * which SecurityGroup, and which SKS endpoints apply to this component":
 *
 * <ul>
 *   <li>{@code mode}: the reader override's mode when active, else the group's mode, else {@code
 *       None}.
 *   <li>{@code securityGroup}: the resolved {@link SecurityGroupConfig} named by the reader
 *       override when active (falling back to the group's reference when the override does not
 *       restate one), else the group's; {@code null} when neither names a group or the reference
 *       does not resolve.
 *   <li>{@code securityPolicyUri}: the component's explicit {@link
 *       MessageSecurityConfig#getSecurityPolicyUri()} (reader override first, then group), else the
 *       resolved SecurityGroup's policy URI; {@code null} means "not constrained by config" and the
 *       key provider's policy is authoritative. A group-level explicit URI describes the
 *       <em>group's</em> SecurityGroup: when an active reader override selects a <em>different</em>
 *       SecurityGroup than the group references, the group-level URI does not apply and the
 *       override-selected SecurityGroup's own policy URI wins (the URI an operator pinned for one
 *       group must never constrain — or silently re-key — a different group).
 *   <li>{@code securityKeyServices}: the first non-empty list of reader override (when active),
 *       group, and {@link PubSubConfig#defaultSecurityKeyServices()}.
 * </ul>
 *
 * @param mode the effective {@link MessageSecurityMode}.
 * @param securityGroup the resolved {@link SecurityGroupConfig}, or {@code null} if none applies.
 * @param securityPolicyUri the effective security policy URI, or {@code null} if not configured.
 * @param securityKeyServices the effective Security Key Service endpoints; possibly empty.
 */
public record EffectiveMessageSecurity(
    MessageSecurityMode mode,
    @Nullable SecurityGroupConfig securityGroup,
    @Nullable String securityPolicyUri,
    List<EndpointDescription> securityKeyServices) {

  /**
   * Create a new {@link EffectiveMessageSecurity}, copying the key services list.
   *
   * @param mode the effective {@link MessageSecurityMode}.
   * @param securityGroup the resolved {@link SecurityGroupConfig}, or {@code null} if none applies.
   * @param securityPolicyUri the effective security policy URI, or {@code null} if not configured.
   * @param securityKeyServices the effective Security Key Service endpoints; possibly empty.
   */
  public EffectiveMessageSecurity {
    securityKeyServices = List.copyOf(securityKeyServices);
  }

  /**
   * Check if the effective mode calls for message security.
   *
   * @return {@code true} if the effective mode is {@code Sign} or {@code SignAndEncrypt}.
   */
  public boolean isSecured() {
    return mode == MessageSecurityMode.Sign || mode == MessageSecurityMode.SignAndEncrypt;
  }

  /**
   * Resolve the effective message security of a writer group.
   *
   * @param config the {@link PubSubConfig} the group belongs to.
   * @param group the {@link WriterGroupConfig}.
   * @return the {@link EffectiveMessageSecurity} of the group.
   */
  public static EffectiveMessageSecurity of(PubSubConfig config, WriterGroupConfig group) {
    return resolve(config, group.getMessageSecurity(), null);
  }

  /**
   * Resolve the effective message security of a reader group.
   *
   * @param config the {@link PubSubConfig} the group belongs to.
   * @param group the {@link ReaderGroupConfig}.
   * @return the {@link EffectiveMessageSecurity} of the group.
   */
  public static EffectiveMessageSecurity of(PubSubConfig config, ReaderGroupConfig group) {
    return resolve(config, group.getMessageSecurity(), null);
  }

  /**
   * Resolve the effective message security of a dataset reader, applying its override to the reader
   * group's settings when the override is active (Part 14 §6.2.9.9–6.2.9.11).
   *
   * @param config the {@link PubSubConfig} the group belongs to.
   * @param group the {@link ReaderGroupConfig} the reader belongs to.
   * @param reader the {@link DataSetReaderConfig}.
   * @return the {@link EffectiveMessageSecurity} of the reader.
   */
  public static EffectiveMessageSecurity of(
      PubSubConfig config, ReaderGroupConfig group, DataSetReaderConfig reader) {

    return resolve(config, group.getMessageSecurity(), reader.getMessageSecurity());
  }

  private static EffectiveMessageSecurity resolve(
      PubSubConfig config,
      @Nullable MessageSecurityConfig groupSecurity,
      @Nullable MessageSecurityConfig readerSecurity) {

    // Invalid is the Part 14 §6.2.9.9 "no override" sentinel: treat the reader config as absent.
    MessageSecurityConfig override =
        readerSecurity != null && readerSecurity.getMode() != MessageSecurityMode.Invalid
            ? readerSecurity
            : null;

    MessageSecurityMode mode;
    if (override != null) {
      mode = override.getMode();
    } else {
      mode = groupSecurity != null ? groupSecurity.getMode() : MessageSecurityMode.None;
    }

    SecurityGroupRef ref = null;
    if (override != null && override.getSecurityGroup() != null) {
      ref = override.getSecurityGroup();
    } else if (groupSecurity != null) {
      ref = groupSecurity.getSecurityGroup();
    }

    SecurityGroupConfig securityGroup = null;
    if (ref != null) {
      String name = ref.name();
      securityGroup =
          config.securityGroups().stream()
              .filter(group -> group.getName().equals(name))
              .findFirst()
              .orElse(null);
    }

    // A group-level explicit policy URI applies only to the SecurityGroup the group itself
    // references: when an active reader override selects a DIFFERENT SecurityGroup, the group's
    // URI must not override that group's own policy (see the class Javadoc).
    boolean overrideSelectedDifferentGroup =
        override != null
            && override.getSecurityGroup() != null
            && (groupSecurity == null
                || !override.getSecurityGroup().equals(groupSecurity.getSecurityGroup()));

    String securityPolicyUri = null;
    if (override != null && override.getSecurityPolicyUri() != null) {
      securityPolicyUri = override.getSecurityPolicyUri();
    } else if (!overrideSelectedDifferentGroup
        && groupSecurity != null
        && groupSecurity.getSecurityPolicyUri() != null) {
      securityPolicyUri = groupSecurity.getSecurityPolicyUri();
    } else if (securityGroup != null) {
      securityPolicyUri = securityGroup.getSecurityPolicyUri();
    }

    List<EndpointDescription> securityKeyServices;
    if (override != null && !override.getKeyServices().isEmpty()) {
      securityKeyServices = override.getKeyServices();
    } else if (groupSecurity != null && !groupSecurity.getKeyServices().isEmpty()) {
      securityKeyServices = groupSecurity.getKeyServices();
    } else {
      securityKeyServices = config.defaultSecurityKeyServices();
    }

    return new EffectiveMessageSecurity(
        mode, securityGroup, securityPolicyUri, securityKeyServices);
  }
}
