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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetReaderConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.EffectiveMessageSecurity;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublisherId;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupRef;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityContextResolver;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeyMaterial;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.jspecify.annotations.Nullable;

/**
 * The subscriber-side {@link SecurityContextResolver} of one connection: maps a received secured
 * NetworkMessage's plaintext identifiers to the SecurityGroup(s) of the connection's matching
 * readers and selects the key within the group's token window.
 *
 * <p>The SecurityHeader names no SecurityGroup — "The relation to the SecurityGroup is done through
 * DataSetWriterIds contained in the NetworkMessage" (Part 14 Table 154) — so candidate
 * SecurityGroups are the effective SecurityGroups of the readers whose filters match the message's
 * PublisherId / WriterGroupId / DataSetWriterIds. Mode acceptance per §7.2.4.3: a reader whose
 * configured mode is above the received mode cannot accept the message (SHALL drop; the per-reader
 * drop is counted by {@code ReaderDispatcher}'s delivery gate, the single counting point for mode
 * drops), and a reader may process a message secured <em>above</em> its configured mode when its
 * resolved SecurityGroup can supply the keys (the MAY) — so a None-configured reader with a
 * SecurityGroup qualifies, while a None-configured reader without one necessarily drops secured
 * messages.
 *
 * <p>When no candidate resolves the token, this resolver is the counting point for the
 * resolution-time drop reason (per the {@link SecurityContextResolver} contract): unknown token
 * ({@code unknownTokenMessages}, refresh triggered single-flight by the key manager) and stale or
 * past key ({@code staleKeyMessages}), ticked once per NetworkMessage at each candidate reader
 * group's path.
 *
 * <p>Runs on the connection's serialized dispatch thread; never blocks.
 */
final class ReaderSecurityResolver implements SecurityContextResolver {

  private final PubSubServiceImpl service;
  private final ConnectionRuntime connection;

  ReaderSecurityResolver(PubSubServiceImpl service, ConnectionRuntime connection) {
    this.service = service;
    this.connection = connection;
  }

  @Override
  public Optional<SecurityKeyMaterial> resolve(
      @Nullable PublisherId publisherId,
      @Nullable UShort writerGroupId,
      List<UShort> dataSetWriterIds,
      MessageSecurityMode receivedMode,
      UInteger securityTokenId) {

    // candidate SecurityGroups, keyed by ref, remembering one reader-group path each for counting
    Map<SecurityGroupRef, String> candidates = new LinkedHashMap<>(2);

    for (ReaderGroupRuntime group : connection.readerGroupRuntimes()) {
      for (DataSetReaderRuntime reader : group.readerRuntimes()) {
        if (!isCandidate(reader)
            || !matches(reader.config(), publisherId, writerGroupId, dataSetWriterIds)) {
          continue;
        }

        EffectiveMessageSecurity security = reader.effectiveSecurity();
        if (receivedMode.getValue() < security.mode().getValue()) {
          // received mode below configured: this reader SHALL drop (§7.2.4.3); the drop is
          // counted per reader by the dispatcher's delivery gate, never here (single tick)
          continue;
        }
        SecurityGroupConfig securityGroup = security.securityGroup();
        if (securityGroup == null) {
          // no SecurityGroup to supply keys (None-configured reader): counted at the gate
          continue;
        }
        candidates.putIfAbsent(new SecurityGroupRef(securityGroup.getName()), group.path());
      }
    }

    if (candidates.isEmpty()) {
      return Optional.empty();
    }

    SecurityKeyManager keyManager = service.getSecurityKeyManager();

    var results = new LinkedHashMap<String, SecurityKeyManager.SubscriberKeyReason>(2);
    for (Map.Entry<SecurityGroupRef, String> candidate : candidates.entrySet()) {
      SecurityKeyManager.SubscriberKey key =
          keyManager.subscriberKey(candidate.getKey(), securityTokenId);
      if (key.material() != null) {
        return Optional.of(key.material());
      }
      results.merge(
          candidate.getValue(),
          key.reason(),
          // a group path may back multiple candidate SecurityGroups: one tick per group,
          // preferring the more actionable unknown-token verdict
          (a, b) -> a == SecurityKeyManager.SubscriberKeyReason.UNKNOWN_TOKEN ? a : b);
    }

    // nothing resolved: count the resolution-time drop once per candidate reader group
    results.forEach(
        (groupPath, reason) -> {
          if (reason == SecurityKeyManager.SubscriberKeyReason.STALE_KEY) {
            service.getDiagnostics().staleKeyMessage(groupPath);
          } else {
            service.getDiagnostics().unknownTokenMessage(groupPath);
          }
        });

    return Optional.empty();
  }

  /**
   * Trigger a proactive key refresh for every SecurityGroup serving readers that match a received
   * force-key-reset signal (SecurityFlags bit 3): the publisher is about to invalidate its keys
   * (subscriber side). DataSetWriterIds may be unavailable (the signaling message may have been
   * dropped before its payload decoded), so matching is by PublisherId/WriterGroupId only.
   */
  void onForceKeyReset(@Nullable PublisherId publisherId, @Nullable UShort writerGroupId) {
    SecurityKeyManager keyManager = service.getSecurityKeyManager();

    var refs = new LinkedHashMap<SecurityGroupRef, Boolean>(2);
    for (ReaderGroupRuntime group : connection.readerGroupRuntimes()) {
      for (DataSetReaderRuntime reader : group.readerRuntimes()) {
        if (!isCandidate(reader)
            || !matches(reader.config(), publisherId, writerGroupId, List.of())) {
          continue;
        }
        SecurityGroupConfig securityGroup = reader.effectiveSecurity().securityGroup();
        if (securityGroup != null) {
          refs.putIfAbsent(new SecurityGroupRef(securityGroup.getName()), Boolean.TRUE);
        }
      }
    }

    refs.keySet().forEach(keyManager::forceKeyReset);
  }

  /**
   * Whether a reader participates in key resolution: everything not explicitly disabled — a reader
   * Paused because its group is still PreOperational (awaiting its first key fetch) still names the
   * SecurityGroup the connection's secured traffic belongs to.
   */
  private static boolean isCandidate(DataSetReaderRuntime reader) {
    return switch (reader.state()) {
      case Disabled -> false;
      default -> true;
    };
  }

  /**
   * The reader matching chain on the wire identifiers a secured message exposes before its payload
   * is verified (Part 14 §6.2.9 matching; null/0 filter values are wildcards, identifiers absent on
   * the wire cannot be checked).
   */
  private static boolean matches(
      DataSetReaderConfig config,
      @Nullable PublisherId publisherId,
      @Nullable UShort writerGroupId,
      List<UShort> dataSetWriterIds) {

    if (!ReaderDispatcher.publisherIdMatches(config, publisherId)) {
      return false;
    }

    UShort writerGroupIdFilter = config.getWriterGroupId();
    if (writerGroupIdFilter != null
        && writerGroupIdFilter.intValue() != 0
        && writerGroupId != null
        && !writerGroupIdFilter.equals(writerGroupId)) {
      return false;
    }

    UShort dataSetWriterIdFilter = config.getDataSetWriterId();
    if (dataSetWriterIdFilter != null
        && dataSetWriterIdFilter.intValue() != 0
        && !dataSetWriterIds.isEmpty()
        && !dataSetWriterIds.contains(dataSetWriterIdFilter)) {
      return false;
    }

    return true;
  }
}
