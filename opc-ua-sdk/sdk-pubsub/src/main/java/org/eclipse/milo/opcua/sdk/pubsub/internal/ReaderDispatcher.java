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

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;

import io.netty.buffer.ByteBuf;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetFieldValue;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetReceivedEvent;
import org.eclipse.milo.opcua.sdk.pubsub.MetaDataReceivedEvent;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetMetaDataConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetReaderConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.EffectiveMessageSecurity;
import org.eclipse.milo.opcua.sdk.pubsub.config.MetadataPolicy;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublisherId;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.UadpDataSetReaderSettings;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.DataSetMessageKind;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.DecodeContext;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.DecodedDataSetMessage;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.DecodedField;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.DecodedMetaData;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.DecodedNetworkMessage;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.MessageMappingProvider;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.UadpDecodedMessage;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.UadpDiscoveryProbe;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.UadpMessageMapping;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.UadpMetaDataAnnouncement;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState;
import org.eclipse.milo.opcua.stack.core.types.structured.ConfigurationVersionDataType;
import org.jspecify.annotations.Nullable;

/**
 * Subscriber-side dispatch: decodes received datagrams and routes the decoded DataSetMessages to
 * the matching DataSetReaders via the Part 14 filter chain (§6.2.9.x / §6.3.1.4.x), where null/0
 * filter values are wildcards.
 *
 * <p>Runs entirely on the transport executor; decode and match failures are counted in diagnostics
 * and never thrown. The connection's {@code networkMessagesReceived} counter ticks once per
 * arrival, before any decode attempt; decode failures tick {@code decodeErrors} at the connection
 * path unless another of the connection's mappings decoded content — DataSetMessages, metadata, or
 * a discovery message — from the same buffer (on mixed-mapping broker connections every message is
 * offered to every mapping, so the "wrong" mapping's failure on a message the right mapping decoded
 * is expected and not an error). A mapping's own partial content never suppresses its own failure:
 * a truncated message that still delivered a decodable prefix ticks that mapping's failure once
 * while suppressing the other mappings' failures on the same bytes. A tolerated skip that decoded
 * nothing, such as the UADP decoder skipping foreign input by its version nibble, suppresses
 * nothing: a buffer no mapping could decode ticks {@code decodeErrors} once per failed mapping. A
 * reader group with a non-zero {@code maxNetworkMessageSize} never sees messages larger than it;
 * such messages tick {@code decodeErrors} at the group path with {@code
 * Bad_EncodingLimitsExceeded}.
 *
 * <p>Data and event DataSetMessages that carry sequence numbers pass a per-reader, per-stream Part
 * 14 §7.2.3 recency window before delivery — the NetworkMessage window first (a stale or invalid
 * NetworkMessage suppresses all its matched DataSetMessages for that reader), then the
 * DataSetMessage window. The DataSetMessage window advances only on delivered messages; the
 * NetworkMessage window is classified — and, on a NEW verdict, advanced — exactly once per (reader,
 * NetworkMessage) for every NetworkMessage that passes {@code matchesNetworkMessage} and carries a
 * sequence number, regardless of whether any contained DataSetMessage matches the reader's
 * dataSetWriterId filter: the publisher consumes one NetworkMessage sequence number for every
 * NetworkMessage it sends (§7.2.3 "incremented by exactly one for each message"), so
 * NetworkMessages carrying only keep-alives, only DataSetMessages dropped at the DataSetMessage
 * window, or only other writers' DataSetMessages all advance the window too. Stale and invalid
 * messages are dropped: not delivered, counted in the reader's {@code staleSequenceMessages} /
 * {@code invalidSequenceMessages} (not in {@code dataSetMessagesReceived}) once per matched
 * DataSetMessage they suppress — a NetworkMessage with no matched DataSetMessages ticks nothing —
 * and, per §6.2.9.6, where a data DataSetMessage is "new" only if its sequence number increments,
 * they do not reset the receive timeout, complete startup, or recover the reader from Error.
 * Messages without a sequence number bypass the window entirely ("each received DataSetMessage is
 * considered new", §6.2.9.6). Keep-alives never advance a seeded DataSetMessage window on a
 * consistent carried value — they may seed an unseeded stream with their carried next-expected
 * number, and they reseed a seeded window whose verdict on the carried value is stale or invalid,
 * per §7.2.4.5.8 (the carried value is the publisher's authoritative next expected sequence number,
 * so a restarted publisher's keep-alives recover its streams; see {@link ReaderSequenceTracker}) —
 * they refresh the stream's §7.2.3 record-discard clock (a keep-alive is a received message), and
 * they always reset the receive timeout — while the NetworkMessage that carries them is an ordinary
 * NetworkMessage whose sequence number advances the NetworkMessage window normally.
 *
 * <p><b>Message security</b> (Phase 4): decode runs with the connection's {@link
 * ReaderSecurityResolver} and per-connection {@code ChunkReassembler} on the {@link DecodeContext}.
 * Security-failure classification maps the decoder's failure taxonomy to the per-component
 * counters: {@code SIGNATURE_INVALID} to {@code invalidSignatureMessages} and {@code
 * DECRYPT_FAILED} to {@code decryptionErrors} (ticked at each matched reader group, or the
 * connection when none matches); {@code UNRESOLVED_KEYS} is counted by the resolver (unknown token,
 * stale key) or the per-reader mode gate here, never twice; the remaining reasons flow through the
 * existing {@code decodeErrors} path. Per K7 (§7.2.4.3), a per-reader security gate runs BEFORE the
 * sequence windows: a reader drops (counted in {@code securityModeRejectedMessages})
 * NetworkMessages whose received mode is below its configured mode — including unsecured messages
 * at a secured reader — and secured messages it has no SecurityGroup to supply keys for; a message
 * secured <em>above</em> the configured mode is processed when keys resolved (the MAY). Per K18, a
 * message that failed its security checks (unsupported header, rejected mode, unresolved keys,
 * invalid signature, or any decode failure on a secured message that never passed signature
 * verification — e.g. one truncated too short to carry its signature) never advances any sequence
 * window and delivers nothing — with security active, only verified messages reach the §7.2.3
 * window (a DECRYPT_FAILED message passed verification: its authentic partial content still flows).
 * Discovery metadata announcements stay mode-None by design (K10) and are exempt from the mode
 * gate. A received force-key-reset flag triggers a proactive key refresh even on dropped messages.
 */
final class ReaderDispatcher {

  /** dataSetFieldId used when no metadata names a decoded field. */
  private static final UUID NULL_FIELD_ID = new UUID(0L, 0L);

  private final PubSubServiceImpl service;

  ReaderDispatcher(PubSubServiceImpl service) {
    this.service = service;
  }

  /**
   * Decode and dispatch one received datagram. Must be called on the transport executor; the caller
   * retains ownership of {@code buffer}.
   *
   * <p>For the built-in UADP mapping the discovery-aware decode is used, so probes arriving on the
   * data socket are routed to the connection's discovery responder and announcements — including
   * Bad-status denials — reach the metadata path regardless of which socket they arrived on.
   */
  void dispatch(ConnectionRuntime connection, ByteBuf buffer) {
    // "received" means "a message arrived and was offered to decode": tick once per arrival,
    // before any mapping runs, so the counter is independent of the decode outcome
    service.getDiagnostics().networkMessageReceived(connection.path());

    // Milo extension: a reader group with a non-zero maxNetworkMessageSize does not accept
    // messages larger than it (Part 14 gives the parameter no receive-side semantics)
    Set<ReaderGroupRuntime> oversizeGroups = oversizeGroups(connection, buffer.readableBytes());

    Map<String, MessageMappingProvider> mappings = connection.subscriberMappings();

    // decode failures are deferred: on mixed-mapping connections every message is offered to
    // every mapping, so a mapping's failure only counts when no OTHER mapping decoded content
    // from the buffer; a mapping's own partial content never suppresses its own failure
    Set<String> mappingsWithContent = null;
    List<DecodeFailure> failures = null;

    // the security resolver and the (stateful, per-connection) chunk reassembler ride the
    // context: the same reassembler instance must see every decode of this connection or
    // reassembly never completes
    DecodeContext context =
        DecodeContext.of(
            service.getEncodingContext(),
            connection.securityResolver(),
            connection.chunkReassembler());

    for (Map.Entry<String, MessageMappingProvider> entry : mappings.entrySet()) {
      String mappingName = entry.getKey();
      MessageMappingProvider provider = entry.getValue();

      UadpDecodedMessage decoded;
      try {
        if (provider instanceof UadpMessageMapping uadpMapping) {
          decoded = uadpMapping.decodeMessage(context, buffer.slice());
        } else {
          decoded = provider.decode(context, buffer.slice());
        }
      } catch (Exception e) {
        if (failures == null) {
          failures = new ArrayList<>(1);
        }
        failures.add(
            new DecodeFailure(
                mappingName,
                UaException.extractStatusCode(e)
                    .orElse(new StatusCode(StatusCodes.Bad_DecodingError)),
                "failed to decode NetworkMessage: " + e.getMessage(),
                e));
        continue;
      }

      DecodedNetworkMessage.Failure failure =
          decoded instanceof DecodedNetworkMessage networkMessage ? networkMessage.failure() : null;
      if (failure != null) {
        switch (failure.reason()) {
          case UNRESOLVED_KEYS -> {
            // deliberately uncounted here: the resolution-time drop was already counted at its
            // deciding point — the resolver/key manager (unknown token, stale key) or the
            // per-reader mode gate in handleDecoded — counting the decoder failure too would
            // double count
          }
          case SIGNATURE_INVALID ->
              securityFailure(
                  connection, (DecodedNetworkMessage) decoded, failure, oversizeGroups, true);
          case DECRYPT_FAILED ->
              securityFailure(
                  connection, (DecodedNetworkMessage) decoded, failure, oversizeGroups, false);
          default -> {
            // the tolerant UADP decode surfaced a failure: count it via the decodeErrors path,
            // but still deliver whatever was decoded before the failure point
            if (failures == null) {
              failures = new ArrayList<>(1);
            }
            failures.add(
                new DecodeFailure(
                    mappingName,
                    failure.statusCode(),
                    "failed to decode NetworkMessage: " + failure.message(),
                    failure.cause()));
          }
        }
      }

      // content is tracked independently of failure: a truncated message that still delivered a
      // decodable prefix makes the OTHER mappings' failures on the same bytes expected, while its
      // own failure above stays observable
      if (decodedContent(decoded)) {
        if (mappingsWithContent == null) {
          mappingsWithContent = new HashSet<>(2);
        }
        mappingsWithContent.add(mappingName);
      }

      if (decoded instanceof DecodedNetworkMessage networkMessage) {
        handleDecoded(connection, mappingName, networkMessage, oversizeGroups);
      } else if (decoded instanceof UadpDiscoveryProbe probe) {
        DiscoveryRuntime discovery = connection.discoveryRuntime();
        if (discovery != null) {
          discovery.onProbeReceived(probe);
        }
      } else if (decoded instanceof UadpMetaDataAnnouncement announcement) {
        handleAnnouncement(connection, mappingName, announcement, oversizeGroups);
      }
    }

    if (failures != null) {
      for (DecodeFailure failure : failures) {
        if (otherMappingDecodedContent(mappingsWithContent, failure.mappingName())) {
          continue;
        }
        service
            .getDiagnostics()
            .decodeError(
                connection.path(), failure.statusCode(), failure.message(), failure.error());
      }
    }
  }

  /** A decode failure deferred until every mapping has had its decode attempt. */
  private record DecodeFailure(
      String mappingName, StatusCode statusCode, String message, @Nullable Throwable error) {}

  /**
   * Count a definitive security verdict on a received secured NetworkMessage — an invalid signature
   * ({@code invalidSignatureMessages}) or an authenticated-but-unparseable payload ({@code
   * decryptionErrors}) — once at every reader group with a receiving reader matching the message's
   * plaintext header identifiers, or at the connection when no group matches (so tampered traffic
   * aimed at nobody is still observable). Not subject to the mixed-mapping decode-failure
   * suppression: a failed signature on resolved key material is a real security event regardless of
   * what other mappings made of the same bytes.
   */
  private void securityFailure(
      ConnectionRuntime connection,
      DecodedNetworkMessage decoded,
      DecodedNetworkMessage.Failure failure,
      Set<ReaderGroupRuntime> oversizeGroups,
      boolean invalidSignature) {

    String message = "secured NetworkMessage dropped: " + failure.message();

    boolean attributed = false;
    for (ReaderGroupRuntime group : connection.readerGroupRuntimes()) {
      if (oversizeGroups.contains(group)) {
        continue;
      }
      for (DataSetReaderRuntime reader : group.readerRuntimes()) {
        if (isNotReceiving(reader.state())) {
          continue;
        }
        if (matchesNetworkMessage(reader.config(), decoded)) {
          attributed = true;
          if (invalidSignature) {
            service
                .getDiagnostics()
                .invalidSignatureMessage(
                    group.path(), failure.statusCode(), message, failure.cause());
          } else {
            service
                .getDiagnostics()
                .decryptionError(group.path(), failure.statusCode(), message, failure.cause());
          }
          break;
        }
      }
    }

    if (!attributed) {
      if (invalidSignature) {
        service
            .getDiagnostics()
            .invalidSignatureMessage(
                connection.path(), failure.statusCode(), message, failure.cause());
      } else {
        service
            .getDiagnostics()
            .decryptionError(connection.path(), failure.statusCode(), message, failure.cause());
      }
    }
  }

  /**
   * Whether a decode failure means the message failed its security checks: such a message delivers
   * nothing and must not advance any sequence window (K18 — only verified messages reach the §7.2.3
   * window). {@code DECRYPT_FAILED} is deliberately NOT a fixed member of this set: its signature
   * verified, so its authentic partial content flows through the normal path — and by the same
   * reasoning any failure on a secured message that never passed verification IS a security drop,
   * whatever its taxonomy bucket: a secured message truncated too short to carry its signature is
   * classified {@code DECODING_ERROR} before {@code verify()} ever runs, and its attacker-supplied
   * plaintext GroupHeader sequence number must not poison the window (an off-path attacker can
   * craft one from any observed live tokenId, no key knowledge required). Unsecured messages
   * ({@code security == null} or the processed-as-unsecured force-key-reset-only mode-None header)
   * keep the pre-existing HG2 partial-decode window behavior.
   */
  private static boolean isSecurityDrop(
      DecodedNetworkMessage.Failure.Reason reason,
      DecodedNetworkMessage.@Nullable Security security) {

    return switch (reason) {
      case SECURITY_UNSUPPORTED, SECURITY_MODE_REJECTED, UNRESOLVED_KEYS, SIGNATURE_INVALID -> true;
      case DECODING_ERROR, DECRYPT_FAILED, CHUNK ->
          // a failure on a secured message that never verified is unauthenticated (K18); a
          // failure on a VERIFIED secured message occurred after verification (sign-only payload
          // parse, decrypted-payload structure, chunk consumption) and its authentic content and
          // header values flow the normal tolerant path
          security != null && security.mode() != MessageSecurityMode.None && !security.verified();
    };
  }

  /**
   * The per-reader K7 security gate (Part 14 §7.2.4.3): a reader SHALL drop messages whose received
   * mode is below its configured effective mode — an unsecured message at a secured reader included
   * — and necessarily drops messages secured <em>above</em> its configured mode when it has no
   * SecurityGroup to supply keys; with a SecurityGroup, processing above the configured mode is the
   * spec's MAY. Runs BEFORE the sequence windows so a rejected (and, for received-below-configured,
   * unverified) message can never advance a window (K18).
   */
  private static boolean securityGateRejects(
      DataSetReaderRuntime reader, DecodedNetworkMessage.@Nullable Security security) {

    EffectiveMessageSecurity configured = reader.effectiveSecurity();

    int received =
        security == null ? MessageSecurityMode.None.getValue() : security.mode().getValue();
    int required = configured.mode().getValue();

    if (received < required) {
      return true;
    }
    if (received > required) {
      SecurityGroupConfig securityGroup = configured.securityGroup();
      return securityGroup == null;
    }
    return false;
  }

  /**
   * Whether any mapping other than {@code mappingName} decoded content from the buffer: the
   * mixed-mapping suppression condition for a failure recorded by {@code mappingName}. A mapping's
   * own partial content keeps its own failure observable.
   */
  private static boolean otherMappingDecodedContent(
      @Nullable Set<String> mappingsWithContent, String mappingName) {

    if (mappingsWithContent == null) {
      return false;
    }
    for (String name : mappingsWithContent) {
      if (!name.equals(mappingName)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Whether a decode actually decoded something from the buffer: DataSetMessages, metadata, or a
   * discovery probe/announcement — including content decoded before a surfaced failure point.
   *
   * <p>The distinction carries the mixed-mapping suppression guard: only a mapping that decoded
   * content from a buffer makes another mapping's failure on the same buffer expected. The tolerant
   * UADP decode returns an empty, failure-free result for foreign input it merely skips (e.g. a
   * JSON document's '{' fails the version-nibble check), and an empty skip that decoded nothing
   * must not suppress another mapping's genuine failure — otherwise a malformed JSON payload on a
   * mixed uadp+json connection would never tick {@code decodeErrors}.
   */
  private static boolean decodedContent(UadpDecodedMessage decoded) {
    if (decoded instanceof DecodedNetworkMessage networkMessage) {
      return !networkMessage.messages().isEmpty() || !networkMessage.metaData().isEmpty();
    }
    // a discovery probe or metadata announcement is decoded content by definition
    return true;
  }

  /**
   * The receiving reader groups whose non-zero maxNetworkMessageSize excludes a message of {@code
   * messageSize} bytes, each ticked with a group-path decodeError.
   */
  private Set<ReaderGroupRuntime> oversizeGroups(ConnectionRuntime connection, int messageSize) {
    Set<ReaderGroupRuntime> oversizeGroups = Set.of();

    for (ReaderGroupRuntime group : connection.readerGroupRuntimes()) {
      if (isNotReceiving(group.state())) {
        continue;
      }
      long maxNetworkMessageSize = group.config().getMaxNetworkMessageSize().longValue();
      if (maxNetworkMessageSize > 0 && messageSize > maxNetworkMessageSize) {
        service
            .getDiagnostics()
            .decodeError(
                group.path(),
                new StatusCode(StatusCodes.Bad_EncodingLimitsExceeded),
                "NetworkMessage not accepted: size %d exceeds maxNetworkMessageSize %d"
                    .formatted(messageSize, maxNetworkMessageSize),
                null);

        if (oversizeGroups.isEmpty()) {
          oversizeGroups = new HashSet<>(2);
        }
        oversizeGroups.add(group);
      }
    }

    return oversizeGroups;
  }

  private void handleDecoded(
      ConnectionRuntime connection,
      String mappingName,
      DecodedNetworkMessage decoded,
      Set<ReaderGroupRuntime> oversizeGroups) {

    DecodedNetworkMessage.Security security = decoded.security();
    DecodedNetworkMessage.Failure failure = decoded.failure();
    boolean securityDropped = failure != null && isSecurityDrop(failure.reason(), security);
    boolean unresolvedKeys =
        failure != null && failure.reason() == DecodedNetworkMessage.Failure.Reason.UNRESOLVED_KEYS;

    if (security != null && security.forceKeyReset()) {
      // Table 154 bit 3: the publisher is about to invalidate its keys — refresh proactively
      // (K6, subscriber side). Surfaced even on dropped messages, so this runs before any gate.
      connection.securityResolver().onForceKeyReset(decoded.publisherId(), decoded.writerGroupId());
    }

    for (ReaderGroupRuntime group : connection.readerGroupRuntimes()) {
      if (oversizeGroups.contains(group)) {
        continue;
      }

      boolean groupMatched = false;

      for (DataSetReaderRuntime reader : group.readerRuntimes()) {
        if (!reader.mappingName().equals(mappingName)) {
          continue;
        }
        if (isNotReceiving(reader.state())) {
          continue;
        }

        // metadata announcements match on (PublisherId, DataSetWriterId) only; discovery and
        // metadata NetworkMessages stay mode-None by design (K10), so no mode gate applies
        for (DecodedMetaData metaData : decoded.metaData()) {
          if (publisherIdMatches(reader.config(), decoded.publisherId())
              && dataSetWriterIdMatches(reader.config(), metaData.dataSetWriterId())) {
            handleMetaData(connection, reader, metaData);
          }
        }

        if (matchesNetworkMessage(reader.config(), decoded)) {
          if (securityDropped) {
            // K18: a message that failed its security checks delivers nothing and must not
            // advance any sequence window. For the resolver-decided UNRESOLVED_KEYS drop the
            // per-reader K7 mode drops are still counted here (the resolver skips
            // mode-incompatible readers without counting; this is the single counting point) —
            // decoder-decided and signature verdicts were counted in dispatch().
            if (unresolvedKeys && securityGateRejects(reader, security)) {
              service.getDiagnostics().securityModeRejectedMessage(reader.path());
            }
            continue;
          }

          if (securityGateRejects(reader, security)) {
            // §7.2.4.3 SHALL: dropped for this reader, counted, and — deliberately BEFORE the
            // window observation — never advancing the reader's sequence windows: an unsecured
            // (unverified) message must not move a secured reader's replay window (K18)
            service.getDiagnostics().securityModeRejectedMessage(reader.path());
            continue;
          }

          long nowNanos = System.nanoTime();

          // one NetworkMessage-window observation per (reader, NetworkMessage), BEFORE the
          // dataSetWriterId filter loop: the (PublisherId, WriterGroupId) stream consumed this
          // sequence number whether or not any contained DataSetMessage matches this reader,
          // and the single observation also keeps a NEW verdict from making sibling
          // DataSetMessages of the same NetworkMessage classify as duplicates
          SequenceNumberWindow.Classification networkMessageClassification =
              observeNetworkMessage(reader.sequenceTracker(), decoded, nowNanos);

          for (DecodedDataSetMessage message : decoded.messages()) {
            if (dataSetWriterIdMatches(reader.config(), message.dataSetWriterId())) {
              groupMatched = true;
              deliver(
                  connection,
                  group,
                  reader,
                  decoded,
                  message,
                  networkMessageClassification,
                  nowNanos);
            }
          }
        }
      }

      if (groupMatched) {
        service.getDiagnostics().networkMessageReceived(group.path());
      }
    }
  }

  /**
   * Route one decoded DataSetMetaData announcement, received on either the data socket or the
   * connection's discovery socket: non-Bad announcements are matched to readers on (PublisherId,
   * DataSetWriterId) and applied like the data-plane metadata path; Bad-status announcements are
   * denials, which terminate matching discovery probe tasks (Part 14 §7.2.4.6.12.2).
   */
  void handleAnnouncement(
      ConnectionRuntime connection, String mappingName, UadpMetaDataAnnouncement announcement) {
    handleAnnouncement(connection, mappingName, announcement, Set.of());
  }

  private void handleAnnouncement(
      ConnectionRuntime connection,
      String mappingName,
      UadpMetaDataAnnouncement announcement,
      Set<ReaderGroupRuntime> oversizeGroups) {

    if (announcement.statusCode().isBad()) {
      DiscoveryRuntime discovery = connection.discoveryRuntime();
      if (discovery != null) {
        discovery.onMetaDataDenied(announcement);
      }
      return;
    }

    var metaData = new DecodedMetaData(announcement.dataSetWriterId(), announcement.metaData());

    for (ReaderGroupRuntime group : connection.readerGroupRuntimes()) {
      if (oversizeGroups.contains(group)) {
        continue;
      }

      for (DataSetReaderRuntime reader : group.readerRuntimes()) {
        if (!reader.mappingName().equals(mappingName)) {
          continue;
        }
        if (isNotReceiving(reader.state())) {
          continue;
        }

        if (publisherIdMatches(reader.config(), announcement.publisherId())
            && dataSetWriterIdMatches(reader.config(), announcement.dataSetWriterId())) {
          handleMetaData(connection, reader, metaData);
        }
      }
    }
  }

  private void deliver(
      ConnectionRuntime connection,
      ReaderGroupRuntime group,
      DataSetReaderRuntime reader,
      DecodedNetworkMessage networkMessage,
      DecodedDataSetMessage message,
      SequenceNumberWindow.@Nullable Classification networkMessageClassification,
      long nowNanos) {

    // a matched message reveals the identifiers a wildcard-filtered REQUEST_IF_MISSING reader
    // needs before it can emit discovery probes
    DiscoveryRuntime discovery = connection.discoveryRuntime();
    if (discovery != null && discovery.hasDeferredProbes()) {
      discovery.onDataSetMessageMatched(
          reader, networkMessage.publisherId(), message.dataSetWriterId());
    }

    ReaderSequenceTracker tracker = reader.sequenceTracker();

    if (message.kind() == DataSetMessageKind.KEEP_ALIVE) {
      // the keep-alive is never dropped on the NetworkMessage verdict: keep-alives always reset
      // the receive timeout (§6.2.9.6 "The DataSetMessages that reset the period include
      // keep-alive and heartbeat messages").
      //
      // a keep-alive carries the next expected sequence number WITHOUT consuming it (Part 14
      // §7.2.4.5.8, §7.2.5.4.1): it may seed an unseeded stream window; on a seeded one it never
      // advances on a consistent carried value — advancing would make the next data message,
      // which carries the same number, classify as a duplicate — but reseeds the window when the
      // carried value classifies stale/invalid (the publisher is authoritative about its own
      // counter, §7.2.4.5.8). It refreshes the stream's §7.2.3 record-discard clock (a
      // keep-alive is a received message, so a keep-alive-only period must not discard the
      // record) and always resets the receive timeout (§6.2.9.6)
      UInteger keepAliveSequence = message.sequenceNumber();
      if (keepAliveSequence != null) {
        tracker.observeKeepAlive(
            networkMessage.publisherId(), message.dataSetWriterId(), keepAliveSequence, nowNanos);
      }
      service.getDiagnostics().dataSetMessageReceived(group.path());
      service.getDiagnostics().dataSetMessageReceived(reader.path());
      reader.onMessageAccepted();
      return;
    }

    if (!message.valid()) {
      service.getDiagnostics().dataSetMessageReceived(group.path());
      service.getDiagnostics().dataSetMessageReceived(reader.path());
      service
          .getDiagnostics()
          .decodeError(
              reader.path(),
              new StatusCode(StatusCodes.Bad_DecodingError),
              "DataSetMessage with valid=false dropped",
              null);
      return;
    }

    DataSetMetaDataConfig metaData = effectiveMetaData(reader);

    // The major version can only be checked when it is transmitted: the decoder substitutes 0
    // when DataSetFlags1 bit 5 is clear (e.g. the default UADP-Dynamic mask carries only the
    // minor version), and a VersionTime of 0 means "not used" per Part 14.
    ConfigurationVersionDataType version = message.configurationVersion();
    if (version != null
        && metaData != null
        && version.getMajorVersion().longValue() != 0L
        && !version.getMajorVersion().equals(metaData.getConfigurationVersionMajor())) {

      // do not reset the receive timeout: per §6.2.9.4 a reader that cannot obtain matching
      // metadata within messageReceiveTimeout goes to Error
      service.getDiagnostics().dataSetMessageReceived(group.path());
      service.getDiagnostics().dataSetMessageReceived(reader.path());
      service
          .getDiagnostics()
          .decodeError(
              reader.path(),
              new StatusCode(StatusCodes.Bad_ConfigurationError),
              "DataSetMetaData major version mismatch: message=%s, local=%s"
                  .formatted(version.getMajorVersion(), metaData.getConfigurationVersionMajor()),
              null);
      return;
    }

    // Part 14 §7.2.3 sequence-number windows: the NetworkMessage verdict first — a stale or
    // invalid NetworkMessage (observed once per (reader, NetworkMessage) by the caller, before
    // the dataSetWriterId filter) suppresses every matched DataSetMessage it carries for this
    // reader — then the DataSetMessage window. Messages without a sequence number bypass the
    // windows ("each received DataSetMessage is considered new", §6.2.9.6). Drops are not
    // delivered, do not reset the receive timeout, do not complete startup, and do not recover
    // from Error (§6.2.9.6: a data DataSetMessage is "new" only if the sequence number
    // increments).
    if (networkMessageClassification != null
        && networkMessageClassification != SequenceNumberWindow.Classification.NEW) {
      sequenceDrop(reader, networkMessageClassification);
      return;
    }

    UInteger dataSetMessageSequence = message.sequenceNumber();
    if (dataSetMessageSequence != null) {
      SequenceNumberWindow.Classification classification =
          tracker.classifyDataSetMessage(
              networkMessage.publisherId(),
              message.dataSetWriterId(),
              dataSetMessageSequence,
              nowNanos);
      if (classification != SequenceNumberWindow.Classification.NEW) {
        sequenceDrop(reader, classification);
        return;
      }

      // the DataSetMessage will be delivered: its window advances only on accept
      tracker.acceptDataSetMessage(
          networkMessage.publisherId(),
          message.dataSetWriterId(),
          dataSetMessageSequence,
          nowNanos);
    }

    service.getDiagnostics().dataSetMessageReceived(group.path());
    service.getDiagnostics().dataSetMessageReceived(reader.path());

    reader.onMessageAccepted();

    // Part 14 §6.2.1 Table 2 (SHALL): a DataSetReader changes to Operational only after the
    // first key frame or event DataSetMessage. Pre-baseline delta frames are DELIBERATELY still
    // delivered to listeners and still reset the receive timeout (their sequence numbers
    // increment, so they are "new" per §6.2.9.6; §7.2.4.3 leaves the delivery policy to the
    // application): listeners receive honest partial state while the reader's PreOperational
    // state signals "no full baseline seen yet", and the publisher-side keyFrameCount cadence
    // bounds the wait for a key frame.
    if (reader.state() == PubSubState.PreOperational
        && (message.kind() == DataSetMessageKind.KEY_FRAME
            || message.kind() == DataSetMessageKind.EVENT)) {
      service.getStateMachine().startupCompleted(reader);
    }

    List<DataSetMetaDataConfig.Field> metaFields = metaData != null ? metaData.fields() : List.of();

    var fields = new ArrayList<DataSetFieldValue>(message.fields().size());
    for (DecodedField field : message.fields()) {
      int index = field.index();
      String wireName = field.fieldName();

      String name;
      UUID fieldId;
      if (wireName != null) {
        // name-keyed mappings (JSON): prefer matching the wire name against the effective
        // metadata; the metadata position becomes the field index
        int metaIndex = indexOfMetaField(metaFields, wireName);
        if (metaIndex >= 0) {
          DataSetMetaDataConfig.Field metaField = metaFields.get(metaIndex);
          name = metaField.name();
          fieldId = metaField.dataSetFieldId();
          index = metaIndex;
        } else {
          name = wireName;
          fieldId = NULL_FIELD_ID;
        }
      } else if (index >= 0 && index < metaFields.size()) {
        DataSetMetaDataConfig.Field metaField = metaFields.get(index);
        name = metaField.name();
        fieldId = metaField.dataSetFieldId();
      } else {
        name = "Field_" + index;
        fieldId = NULL_FIELD_ID;
      }

      fields.add(new DataSetFieldValue(fieldId, name, index, field.value()));
    }

    String dataSetName = null;
    if (metaData != null && !metaData.getName().isEmpty()) {
      dataSetName = metaData.getName();
    }

    var event =
        new DataSetReceivedEvent(
            reader.handle(),
            eventPublisherId(connection, reader, networkMessage),
            eventWriterGroupId(reader, networkMessage),
            eventDataSetWriterId(reader, message),
            networkMessage.sequenceNumber(),
            dataSetMessageSequence,
            dataSetName,
            metaData,
            fields);

    service.getEventDispatcher().notifyDataSet(reader.readerRef(), event);
  }

  /**
   * Classify the NetworkMessage's sequence number against its (PublisherId, WriterGroupId) stream
   * window, advancing the window immediately on a NEW verdict. Called exactly once per (reader,
   * NetworkMessage) — from the dispatch loop, after {@code matchesNetworkMessage} and BEFORE the
   * dataSetWriterId filter — and the verdict is shared by every matched DataSetMessage of the
   * NetworkMessage, so the verdict that advanced the window does not make sibling DataSetMessages
   * classify as duplicates.
   *
   * <p>The observation is independent of DataSetMessage matching and delivery: the publisher
   * consumes one NetworkMessage sequence number for EVERY NetworkMessage (§7.2.3 "incremented by
   * exactly one for each message"), including NetworkMessages carrying only keep-alives, only
   * DataSetMessages subsequently dropped at the valid/metadata gates or the DataSetMessage window,
   * or only other writers' DataSetMessages. Observing any later — say, on delivery — would freeze
   * the window while the publisher's counter keeps advancing (e.g. for a reader filtered to one
   * quiet writer while another writer of the same group publishes): after 2^(N-2) unobserved
   * NetworkMessages, resumed data would be wrongly dropped — invalid, then stale — for up to 2^N -
   * 2^(N-2) consecutive messages.
   *
   * @return the verdict, or {@code null} when the NetworkMessage carries no sequence number and the
   *     NetworkMessage window is bypassed.
   */
  private static SequenceNumberWindow.@Nullable Classification observeNetworkMessage(
      ReaderSequenceTracker tracker, DecodedNetworkMessage networkMessage, long nowNanos) {

    UShort sequenceNumber = networkMessage.sequenceNumber();
    if (sequenceNumber == null) {
      return null;
    }

    SequenceNumberWindow.Classification classification =
        tracker.classifyNetworkMessage(
            networkMessage.publisherId(), networkMessage.writerGroupId(), sequenceNumber, nowNanos);

    if (classification == SequenceNumberWindow.Classification.NEW) {
      tracker.acceptNetworkMessage(
          networkMessage.publisherId(), networkMessage.writerGroupId(), sequenceNumber, nowNanos);
    }

    return classification;
  }

  /**
   * Count one DataSetMessage dropped by the §7.2.3 window. Sequence drops are normal operation
   * ("shall be ignored"), counted apart from {@code dataSetMessagesReceived} and from the
   * error-class counters: no {@code lastError}, no diagnostics event.
   */
  private void sequenceDrop(
      DataSetReaderRuntime reader, SequenceNumberWindow.Classification classification) {

    if (classification == SequenceNumberWindow.Classification.STALE) {
      service.getDiagnostics().staleSequenceMessage(reader.path());
    } else {
      service.getDiagnostics().invalidSequenceMessage(reader.path());
    }
  }

  private void handleMetaData(
      ConnectionRuntime connection, DataSetReaderRuntime reader, DecodedMetaData metaData) {

    DataSetMetaDataConfig converted;
    try {
      converted = MetadataCache.fromDataType(metaData.metaData());
    } catch (RuntimeException e) {
      service
          .getDiagnostics()
          .decodeError(
              reader.path(),
              new StatusCode(StatusCodes.Bad_DecodingError),
              "invalid DataSetMetaData announcement: " + e.getMessage(),
              e);
      return;
    }

    if (reader.config().getMetadataPolicy() != MetadataPolicy.REQUIRE_CONFIGURED) {
      service.getMetadataCache().putDiscovered(reader.handle(), converted);

      // double-check: dispose() (which removes the entry) may have run concurrently on the
      // engine lock between the put landing and here; handles are never reused, so an entry
      // that lands after dispose would otherwise leak forever. dispose() sets the flag before
      // removing, so every interleaving leaves the entry removed.
      if (reader.isDisposed()) {
        service.getMetadataCache().remove(reader.handle());
      }

      // the reader now has effective metadata: any REQUEST_IF_MISSING probe loop can stop
      DiscoveryRuntime discovery = connection.discoveryRuntime();
      if (discovery != null) {
        discovery.onMetaDataApplied(reader);
      }
    }

    var event =
        new MetaDataReceivedEvent(
            reader.handle(),
            metaData.metaData().getName(),
            metaData.metaData(),
            metaData.metaData().getConfigurationVersion());

    service.getEventDispatcher().notifyMetaData(event);
  }

  /**
   * The metadata used to decode for this reader: discovered metadata when the policy accepts it and
   * an announcement has been received, otherwise the configured metadata.
   */
  private @Nullable DataSetMetaDataConfig effectiveMetaData(DataSetReaderRuntime reader) {
    if (reader.config().getMetadataPolicy() != MetadataPolicy.REQUIRE_CONFIGURED) {
      DataSetMetaDataConfig discovered = service.getMetadataCache().getDiscovered(reader.handle());
      if (discovered != null) {
        return discovered;
      }
    }
    return reader.configuredMetaData();
  }

  private static boolean isNotReceiving(PubSubState state) {
    return state != PubSubState.PreOperational
        && state != PubSubState.Operational
        && state != PubSubState.Error;
  }

  private static boolean matchesNetworkMessage(
      DataSetReaderConfig config, DecodedNetworkMessage decoded) {

    if (!publisherIdMatches(config, decoded.publisherId())) {
      return false;
    }

    // Identifier filters are applied only when the identifier is present in the message: a
    // publisher that omits it from the network message header (e.g. GroupFlags without
    // WriterGroupId) cannot be checked against the configured value (Part 14 6.2.9 matching;
    // open62541 behaves the same way).
    UShort writerGroupId = config.getWriterGroupId();
    if (writerGroupId != null && writerGroupId.intValue() != 0) {
      if (decoded.writerGroupId() != null && !writerGroupId.equals(decoded.writerGroupId())) {
        return false;
      }
    }

    if (config.getSettings() instanceof UadpDataSetReaderSettings settings) {
      if (settings.getGroupVersion().longValue() != 0L
          && decoded.groupVersion() != null
          && !settings.getGroupVersion().equals(decoded.groupVersion())) {
        return false;
      }

      return settings.getNetworkMessageNumber().intValue() == 0
          || decoded.networkMessageNumber() == null
          || settings.getNetworkMessageNumber().equals(decoded.networkMessageNumber());
    }

    return true;
  }

  /** Find the index of the metadata field named {@code name}, or -1. */
  private static int indexOfMetaField(List<DataSetMetaDataConfig.Field> metaFields, String name) {
    for (int i = 0; i < metaFields.size(); i++) {
      if (metaFields.get(i).name().equals(name)) {
        return i;
      }
    }
    return -1;
  }

  /** Shared with {@link ReaderSecurityResolver}, which matches on the same wire identifiers. */
  static boolean publisherIdMatches(DataSetReaderConfig config, @Nullable PublisherId publisherId) {

    PublisherId filter = config.getPublisherId();

    // a message without a PublisherId can only be processed by readers without a PublisherId
    // filter; ids of the same type require an exact match
    if (filter == null) {
      return true;
    }
    if (filter.equals(publisherId)) {
      return true;
    }
    if (publisherId == null) {
      return false;
    }

    // ids of differing types compare by canonical String form: the JSON mapping carries every
    // PublisherId as a String (Part 14 §7.2.5.3 Table 184), so a reader filtering on a numeric
    // id must still match the decoded string form (and vice versa)
    return filter.getClass() != publisherId.getClass()
        && filter.toCanonicalString().equals(publisherId.toCanonicalString());
  }

  private static boolean dataSetWriterIdMatches(
      DataSetReaderConfig config, @Nullable UShort dataSetWriterId) {

    UShort filter = config.getDataSetWriterId();
    if (filter == null || filter.intValue() == 0) {
      return true;
    }
    // absent on the wire (payload header disabled, fixed-layout publisher): the filter cannot be
    // applied and the reader identifies the message by its configuration (Part 14 6.2.9)
    return dataSetWriterId == null || filter.equals(dataSetWriterId);
  }

  private static PublisherId eventPublisherId(
      ConnectionRuntime connection, DataSetReaderRuntime reader, DecodedNetworkMessage decoded) {

    if (decoded.publisherId() != null) {
      return decoded.publisherId();
    }
    if (reader.config().getPublisherId() != null) {
      return reader.config().getPublisherId();
    }
    PublisherId connectionPublisherId = connection.config().publisherId();
    if (connectionPublisherId != null) {
      return connectionPublisherId;
    }
    return PublisherId.string("");
  }

  private static UShort eventWriterGroupId(
      DataSetReaderRuntime reader, DecodedNetworkMessage decoded) {

    if (decoded.writerGroupId() != null) {
      return decoded.writerGroupId();
    }
    UShort configured = reader.config().getWriterGroupId();
    return configured != null ? configured : ushort(0);
  }

  private static UShort eventDataSetWriterId(
      DataSetReaderRuntime reader, DecodedDataSetMessage message) {

    if (message.dataSetWriterId() != null) {
      return message.dataSetWriterId();
    }
    UShort configured = reader.config().getDataSetWriterId();
    return configured != null ? configured : ushort(0);
  }
}
