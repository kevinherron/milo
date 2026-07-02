/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.uadp;

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublisherId;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityContextResolver;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeyMaterial;
import org.eclipse.milo.opcua.sdk.pubsub.security.UadpMessageSecurity;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingContext;
import org.eclipse.milo.opcua.stack.core.encoding.binary.OpcUaBinaryDecoder;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.ConfigurationVersionDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.DataSetMetaDataType;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Decodes one UADP NetworkMessage (OPC UA Part 14 §7.2.4) into a {@link DecodedNetworkMessage}.
 *
 * <p>Decoding is tolerant by design: malformed or unsupported input never raises an exception to
 * the caller. Whatever was decoded before the problem is returned, and skipped DataSetMessages are
 * represented as entries with {@code valid == false} and no fields. A NetworkMessage whose header
 * cannot be decoded at all yields an empty {@link DecodedNetworkMessage}.
 *
 * <p>Failures that end decoding early are surfaced via {@link DecodedNetworkMessage#failure()}
 * rather than thrown, classified by {@link DecodedNetworkMessage.Failure.Reason}: truncated or
 * malformed input that raises an exception mid-decode, any explicit length field exceeding the
 * remaining bytes (a DataSetMessage Sizes entry, the PromotedFields Size, the SecurityHeader
 * NonceLength, a chunk's ChunkData length, a discovery probe's DataSetWriterIds count — the
 * truncation signatures), security drops (see below), and chunked NetworkMessages that could not be
 * consumed. Input that is merely tolerated and skipped — a non-UADP version nibble, reserved flag
 * or type values, unsupported discovery content — reports no failure.
 *
 * <p><b>Message security</b> (§7.2.4.4.3): a SecurityHeader with the signed bit set is processed
 * against key material obtained from the {@link DecodeContext#securityContextResolver()}. The
 * trailing signature is verified over the whole NetworkMessage <b>before</b> any payload parsing;
 * an encrypted payload is then decrypted into a <b>copy</b> — the arrival buffer, which the
 * transport shares across mapping providers, is never mutated. A secured message that fails a
 * security check is dropped whole (no DataSetMessages), with the drop observable as a failure:
 * reserved SecurityFlags bits or an indicated SecurityFooter ({@code SECURITY_UNSUPPORTED}),
 * encrypted-without-signed flags ({@code SECURITY_MODE_REJECTED}), missing resolver or empty
 * resolution ({@code UNRESOLVED_KEYS}), and signature verification failure ({@code
 * SIGNATURE_INVALID}). Both sign-only SecurityHeader forms are accepted: the Annex A form with a
 * real token id and 8-byte MessageNonce, and the literal Table 154 form with a zero token and empty
 * nonce (NonceLength is self-describing). The received token id, mode, and force-key-reset bit are
 * surfaced via {@link DecodedNetworkMessage#security()} even when the message is dropped.
 *
 * <p><b>Chunked NetworkMessages</b> (§7.2.4.4.4) are reassembled when the {@link
 * DecodeContext#chunkReassembler()} is present: each chunk NetworkMessage is verified and decrypted
 * individually first, then its Table 159 fields are offered to the reassembler, and a completed
 * payload is decoded through the normal DataSetMessage path. Without a reassembler — and for
 * chunked discovery messages, whose reassembly is not implemented — chunked messages are dropped
 * with a {@code CHUNK} failure ({@code Bad_NotSupported}).
 *
 * <p>Scope and limitations:
 *
 * <ul>
 *   <li>Data Key Frame, Data Delta Frame, Event, and Keep Alive DataSetMessages with Variant or
 *       DataValue field encoding are decoded.
 *   <li>RawData field encoding requires metadata-driven offsets and is not supported; affected
 *       DataSetMessages are skipped ({@code valid == false}, empty fields).
 *   <li>Discovery announcements of type DataSetMetaData and DataSetMetaData probes (ProbeType 1,
 *       InformationType 2) are decoded; {@link #decodeMessage(DecodeContext, ByteBuf)} surfaces
 *       them as {@link UadpMetaDataAnnouncement} (any status, including Bad denials) and {@link
 *       UadpDiscoveryProbe}. The legacy {@link #decode(DecodeContext, ByteBuf)} surface folds
 *       non-Bad announcements into {@link DecodedMetaData} and drops probes and Bad-status
 *       announcements. FindApplications probes, other probe InformationTypes, and other
 *       announcement types are tolerated and skipped.
 *   <li>ActionHeaders are detected and their payloads skipped. A PromotedFields block is skipped
 *       via its Size field and the payload after it is decoded normally.
 *   <li>If the PayloadHeader is absent the payload is assumed to contain a single DataSetMessage.
 * </ul>
 *
 * <p>Stateless: a new instance is used for each NetworkMessage. The only cross-message state is the
 * caller-owned {@link ChunkReassembler}.
 */
final class UadpNetworkMessageDecoder {

  private static final Logger LOGGER = LoggerFactory.getLogger(UadpNetworkMessageDecoder.class);

  /** UADP NetworkMessage type values, from ExtendedFlags2 bits 2-4. */
  private static final int TYPE_DATA = 0;

  private static final int TYPE_DISCOVERY_PROBE = 1;
  private static final int TYPE_DISCOVERY_ANNOUNCEMENT = 2;

  /** Discovery announcement type values (Part 14 §7.2.4.6.3, Table 168). */
  private static final int ANNOUNCEMENT_DATA_SET_META_DATA = 2;

  /** Field Encoding values, from DataSetFlags1 bits 1-2. */
  private static final int FIELD_ENCODING_RAW_DATA = 1;

  private static final int FIELD_ENCODING_DATA_VALUE = 2;
  private static final int FIELD_ENCODING_RESERVED = 3;

  /** The counter block requires the first 8 bytes of the MessageNonce (Table 157). */
  private static final int AES_CTR_NONCE_LENGTH = 8;

  private final List<DecodedDataSetMessage> messages = new ArrayList<>();
  private final List<DecodedMetaData> metaData = new ArrayList<>();

  private @Nullable UadpDiscoveryProbe probe;
  private @Nullable UadpMetaDataAnnouncement announcement;

  private DecodedNetworkMessage.@Nullable Failure failure;
  private DecodedNetworkMessage.@Nullable Security security;

  private @Nullable PublisherId publisherId;
  private @Nullable UShort writerGroupId;
  private @Nullable UInteger groupVersion;
  private @Nullable UShort networkMessageNumber;
  private @Nullable UShort sequenceNumber;
  private @Nullable DateTime timestamp;

  /** The single DataSetWriterId of a chunk NetworkMessage's PayloadHeader (Table 158). */
  private @Nullable UShort chunkDataSetWriterId;

  /** Set once the payload region has been decrypted; classifies later parse failures. */
  private boolean payloadDecrypted;

  private final DecodeContext context;
  private final EncodingContext encodingContext;

  /** The reader index of the first NetworkMessage byte; the start of the signed region. */
  private final int messageStart;

  /**
   * The buffer being parsed. Starts as the arrival buffer; after security processing it is replaced
   * with the bounded payload region — a slice for sign-only messages, a decrypted copy for
   * encrypted messages — so payload parsing can never run into the trailing signature.
   */
  private ByteBuf buffer;

  private OpcUaBinaryDecoder decoder;

  private UadpNetworkMessageDecoder(DecodeContext context, ByteBuf buffer) {
    this.context = context;
    this.encodingContext = context.encodingContext();
    this.buffer = buffer;
    this.messageStart = buffer.readerIndex();

    decoder = new OpcUaBinaryDecoder(encodingContext).setBuffer(buffer);
  }

  /**
   * Decode one NetworkMessage from {@code buffer} into the legacy data-plane shape.
   *
   * <p>Discovery content is folded into the data-plane result the way it always was: a
   * DataSetMetaData announcement with a non-Bad status becomes a {@link DecodedMetaData} entry,
   * while probes and Bad-status announcements yield a header-only result. Use {@link
   * #decodeMessage(DecodeContext, ByteBuf)} to surface them.
   *
   * @param context the decode context.
   * @param buffer the buffer containing the received NetworkMessage; the caller retains ownership.
   * @return the decoded NetworkMessage; possibly partial or empty if the input was malformed or
   *     unsupported.
   */
  static DecodedNetworkMessage decode(DecodeContext context, ByteBuf buffer) {
    var decoder = new UadpNetworkMessageDecoder(context, buffer);

    try {
      decoder.decodeNetworkMessage();
    } catch (Exception e) {
      LOGGER.debug("failed to fully decode NetworkMessage: {}", e.getMessage(), e);
      decoder.recordFailure(e);
    }

    return decoder.legacyResult();
  }

  /**
   * Decode one NetworkMessage from {@code buffer}, surfacing discovery messages.
   *
   * @param context the decode context.
   * @param buffer the buffer containing the received NetworkMessage; the caller retains ownership.
   * @return a {@link UadpDiscoveryProbe} for a DataSetMetaData probe, a {@link
   *     UadpMetaDataAnnouncement} for a DataSetMetaData announcement of any status, or a {@link
   *     DecodedNetworkMessage} otherwise — possibly partial or empty if the input was malformed,
   *     unsupported, or discovery content that is tolerated but not surfaced.
   */
  static UadpDecodedMessage decodeMessage(DecodeContext context, ByteBuf buffer) {
    var decoder = new UadpNetworkMessageDecoder(context, buffer);

    try {
      decoder.decodeNetworkMessage();
    } catch (Exception e) {
      LOGGER.debug("failed to fully decode NetworkMessage: {}", e.getMessage(), e);
      decoder.recordFailure(e);
    }

    return decoder.result();
  }

  /** Record the exception that ended decoding, unless a failure was already recorded. */
  private void recordFailure(Exception e) {
    if (failure == null) {
      failure =
          new DecodedNetworkMessage.Failure(
              new StatusCode(StatusCodes.Bad_DecodingError),
              "failed to fully decode NetworkMessage: " + e.getMessage(),
              e,
              payloadFailureReason());
    }
  }

  /** Record a failure detected without an exception, unless a failure was already recorded. */
  private void recordFailure(
      DecodedNetworkMessage.Failure.Reason reason, long statusCode, String message) {

    if (failure == null) {
      failure =
          new DecodedNetworkMessage.Failure(new StatusCode(statusCode), message, null, reason);
    }
  }

  /**
   * The reason classifying a payload parse failure: structural failures inside a decrypted payload
   * are decrypt failures — AES-CTR cannot itself detect corruption (Part 14 §7.2.4.4.3.2).
   */
  private DecodedNetworkMessage.Failure.Reason payloadFailureReason() {
    return payloadDecrypted
        ? DecodedNetworkMessage.Failure.Reason.DECRYPT_FAILED
        : DecodedNetworkMessage.Failure.Reason.DECODING_ERROR;
  }

  private UadpDecodedMessage result() {
    if (probe != null) {
      return probe;
    }
    if (announcement != null) {
      return announcement;
    }
    return dataPlaneResult();
  }

  private DecodedNetworkMessage legacyResult() {
    if (announcement != null && !announcement.statusCode().isBad()) {
      metaData.add(new DecodedMetaData(announcement.dataSetWriterId(), announcement.metaData()));
    } else if (announcement != null) {
      // The Publisher cannot provide metadata for this DataSetWriter; the legacy surface has
      // no slot for denials.
      LOGGER.debug(
          "DataSetMetaData announcement with Bad status: {} (dataSetWriterId={})",
          announcement.statusCode(),
          announcement.dataSetWriterId());
    }

    return dataPlaneResult();
  }

  private DecodedNetworkMessage dataPlaneResult() {
    return DecodedNetworkMessage.of(
        publisherId,
        writerGroupId,
        groupVersion,
        networkMessageNumber,
        sequenceNumber,
        timestamp,
        messages,
        metaData,
        failure,
        security);
  }

  private void decodeNetworkMessage() throws UaException {
    int byte0 = buffer.readUnsignedByte();

    int version = byte0 & 0x0F;
    if (version != 1) {
      LOGGER.debug("unsupported UADP version: {}", version);
      return;
    }

    boolean publisherIdEnabled = (byte0 & 0x10) != 0;
    boolean groupHeaderEnabled = (byte0 & 0x20) != 0;
    boolean payloadHeaderEnabled = (byte0 & 0x40) != 0;

    int extendedFlags1 = (byte0 & 0x80) != 0 ? buffer.readUnsignedByte() : 0;
    int extendedFlags2 = (extendedFlags1 & 0x80) != 0 ? buffer.readUnsignedByte() : 0;

    int publisherIdType = extendedFlags1 & 0x07;
    boolean dataSetClassIdEnabled = (extendedFlags1 & 0x08) != 0;
    boolean securityEnabled = (extendedFlags1 & 0x10) != 0;
    boolean timestampEnabled = (extendedFlags1 & 0x20) != 0;
    boolean picoSecondsEnabled = (extendedFlags1 & 0x40) != 0;

    boolean chunk = (extendedFlags2 & 0x01) != 0;
    boolean promotedFieldsEnabled = (extendedFlags2 & 0x02) != 0;
    int messageType = (extendedFlags2 >> 2) & 0x07;
    boolean actionHeaderEnabled = (extendedFlags2 & 0x20) != 0;

    if ((extendedFlags2 & 0xC0) != 0) {
      LOGGER.debug("reserved ExtendedFlags2 bits set: 0x{}", Integer.toHexString(extendedFlags2));
      return;
    }
    if (messageType > TYPE_DISCOVERY_ANNOUNCEMENT) {
      LOGGER.debug("reserved NetworkMessage type: {}", messageType);
      return;
    }

    if (publisherIdEnabled) {
      publisherId = decodePublisherId(publisherIdType);
      if (publisherId == null) {
        return;
      }
    }

    if (dataSetClassIdEnabled) {
      // Consume; the DataSetClassId is not surfaced by DecodedNetworkMessage.
      decoder.decodeGuid();
    }

    if (groupHeaderEnabled) {
      int groupFlags = buffer.readUnsignedByte();

      if ((groupFlags & 0xF0) != 0) {
        LOGGER.debug("reserved GroupFlags bits set: 0x{}", Integer.toHexString(groupFlags));
        return;
      }

      if ((groupFlags & 0x01) != 0) {
        writerGroupId = decoder.decodeUInt16();
      }
      if ((groupFlags & 0x02) != 0) {
        groupVersion = decoder.decodeUInt32();
      }
      if ((groupFlags & 0x04) != 0) {
        networkMessageNumber = decoder.decodeUInt16();
      }
      if ((groupFlags & 0x08) != 0) {
        sequenceNumber = decoder.decodeUInt16();
      }
    }

    List<UShort> dataSetWriterIds = null;

    if (payloadHeaderEnabled) {
      if (chunk) {
        // Chunked NetworkMessage payload header: a single DataSetWriterId, no Count (Table 158).
        chunkDataSetWriterId = decoder.decodeUInt16();
      } else if (messageType == TYPE_DATA) {
        int count = buffer.readUnsignedByte();

        dataSetWriterIds = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
          dataSetWriterIds.add(decoder.decodeUInt16());
        }
      } else {
        // Discovery messages shall not have a PayloadHeader; the layout that follows is
        // undefined.
        LOGGER.debug("discovery NetworkMessage with PayloadHeader enabled");
        return;
      }
    }

    if (timestampEnabled) {
      timestamp = decoder.decodeDateTime();
    }
    if (picoSecondsEnabled) {
      // Consume; PicoSeconds are not surfaced by DecodedNetworkMessage.
      decoder.decodeUInt16();
    }

    if (promotedFieldsEnabled) {
      // Skip the PromotedFields block via its Size field; the payload that follows is still
      // decodable. Promoted fields are never encrypted (§5.3.4) — plaintext, like the header.
      int size = decoder.decodeUInt16().intValue();
      if (size > buffer.readableBytes()) {
        // a truncation signature: the Size field promised more bytes than arrived
        LOGGER.debug("PromotedFields size exceeds remaining bytes: {}", size);
        recordFailure(
            DecodedNetworkMessage.Failure.Reason.DECODING_ERROR,
            StatusCodes.Bad_DecodingError,
            "PromotedFields size exceeds remaining bytes: " + size);
        return;
      }
      buffer.skipBytes(size);
    }

    if (securityEnabled) {
      List<UShort> securityWriterIds;
      if (chunkDataSetWriterId != null) {
        securityWriterIds = List.of(chunkDataSetWriterId);
      } else if (dataSetWriterIds != null) {
        securityWriterIds = dataSetWriterIds;
      } else {
        securityWriterIds = List.of();
      }

      if (!decodeSecurityHeader(securityWriterIds)) {
        return;
      }
    }

    if (actionHeaderEnabled) {
      LOGGER.debug("ActionHeader is not supported; skipping payload");
      return;
    }

    if (chunk) {
      decodeChunkPayload(messageType);
      return;
    }

    if (messageType == TYPE_DISCOVERY_ANNOUNCEMENT) {
      decodeDiscoveryAnnouncement();
    } else if (messageType == TYPE_DISCOVERY_PROBE) {
      decodeDiscoveryProbe();
    } else {
      decodeDataPayload(payloadHeaderEnabled, dataSetWriterIds);
    }
  }

  private @Nullable PublisherId decodePublisherId(int publisherIdType) {
    switch (publisherIdType) {
      case 0x00:
        return PublisherId.ubyte(decoder.decodeByte());
      case 0x01:
        return PublisherId.uint16(decoder.decodeUInt16());
      case 0x02:
        return PublisherId.uint32(decoder.decodeUInt32());
      case 0x03:
        return PublisherId.uint64(decoder.decodeUInt64());
      case 0x04:
        String value = decoder.decodeString();
        if (value == null) {
          LOGGER.debug("null String PublisherId");
          return null;
        }
        return PublisherId.string(value);
      default:
        LOGGER.debug("reserved PublisherId type: {}", publisherIdType);
        return null;
    }
  }

  /**
   * Decode the SecurityHeader and, for a secured message, verify the trailing signature and decrypt
   * the payload region (Part 14 §7.2.4.4.2 Table 154, §7.2.4.4.3).
   *
   * <p>On success for a secured message, {@link #buffer} and {@link #decoder} are replaced with the
   * bounded payload region — a slice for sign-only messages, a decrypted copy for encrypted
   * messages — so subsequent payload parsing never reads the trailing signature and never mutates
   * the shared arrival buffer.
   *
   * @param dataSetWriterIds the plaintext DataSetWriterIds passed to the resolver, in wire order.
   * @return {@code true} if the payload that follows can be processed; {@code false} if the message
   *     was dropped, with the drop recorded as a failure where required.
   */
  private boolean decodeSecurityHeader(List<UShort> dataSetWriterIds) throws UaException {
    int securityFlags = buffer.readUnsignedByte();

    if ((securityFlags & 0xF0) != 0) {
      // "Reserved bits shall be set to false by the the sender and the receiver shall skip
      // messages where the reserved bits are not false." (Table 154)
      LOGGER.debug(
          "reserved SecurityFlags bits set: 0x{}; skipping message",
          Integer.toHexString(securityFlags));
      recordFailure(
          DecodedNetworkMessage.Failure.Reason.SECURITY_UNSUPPORTED,
          StatusCodes.Bad_NotSupported,
          "reserved SecurityFlags bits set: 0x" + Integer.toHexString(securityFlags));
      return false;
    }

    boolean signed = (securityFlags & 0x01) != 0;
    boolean encrypted = (securityFlags & 0x02) != 0;
    boolean footerEnabled = (securityFlags & 0x04) != 0;
    boolean forceKeyReset = (securityFlags & 0x08) != 0;

    if (footerEnabled) {
      // The two defined PubSub policies use no SecurityFooter (Annex A pins the footer bit
      // false); a message indicating one is unsupported and skipped.
      LOGGER.debug("SecurityFooter is not supported; skipping message");
      recordFailure(
          DecodedNetworkMessage.Failure.Reason.SECURITY_UNSUPPORTED,
          StatusCodes.Bad_NotSupported,
          "SecurityFooter is not supported");
      return false;
    }

    if (encrypted && !signed) {
      // "Therefore bit 0 shall be true if bit 1 is true." (Table 154)
      LOGGER.debug("SecurityFlags indicate encrypted without signed; skipping message");
      recordFailure(
          DecodedNetworkMessage.Failure.Reason.SECURITY_MODE_REJECTED,
          StatusCodes.Bad_SecurityChecksFailed,
          "SecurityFlags indicate an encrypted but unsigned NetworkMessage");
      return false;
    }

    UInteger securityTokenId = decoder.decodeUInt32();

    int nonceLength = buffer.readUnsignedByte();
    if (nonceLength > buffer.readableBytes()) {
      // a truncation signature: the NonceLength promised more bytes than arrived
      LOGGER.debug("NonceLength exceeds remaining bytes: {}", nonceLength);
      recordFailure(
          DecodedNetworkMessage.Failure.Reason.DECODING_ERROR,
          StatusCodes.Bad_DecodingError,
          "SecurityHeader NonceLength exceeds remaining bytes: " + nonceLength);
      return false;
    }
    byte[] messageNonce = new byte[nonceLength];
    buffer.readBytes(messageNonce);

    // SecurityFooterSize is only present when the SecurityFooter flag is set, which was
    // rejected above.

    if (!signed && !forceKeyReset) {
      // Mode None: nothing to verify or decrypt; the payload runs to the end of the buffer.
      return true;
    }

    MessageSecurityMode mode;
    if (encrypted) {
      mode = MessageSecurityMode.SignAndEncrypt;
    } else if (signed) {
      mode = MessageSecurityMode.Sign;
    } else {
      mode = MessageSecurityMode.None;
    }

    // Surfaced before any security check so the subscriber key manager observes token ids and
    // force-key-reset signals on dropped messages too; unverified until the signature verifies.
    security = new DecodedNetworkMessage.Security(mode, securityTokenId, forceKeyReset, false);

    if (!signed) {
      // Only the force-key-reset bit was set; the message itself is unsecured.
      return true;
    }

    SecurityContextResolver resolver = context.securityContextResolver();
    if (resolver == null) {
      LOGGER.debug("secured NetworkMessage but no SecurityContextResolver; dropping");
      recordFailure(
          DecodedNetworkMessage.Failure.Reason.UNRESOLVED_KEYS,
          StatusCodes.Bad_SecurityChecksFailed,
          "secured NetworkMessage but no SecurityContextResolver is available");
      return false;
    }

    Optional<SecurityKeyMaterial> resolved =
        resolver.resolve(publisherId, writerGroupId, dataSetWriterIds, mode, securityTokenId);

    if (resolved.isEmpty()) {
      LOGGER.debug(
          "no key material resolved for secured NetworkMessage (tokenId={}); dropping",
          securityTokenId);
      recordFailure(
          DecodedNetworkMessage.Failure.Reason.UNRESOLVED_KEYS,
          StatusCodes.Bad_SecurityChecksFailed,
          "no key material resolved for secured NetworkMessage (tokenId=" + securityTokenId + ")");
      return false;
    }
    SecurityKeyMaterial keyMaterial = resolved.get();

    // Boundary math (§7.2.4.4.1): the signature is the trailing signatureLength bytes of the
    // NetworkMessage; the signed region is everything before it, from the first header byte.
    int signatureLength = keyMaterial.getPolicy().getSignatureLength();
    int signedEnd = buffer.writerIndex() - signatureLength;

    if (signedEnd < buffer.readerIndex()) {
      LOGGER.debug("secured NetworkMessage too short to carry its signature; dropping");
      recordFailure(
          DecodedNetworkMessage.Failure.Reason.DECODING_ERROR,
          StatusCodes.Bad_DecodingError,
          "secured NetworkMessage is too short to carry its %d-byte signature"
              .formatted(signatureLength));
      return false;
    }

    byte[] signature = new byte[signatureLength];
    buffer.getBytes(signedEnd, signature);

    // "it shall verify the signature before processing the payload. If verification fails, it
    // drops the NetworkMessage." (§7.2.4.4.3.2)
    boolean verified =
        UadpMessageSecurity.verify(
            keyMaterial, buffer, messageStart, signedEnd - messageStart, signature);

    if (!verified) {
      LOGGER.debug("NetworkMessage signature verification failed; dropping");
      recordFailure(
          DecodedNetworkMessage.Failure.Reason.SIGNATURE_INVALID,
          StatusCodes.Bad_SecurityChecksFailed,
          "NetworkMessage signature verification failed");
      return false;
    }

    // The message is authenticated from here on: any later failure (payload parsing, decryption
    // structure, chunk consumption) is a failure of verified content, so its header values may
    // safely affect reader state.
    security = new DecodedNetworkMessage.Security(mode, securityTokenId, forceKeyReset, true);

    int payloadStart = buffer.readerIndex();
    int payloadLength = signedEnd - payloadStart;

    if (encrypted) {
      if (nonceLength < AES_CTR_NONCE_LENGTH) {
        // The counter block needs the first 8 bytes of the MessageNonce (Table 157); an
        // encrypted message with a shorter nonce cannot be decrypted.
        LOGGER.debug("encrypted NetworkMessage with a {}-byte MessageNonce; dropping", nonceLength);
        recordFailure(
            DecodedNetworkMessage.Failure.Reason.SECURITY_UNSUPPORTED,
            StatusCodes.Bad_NotSupported,
            "encrypted NetworkMessage requires an 8-byte MessageNonce, got " + nonceLength);
        return false;
      }
      // "The first 8 bytes of the Nonce in the SecurityHeader" (Table 157); longer nonces are
      // tolerated on decode, only their first 8 bytes feed the counter block.
      byte[] counterNonce =
          nonceLength == AES_CTR_NONCE_LENGTH
              ? messageNonce
              : Arrays.copyOf(messageNonce, AES_CTR_NONCE_LENGTH);

      // Decrypt a COPY of the payload region: the arrival buffer is shared across mapping
      // providers and must never be mutated.
      byte[] payloadCopy = new byte[payloadLength];
      buffer.getBytes(payloadStart, payloadCopy);

      ByteBuf plaintext = Unpooled.wrappedBuffer(payloadCopy);
      UadpMessageSecurity.applyCtr(keyMaterial, counterNonce, plaintext, 0, payloadLength);

      buffer = plaintext;
      payloadDecrypted = true;
    } else {
      // Sign-only: parse the payload from a bounded slice so the trailing signature bytes are
      // never misread as payload.
      buffer = buffer.slice(payloadStart, payloadLength);
    }

    decoder = new OpcUaBinaryDecoder(encodingContext).setBuffer(buffer);

    return true;
  }

  /**
   * Decode the payload of a chunk NetworkMessage (Part 14 §7.2.4.4.4, Table 159) — already verified
   * and decrypted — and offer it to the caller's {@link ChunkReassembler}; a completed reassembly
   * is decoded through the normal DataSetMessage path.
   */
  private void decodeChunkPayload(int messageType) {
    ChunkReassembler reassembler = context.chunkReassembler();

    if (reassembler == null) {
      LOGGER.debug("chunked NetworkMessage is not supported; skipping payload");
      recordFailure(
          DecodedNetworkMessage.Failure.Reason.CHUNK,
          StatusCodes.Bad_NotSupported,
          "chunked NetworkMessage is not supported: no ChunkReassembler is available");
      return;
    }

    if (messageType != TYPE_DATA) {
      // Chunked discovery announcements (Table 159 without a PayloadHeader) are not
      // reassembled in this version.
      LOGGER.debug("chunked discovery NetworkMessage is not supported; skipping payload");
      recordFailure(
          DecodedNetworkMessage.Failure.Reason.CHUNK,
          StatusCodes.Bad_NotSupported,
          "chunked discovery NetworkMessage is not supported");
      return;
    }

    if (chunkDataSetWriterId == null) {
      // Table 158: a chunked data NetworkMessage carries its single DataSetWriterId in the
      // PayloadHeader; without one the chunk cannot be keyed.
      LOGGER.debug("chunked NetworkMessage without a PayloadHeader; skipping payload");
      recordFailure(
          DecodedNetworkMessage.Failure.Reason.CHUNK,
          StatusCodes.Bad_DecodingError,
          "chunked NetworkMessage without a PayloadHeader DataSetWriterId");
      return;
    }

    UShort messageSequenceNumber;
    long chunkOffset;
    long totalSize;
    byte[] chunkData;
    try {
      messageSequenceNumber = decoder.decodeUInt16();
      chunkOffset = decoder.decodeUInt32().longValue();
      totalSize = decoder.decodeUInt32().longValue();

      int chunkDataLength = decoder.decodeInt32();
      if (chunkDataLength < 0) {
        // a null ByteString; tolerated as an empty chunk
        chunkData = new byte[0];
      } else if (chunkDataLength > buffer.readableBytes()) {
        // a truncation signature: the ChunkData length promised more bytes than arrived
        LOGGER.debug("ChunkData length exceeds remaining bytes: {}", chunkDataLength);
        recordFailure(
            DecodedNetworkMessage.Failure.Reason.CHUNK,
            StatusCodes.Bad_DecodingError,
            "ChunkData length exceeds remaining bytes: " + chunkDataLength);
        return;
      } else {
        chunkData = new byte[chunkDataLength];
        buffer.readBytes(chunkData);
      }
    } catch (Exception e) {
      LOGGER.debug("failed to decode chunk fields: {}", e.getMessage(), e);
      recordFailure(
          DecodedNetworkMessage.Failure.Reason.CHUNK,
          StatusCodes.Bad_DecodingError,
          "failed to decode chunk NetworkMessage payload fields: " + e.getMessage());
      return;
    }

    // secured = the chunk NM passed signature verification: participates in the assembly key so
    // an UNSECURED chunk spoofing the plaintext (PublisherId, DataSetWriterId) of a secured
    // stream can never abandon or contribute to a secured in-progress reassembly (the mode
    // gate runs per-reader AFTER reassembly, too late to protect the reassembly state itself)
    DecodedNetworkMessage.Security security = this.security;
    boolean secured = security != null && security.verified();

    ChunkReassembler.Result result =
        reassembler.accept(
            publisherId,
            chunkDataSetWriterId,
            secured,
            messageSequenceNumber,
            chunkOffset,
            totalSize,
            chunkData);

    switch (result.status()) {
      case COMPLETE -> {
        byte[] payload = Objects.requireNonNull(result.payload());

        ByteBuf reassembled = Unpooled.wrappedBuffer(payload);
        OpcUaBinaryDecoder reassembledDecoder =
            new OpcUaBinaryDecoder(encodingContext).setBuffer(reassembled);

        try {
          messages.add(decodeDataSetMessage(reassembledDecoder, reassembled, chunkDataSetWriterId));
        } catch (Exception e) {
          LOGGER.debug("failed to decode reassembled DataSetMessage: {}", e.getMessage(), e);

          messages.add(invalidDataSetMessage(chunkDataSetWriterId));
        }
      }
      case PENDING -> {
        // Buffered; the DataSetMessage completes in a later chunk.
      }
      case STALE -> {
        LOGGER.debug(
            "dropped stale chunk (publisherId={}, dataSetWriterId={}, sequenceNumber={})",
            publisherId,
            chunkDataSetWriterId,
            messageSequenceNumber);
      }
      case REJECTED -> {
        StatusCode statusCode = Objects.requireNonNull(result.statusCode());
        String message = Objects.requireNonNull(result.message());

        LOGGER.debug("chunk rejected: {}", message);
        recordFailure(DecodedNetworkMessage.Failure.Reason.CHUNK, statusCode.value(), message);
      }
    }
  }

  private void decodeDiscoveryAnnouncement() {
    int announcementType = buffer.readUnsignedByte();

    // Per-PublisherId announcement SequenceNumber, independent of the data-plane counters.
    UShort announcementSequenceNumber = decoder.decodeUInt16();

    if (announcementType != ANNOUNCEMENT_DATA_SET_META_DATA) {
      LOGGER.debug("unsupported discovery announcement type: {}", announcementType);
      return;
    }

    UShort dataSetWriterId = decoder.decodeUInt16();

    var dataSetMetaData =
        (DataSetMetaDataType) decoder.decodeStruct("MetaData", DataSetMetaDataType.TYPE_ID);

    StatusCode status = decoder.decodeStatusCode();

    if (publisherId == null) {
      // Discovery messages shall carry a PublisherId (§7.2.4.6.3); without one the
      // announcement cannot be correlated with a Publisher.
      LOGGER.debug("DataSetMetaData announcement without PublisherId");
      return;
    }

    // Surfaced regardless of status; a Bad status is a denial the subscriber needs to see.
    announcement =
        UadpMetaDataAnnouncement.of(
            publisherId, announcementSequenceNumber, dataSetWriterId, dataSetMetaData, status);
  }

  private void decodeDiscoveryProbe() {
    int probeType = buffer.readUnsignedByte();

    if (probeType != UadpDiscoveryProbe.PROBE_TYPE_PUBLISHER_INFORMATION) {
      // FindApplications probes (2) and reserved values are tolerated and ignored.
      LOGGER.debug("unsupported discovery probe type: {}", probeType);
      return;
    }

    int informationType = buffer.readUnsignedByte();

    if (informationType != UadpDiscoveryProbe.INFORMATION_TYPE_DATA_SET_META_DATA) {
      // Publisher endpoints and writer/group/connection configuration probes are tolerated
      // and ignored.
      LOGGER.debug("unsupported discovery probe InformationType: {}", informationType);
      return;
    }

    // DataSetWriter settings (Table 180): standard OPC UA Binary array of UInt16; a null
    // (-1) or empty array surfaces as an empty list.
    int count = decoder.decodeInt32();
    if (count > buffer.readableBytes() / 2) {
      // a truncation signature: the array count promised more bytes than arrived
      LOGGER.debug("DataSetWriterIds count exceeds remaining bytes: {}", count);
      recordFailure(
          payloadFailureReason(),
          StatusCodes.Bad_DecodingError,
          "discovery probe DataSetWriterIds count exceeds remaining bytes: " + count);
      return;
    }

    List<UShort> dataSetWriterIds = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      dataSetWriterIds.add(decoder.decodeUInt16());
    }

    if (publisherId == null) {
      // The header PublisherId identifies the probed Publisher (§7.2.4.6.12.1); without one
      // the probe cannot be answered.
      LOGGER.debug("discovery probe without PublisherId");
      return;
    }

    probe = UadpDiscoveryProbe.of(publisherId, dataSetWriterIds);
  }

  private void decodeDataPayload(
      boolean payloadHeaderEnabled, @Nullable List<UShort> dataSetWriterIds) {

    // Without a PayloadHeader the number and sizes of DataSetMessages can only come from
    // reader configuration; assume a single DataSetMessage spanning the rest of the buffer.
    int count = dataSetWriterIds != null ? dataSetWriterIds.size() : 1;

    int[] sizes = null;
    if (payloadHeaderEnabled && count > 1) {
      sizes = new int[count];
      for (int i = 0; i < count; i++) {
        sizes[i] = decoder.decodeUInt16().intValue();
      }
    }

    for (int i = 0; i < count; i++) {
      UShort dataSetWriterId = dataSetWriterIds != null ? dataSetWriterIds.get(i) : null;

      if (sizes != null) {
        int size = sizes[i];
        if (size > buffer.readableBytes()) {
          // a truncated NetworkMessage: the Sizes array promised more payload than arrived;
          // everything decoded before this point is still delivered
          LOGGER.debug("DataSetMessage size exceeds remaining bytes: {}", size);
          recordFailure(
              payloadFailureReason(),
              StatusCodes.Bad_DecodingError,
              "DataSetMessage size exceeds remaining bytes: " + size);
          return;
        }

        ByteBuf slice = buffer.readSlice(size);
        OpcUaBinaryDecoder sliceDecoder = new OpcUaBinaryDecoder(encodingContext).setBuffer(slice);

        try {
          messages.add(decodeDataSetMessage(sliceDecoder, slice, dataSetWriterId));
        } catch (Exception e) {
          LOGGER.debug("failed to decode DataSetMessage {}: {}", i, e.getMessage(), e);

          messages.add(invalidDataSetMessage(dataSetWriterId));
        }
      } else {
        // Not size-bounded; an exception propagates and ends decoding of this
        // NetworkMessage with whatever was decoded so far.
        messages.add(decodeDataSetMessage(decoder, buffer, dataSetWriterId));
      }
    }
  }

  private static DecodedDataSetMessage decodeDataSetMessage(
      OpcUaBinaryDecoder decoder, ByteBuf buffer, @Nullable UShort dataSetWriterId) {

    int flags1 = buffer.readUnsignedByte();

    boolean valid = (flags1 & 0x01) != 0;
    if (!valid) {
      // "If the bit is false the rest of this DataSetMessage shall not be processed."
      return invalidDataSetMessage(dataSetWriterId);
    }

    int fieldEncoding = (flags1 >> 1) & 0x03;

    int flags2 = (flags1 & 0x80) != 0 ? buffer.readUnsignedByte() : 0;
    int messageType = flags2 & 0x0F;

    DataSetMessageKind kind =
        switch (messageType) {
          case 0x00 -> DataSetMessageKind.KEY_FRAME;
          case 0x01 -> DataSetMessageKind.DELTA_FRAME;
          case 0x02 -> DataSetMessageKind.EVENT;
          case 0x03 -> DataSetMessageKind.KEEP_ALIVE;
          default -> null;
        };

    // the DecodedDataSetMessage slot is UInt32 (JSON mapping range); UADP carries UInt16 values
    UInteger sequenceNumber = (flags1 & 0x08) != 0 ? uint(decoder.decodeUInt16().intValue()) : null;
    DateTime timestamp = (flags2 & 0x10) != 0 ? decoder.decodeDateTime() : null;
    if ((flags2 & 0x20) != 0) {
      // Consume; DataSetMessage PicoSeconds are not surfaced.
      decoder.decodeUInt16();
    }

    StatusCode status = null;
    if ((flags1 & 0x10) != 0) {
      // The header Status is the high-order 16 bits of the StatusCode.
      status = new StatusCode(decoder.decodeUInt16().longValue() << 16);
    }

    UInteger majorVersion = (flags1 & 0x20) != 0 ? decoder.decodeUInt32() : null;
    UInteger minorVersion = (flags1 & 0x40) != 0 ? decoder.decodeUInt32() : null;

    ConfigurationVersionDataType configurationVersion = null;
    if (majorVersion != null || minorVersion != null) {
      configurationVersion =
          new ConfigurationVersionDataType(
              majorVersion != null ? majorVersion : uint(0),
              minorVersion != null ? minorVersion : uint(0));
    }

    if (kind == null || fieldEncoding == FIELD_ENCODING_RESERVED) {
      LOGGER.debug(
          "reserved DataSetMessage type or field encoding: type={}, fieldEncoding={}",
          messageType,
          fieldEncoding);

      return new DecodedDataSetMessage(
          dataSetWriterId,
          DataSetMessageKind.KEY_FRAME,
          false,
          sequenceNumber,
          timestamp,
          status,
          configurationVersion,
          List.of());
    }

    if (kind == DataSetMessageKind.KEEP_ALIVE) {
      return new DecodedDataSetMessage(
          dataSetWriterId,
          kind,
          true,
          sequenceNumber,
          timestamp,
          status,
          configurationVersion,
          List.of());
    }

    if (fieldEncoding == FIELD_ENCODING_RAW_DATA) {
      // RawData decoding requires metadata-driven offsets; skip this DataSetMessage.
      LOGGER.debug("RawData field encoding is not supported; skipping DataSetMessage");

      return new DecodedDataSetMessage(
          dataSetWriterId,
          kind,
          false,
          sequenceNumber,
          timestamp,
          status,
          configurationVersion,
          List.of());
    }

    List<DecodedField> fields = new ArrayList<>();

    if (kind == DataSetMessageKind.DELTA_FRAME) {
      int fieldCount = decoder.decodeUInt16().intValue();

      for (int i = 0; i < fieldCount; i++) {
        int fieldIndex = decoder.decodeUInt16().intValue();
        fields.add(new DecodedField(fieldIndex, decodeFieldValue(decoder, fieldEncoding)));
      }
    } else if (buffer.readableBytes() > 0) {
      // Key frame or event. A key frame with no body at all is a heartbeat.
      int fieldCount = decoder.decodeUInt16().intValue();

      for (int i = 0; i < fieldCount; i++) {
        fields.add(new DecodedField(i, decodeFieldValue(decoder, fieldEncoding)));
      }
    }

    return new DecodedDataSetMessage(
        dataSetWriterId,
        kind,
        true,
        sequenceNumber,
        timestamp,
        status,
        configurationVersion,
        fields);
  }

  /**
   * Decode one field value, reversing the status propagation rules of Part 14 Table 34 for the
   * Variant field encoding: a Variant containing a Bad StatusCode is the field status, and a
   * Variant containing a DataValue carries an Uncertain value and status.
   */
  private static DataValue decodeFieldValue(OpcUaBinaryDecoder decoder, int fieldEncoding) {
    if (fieldEncoding == FIELD_ENCODING_DATA_VALUE) {
      return decoder.decodeDataValue();
    } else {
      Variant variant = decoder.decodeVariant();
      Object value = variant.value();

      if (value instanceof StatusCode statusCode && statusCode.isBad()) {
        return new DataValue(Variant.NULL_VALUE, statusCode, null, null, null, null);
      } else if (value instanceof DataValue dataValue) {
        return dataValue;
      } else {
        return new DataValue(variant, StatusCode.GOOD, null, null, null, null);
      }
    }
  }

  private static DecodedDataSetMessage invalidDataSetMessage(@Nullable UShort dataSetWriterId) {
    return new DecodedDataSetMessage(
        dataSetWriterId, DataSetMessageKind.KEY_FRAME, false, null, null, null, null, List.of());
  }
}
