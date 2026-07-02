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

import java.util.List;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublisherId;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.jspecify.annotations.Nullable;

/**
 * A decoded NetworkMessage: the header values present on the wire plus the decoded DataSetMessages
 * and any discovery metadata announcements it carried.
 *
 * <p>Header components are {@code null} when the corresponding header was not present on the wire;
 * the reader matching chain treats absent values as wildcards.
 *
 * <p>A non-null {@link #security()} reports the SecurityHeader values of a message whose
 * SecurityFlags had any of the signed, encrypted, or force-key-reset bits set — including messages
 * that were subsequently dropped, so the subscriber key manager can observe unknown token ids and
 * force-key-reset signals on messages it could not process. It is {@code null} for messages without
 * a SecurityHeader and for the plain mode-None header ({@code SecurityFlags == 0}).
 *
 * <p>A non-null {@link #failure()} reports that decoding could not complete: the message was
 * truncated or malformed past the failure point, was dropped by a security check, or carried a
 * chunked payload that could not be consumed. The tolerant-decode contract is preserved —
 * everything decoded before the failure point is still present in {@link #messages()} and {@link
 * #metaData()} — but the failure is observable so callers can count it. A secured message that
 * fails a security check is dropped whole: it never contributes DataSetMessages. Input that is
 * merely foreign or tolerated-and-skipped (e.g. a non-UADP version nibble, reserved flag values)
 * does not report a failure.
 *
 * @param publisherId the publisher id, or {@code null} if not present.
 * @param writerGroupId the WriterGroupId, or {@code null} if not present.
 * @param groupVersion the GroupVersion, or {@code null} if not present.
 * @param networkMessageNumber the NetworkMessageNumber, or {@code null} if not present.
 * @param sequenceNumber the NetworkMessage SequenceNumber, or {@code null} if not present.
 * @param timestamp the NetworkMessage timestamp, or {@code null} if not present.
 * @param messages the decoded DataSetMessages, in payload order; possibly empty.
 * @param metaData the DataSetMetaData announcements carried by the message; possibly empty.
 * @param failure the decode failure, or {@code null} if decoding completed.
 * @param security the received SecurityHeader values, or {@code null} if the message carried no
 *     SecurityHeader or a plain mode-None header.
 * @apiNote Create instances via {@link #of(PublisherId, UShort, UInteger, UShort, UShort, DateTime,
 *     List, List)} rather than the canonical constructor; the factory methods are stable while the
 *     canonical constructor is not.
 */
public record DecodedNetworkMessage(
    @Nullable PublisherId publisherId,
    @Nullable UShort writerGroupId,
    @Nullable UInteger groupVersion,
    @Nullable UShort networkMessageNumber,
    @Nullable UShort sequenceNumber,
    @Nullable DateTime timestamp,
    List<DecodedDataSetMessage> messages,
    List<DecodedMetaData> metaData,
    @Nullable Failure failure,
    @Nullable Security security)
    implements UadpDecodedMessage {

  /**
   * Create a new {@link DecodedNetworkMessage}.
   *
   * @param publisherId the publisher id, or {@code null} if not present.
   * @param writerGroupId the WriterGroupId, or {@code null} if not present.
   * @param groupVersion the GroupVersion, or {@code null} if not present.
   * @param networkMessageNumber the NetworkMessageNumber, or {@code null} if not present.
   * @param sequenceNumber the NetworkMessage SequenceNumber, or {@code null} if not present.
   * @param timestamp the NetworkMessage timestamp, or {@code null} if not present.
   * @param messages the decoded DataSetMessages, in payload order; possibly empty.
   * @param metaData the DataSetMetaData announcements carried by the message; possibly empty.
   * @param failure the decode failure, or {@code null} if decoding completed.
   * @param security the received SecurityHeader values, or {@code null} if the message carried no
   *     SecurityHeader or a plain mode-None header.
   */
  public DecodedNetworkMessage {
    messages = List.copyOf(messages);
    metaData = List.copyOf(metaData);
  }

  /**
   * Create a {@link DecodedNetworkMessage} without a decode failure.
   *
   * @param publisherId the publisher id, or {@code null} if not present.
   * @param writerGroupId the WriterGroupId, or {@code null} if not present.
   * @param groupVersion the GroupVersion, or {@code null} if not present.
   * @param networkMessageNumber the NetworkMessageNumber, or {@code null} if not present.
   * @param sequenceNumber the NetworkMessage SequenceNumber, or {@code null} if not present.
   * @param timestamp the NetworkMessage timestamp, or {@code null} if not present.
   * @param messages the decoded DataSetMessages, in payload order; possibly empty.
   * @param metaData the DataSetMetaData announcements carried by the message; possibly empty.
   * @return a new {@link DecodedNetworkMessage}.
   */
  public static DecodedNetworkMessage of(
      @Nullable PublisherId publisherId,
      @Nullable UShort writerGroupId,
      @Nullable UInteger groupVersion,
      @Nullable UShort networkMessageNumber,
      @Nullable UShort sequenceNumber,
      @Nullable DateTime timestamp,
      List<DecodedDataSetMessage> messages,
      List<DecodedMetaData> metaData) {

    return of(
        publisherId,
        writerGroupId,
        groupVersion,
        networkMessageNumber,
        sequenceNumber,
        timestamp,
        messages,
        metaData,
        null);
  }

  /**
   * Create a {@link DecodedNetworkMessage}.
   *
   * @param publisherId the publisher id, or {@code null} if not present.
   * @param writerGroupId the WriterGroupId, or {@code null} if not present.
   * @param groupVersion the GroupVersion, or {@code null} if not present.
   * @param networkMessageNumber the NetworkMessageNumber, or {@code null} if not present.
   * @param sequenceNumber the NetworkMessage SequenceNumber, or {@code null} if not present.
   * @param timestamp the NetworkMessage timestamp, or {@code null} if not present.
   * @param messages the decoded DataSetMessages, in payload order; possibly empty.
   * @param metaData the DataSetMetaData announcements carried by the message; possibly empty.
   * @param failure the decode failure, or {@code null} if decoding completed.
   * @return a new {@link DecodedNetworkMessage}.
   */
  public static DecodedNetworkMessage of(
      @Nullable PublisherId publisherId,
      @Nullable UShort writerGroupId,
      @Nullable UInteger groupVersion,
      @Nullable UShort networkMessageNumber,
      @Nullable UShort sequenceNumber,
      @Nullable DateTime timestamp,
      List<DecodedDataSetMessage> messages,
      List<DecodedMetaData> metaData,
      @Nullable Failure failure) {

    return of(
        publisherId,
        writerGroupId,
        groupVersion,
        networkMessageNumber,
        sequenceNumber,
        timestamp,
        messages,
        metaData,
        failure,
        null);
  }

  /**
   * Create a {@link DecodedNetworkMessage}.
   *
   * @param publisherId the publisher id, or {@code null} if not present.
   * @param writerGroupId the WriterGroupId, or {@code null} if not present.
   * @param groupVersion the GroupVersion, or {@code null} if not present.
   * @param networkMessageNumber the NetworkMessageNumber, or {@code null} if not present.
   * @param sequenceNumber the NetworkMessage SequenceNumber, or {@code null} if not present.
   * @param timestamp the NetworkMessage timestamp, or {@code null} if not present.
   * @param messages the decoded DataSetMessages, in payload order; possibly empty.
   * @param metaData the DataSetMetaData announcements carried by the message; possibly empty.
   * @param failure the decode failure, or {@code null} if decoding completed.
   * @param security the received SecurityHeader values, or {@code null} if the message carried no
   *     SecurityHeader or a plain mode-None header.
   * @return a new {@link DecodedNetworkMessage}.
   */
  public static DecodedNetworkMessage of(
      @Nullable PublisherId publisherId,
      @Nullable UShort writerGroupId,
      @Nullable UInteger groupVersion,
      @Nullable UShort networkMessageNumber,
      @Nullable UShort sequenceNumber,
      @Nullable DateTime timestamp,
      List<DecodedDataSetMessage> messages,
      List<DecodedMetaData> metaData,
      @Nullable Failure failure,
      @Nullable Security security) {

    return new DecodedNetworkMessage(
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

  /**
   * The SecurityHeader values received on the wire (OPC UA Part 14 §7.2.4.4.2 Table 154).
   *
   * <p>Populated whenever the received SecurityFlags had any of the signed (bit 0), encrypted (bit
   * 1), or force-key-reset (bit 3) bits set, whether or not the message passed its security checks;
   * the subscriber key manager uses it to observe token rollover, unknown token ids, and
   * force-key-reset signals (the Part 14 §8.3.2 refetch triggers) even on dropped messages.
   *
   * <p>The wire names no SecurityGroup: "The relation to the SecurityGroup is done through
   * DataSetWriterIds contained in the NetworkMessage" (Table 154) — the SecurityGroup is whatever
   * the resolver on the {@link DecodeContext} mapped the message's plaintext identifiers to.
   *
   * @param mode the security mode indicated by SecurityFlags bits 0 and 1: {@link
   *     MessageSecurityMode#SignAndEncrypt} when both are set, {@link MessageSecurityMode#Sign}
   *     when only bit 0 is set, {@link MessageSecurityMode#None} when neither is (only reachable
   *     with the force-key-reset bit set — such a message is processed as unsecured).
   * @param securityTokenId the SecurityTokenId identifying the key within the SecurityGroup.
   * @param forceKeyReset the force-key-reset bit (bit 3): the Publisher is about to invalidate all
   *     keys and Subscribers should fetch new keys now.
   * @param verified whether the message's signature verified against resolved key material. {@code
   *     false} for a message whose decode ended before verification could run (no resolver, no
   *     resolvable keys, truncated before its signature) or whose signature did not verify — such a
   *     message is unauthenticated, so nothing it carries (its sequence number included) may affect
   *     reader state (K18: only verified messages reach the Part 14 §7.2.3 sequence window). A
   *     failure recorded on a {@code verified} message occurred <em>after</em> verification
   *     (payload parsing, decryption structure, chunk consumption): its content is authentic and
   *     flows the normal tolerant-decode path. Always {@code false} for the processed-as-unsecured
   *     mode-None header (force-key-reset only): there is no signature to verify.
   */
  public record Security(
      MessageSecurityMode mode,
      UInteger securityTokenId,
      boolean forceKeyReset,
      boolean verified) {}

  /**
   * A decode failure: why a NetworkMessage could not be fully decoded, classified by {@link Reason}
   * so callers can maintain per-cause diagnostics counters.
   *
   * @param statusCode the status code classifying the failure.
   * @param message a human-readable description of the failure.
   * @param cause the exception that ended decoding, or {@code null} if the failure was detected
   *     without an exception. Compared by reference in {@link #equals(Object)}.
   * @param reason the failure taxonomy bucket; see {@link Reason} for the counter each value maps
   *     to.
   */
  public record Failure(
      StatusCode statusCode, String message, @Nullable Throwable cause, Reason reason) {

    /**
     * The failure taxonomy: which diagnostics counter a {@link Failure} maps to.
     *
     * <p>Resolution-time security drops ({@link #UNRESOLVED_KEYS}) are deliberately coarse here:
     * the {@link org.eclipse.milo.opcua.sdk.pubsub.security.SecurityContextResolver} is the
     * counting point for the fine-grained resolution drop reasons it decided (unknown token,
     * received mode below configured, no group, stale keys) — the decoder cannot distinguish them.
     * Signature and decrypt failures on resolved material are counted from this taxonomy, not by
     * the resolver.
     */
    public enum Reason {
      /**
       * Truncated or malformed input: an exception mid-decode or an explicit length field exceeding
       * the remaining bytes ({@code Bad_DecodingError}).
       */
      DECODING_ERROR,

      /**
       * The SecurityHeader is unsupported: reserved SecurityFlags bits set (Table 154 requires the
       * receiver to skip such messages), a SecurityFooter indicated (never emitted by the two
       * defined PubSub policies; unsupported on receive), or an encrypted message whose
       * MessageNonce is shorter than the 8 bytes AES-CTR requires.
       */
      SECURITY_UNSUPPORTED,

      /**
       * The SecurityFlags indicate an invalid mode: encrypted (bit 1) without signed (bit 0), which
       * Table 154 forbids ("bit 0 shall be true if bit 1 is true"). Mode-vs-configured acceptance
       * (Part 14 §7.2.4.3) is decided by the resolver and surfaces as {@link #UNRESOLVED_KEYS}.
       */
      SECURITY_MODE_REJECTED,

      /**
       * No key material could be resolved for a secured message: no resolver is configured on the
       * {@link DecodeContext}, or the resolver returned empty (unknown token id, mode below
       * configured, no resolvable group, stale keys — the resolver counts which).
       */
      UNRESOLVED_KEYS,

      /**
       * The trailing signature did not verify against the resolved key material; the message is
       * dropped whole, before any payload parsing (Part 14 §7.2.4.4.3.2). Maps to the
       * invalid-signature counter.
       */
      SIGNATURE_INVALID,

      /**
       * The decrypted payload could not be parsed. AES-CTR cannot itself detect corruption, and a
       * verified signature vouches for the ciphertext, so structural parse failures inside a
       * decrypted payload are classified here rather than as {@link #DECODING_ERROR}. Maps to the
       * decryption-errors counter.
       */
      DECRYPT_FAILED,

      /**
       * A chunked NetworkMessage (ExtendedFlags2 bit 0, Part 14 §7.2.4.4.4) could not be consumed:
       * no {@link ChunkReassembler} is configured ({@code Bad_NotSupported}), the chunk was a
       * discovery chunk (unsupported), its fields were malformed or truncated ({@code
       * Bad_DecodingError}), or the reassembler rejected it ({@code Bad_EncodingLimitsExceeded} for
       * size or buffer-budget violations).
       */
      CHUNK
    }
  }
}
