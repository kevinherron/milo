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

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ubyte;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublisherId;
import org.eclipse.milo.opcua.sdk.pubsub.security.PubSubSecurityPolicy;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityContextResolver;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeyMaterial;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.encoding.DefaultEncodingContext;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingContext;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.junit.jupiter.api.Test;

/**
 * Inbound chunk reassembly through the UADP decoder (OPC UA Part 14 §7.2.4.4.4, Tables 158/159):
 * chunk NetworkMessages hand-derived byte by byte, offered to a caller-owned {@link
 * ChunkReassembler} carried on the {@link DecodeContext}, with the completed payload decoded
 * through the normal DataSetMessage path. Secured chunks are verified and decrypted individually
 * per chunk NetworkMessage before reassembly.
 */
class UadpChunkDecodeTest {

  /**
   * The original DataSetMessage being chunked: a key frame with Variant fields Int32 42 and Boolean
   * true (10 bytes).
   */
  private static final byte[] DSM_BYTES =
      bytes(
          0x01, // DataSetFlags1: valid 0x01 | field encoding 00 (Variant)
          0x02, 0x00, // FieldCount = 2 (UInt16 LE)
          0x06, 0x2A, 0x00, 0x00, 0x00, // field 0: Variant, type Int32 (6), value 42
          0x01, 0x01); // field 1: Variant, type Boolean (1), value true

  private static final byte[] SIGNING_KEY = sequentialBytes(32, 0x00);
  private static final byte[] ENCRYPTING_KEY_128 = sequentialBytes(16, 0x40);
  private static final byte[] KEY_NONCE = bytes(0xA0, 0xA1, 0xA2, 0xA3);

  private final EncodingContext encodingContext = new DefaultEncodingContext();

  // region reassembly round trips

  /** Two chunks, in order: the first yields nothing, the second completes the DataSetMessage. */
  @Test
  void twoChunkReassemblyRoundTrip() {
    ChunkReassembler reassembler = ChunkReassembler.create();

    byte[] chunk1 = chunkMessage(7, 0, DSM_BYTES.length, Arrays.copyOfRange(DSM_BYTES, 0, 6));
    byte[] chunk2 =
        chunkMessage(7, 6, DSM_BYTES.length, Arrays.copyOfRange(DSM_BYTES, 6, DSM_BYTES.length));

    DecodedNetworkMessage first = decode(chunk1, null, reassembler);
    assertNull(first.failure());
    assertTrue(first.messages().isEmpty());
    assertEquals(PublisherId.ubyte(ubyte(42)), first.publisherId());

    DecodedNetworkMessage second = decode(chunk2, null, reassembler);
    assertNull(second.failure());
    assertEquals(1, second.messages().size());

    DecodedDataSetMessage message = second.messages().get(0);
    assertEquals(ushort(1), message.dataSetWriterId());
    assertEquals(DataSetMessageKind.KEY_FRAME, message.kind());
    assertTrue(message.valid());
    assertEquals(
        List.of(
            new DecodedField(0, goodValue(Variant.ofInt32(42))),
            new DecodedField(1, goodValue(Variant.ofBoolean(true)))),
        message.fields());
  }

  /** Chunks may arrive out of order (UDP): the last chunk first, then the first completes. */
  @Test
  void outOfOrderChunksReassemble() {
    ChunkReassembler reassembler = ChunkReassembler.create();

    byte[] chunk1 = chunkMessage(7, 0, DSM_BYTES.length, Arrays.copyOfRange(DSM_BYTES, 0, 6));
    byte[] chunk2 =
        chunkMessage(7, 6, DSM_BYTES.length, Arrays.copyOfRange(DSM_BYTES, 6, DSM_BYTES.length));

    assertTrue(decode(chunk2, null, reassembler).messages().isEmpty());

    DecodedNetworkMessage completed = decode(chunk1, null, reassembler);
    assertNull(completed.failure());
    assertEquals(1, completed.messages().size());
    assertEquals(2, completed.messages().get(0).fields().size());
  }

  /**
   * Secured chunks: each chunk NetworkMessage is signed and encrypted individually (with its own
   * MessageNonce), verified and decrypted before its chunk fields reach the reassembler.
   */
  @Test
  void securedTwoChunkReassemblyRoundTrip() throws Exception {
    ChunkReassembler reassembler = ChunkReassembler.create();
    SecurityKeyMaterial material =
        SecurityKeyMaterial.of(
            PubSubSecurityPolicy.Aes128Ctr, SIGNING_KEY, ENCRYPTING_KEY_128, KEY_NONCE);
    SecurityContextResolver resolver = (p, w, ids, mode, tokenId) -> Optional.of(material);

    // Each chunk NetworkMessage carries a UNIQUE MessageNonce: (key, nonce) never repeats.
    byte[] nonce1 = bytes(0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x00, 0x00, 0x00);
    byte[] nonce2 = bytes(0xDE, 0xAD, 0xBE, 0xEF, 0x02, 0x00, 0x00, 0x00);

    byte[] chunk1 =
        securedChunkMessage(7, 0, DSM_BYTES.length, Arrays.copyOfRange(DSM_BYTES, 0, 6), nonce1);
    byte[] chunk2 =
        securedChunkMessage(
            7, 6, DSM_BYTES.length, Arrays.copyOfRange(DSM_BYTES, 6, DSM_BYTES.length), nonce2);

    DecodedNetworkMessage first = decode(chunk1, resolver, reassembler);
    assertNull(first.failure());
    assertTrue(first.messages().isEmpty());
    assertNotNull(first.security());
    assertEquals(MessageSecurityMode.SignAndEncrypt, first.security().mode());

    DecodedNetworkMessage second = decode(chunk2, resolver, reassembler);
    assertNull(second.failure());
    assertEquals(1, second.messages().size());
    assertEquals(
        List.of(
            new DecodedField(0, goodValue(Variant.ofInt32(42))),
            new DecodedField(1, goodValue(Variant.ofBoolean(true)))),
        second.messages().get(0).fields());
  }

  /**
   * An UNSECURED chunk NetworkMessage spoofing the plaintext identifiers of an in-progress secured
   * reassembly — PublisherId and chunk-PayloadHeader DataSetWriterId are readable on the wire even
   * for secured chunks — with a newer MessageSequenceNumber must not abandon the secured assembly:
   * signature-verified and unverified chunks live in disjoint assembly key spaces, so an off-path
   * attacker with no key knowledge cannot censor large secured messages at the reassembly layer.
   */
  @Test
  void unsecuredSpoofedChunkDoesNotAbandonSecuredReassembly() throws Exception {
    ChunkReassembler reassembler = ChunkReassembler.create();
    SecurityKeyMaterial material =
        SecurityKeyMaterial.of(
            PubSubSecurityPolicy.Aes128Ctr, SIGNING_KEY, ENCRYPTING_KEY_128, KEY_NONCE);
    SecurityContextResolver resolver = (p, w, ids, mode, tokenId) -> Optional.of(material);

    byte[] nonce1 = bytes(0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x00, 0x00, 0x00);
    byte[] nonce2 = bytes(0xDE, 0xAD, 0xBE, 0xEF, 0x02, 0x00, 0x00, 0x00);

    byte[] chunk1 =
        securedChunkMessage(7, 0, DSM_BYTES.length, Arrays.copyOfRange(DSM_BYTES, 0, 6), nonce1);
    byte[] chunk2 =
        securedChunkMessage(
            7, 6, DSM_BYTES.length, Arrays.copyOfRange(DSM_BYTES, 6, DSM_BYTES.length), nonce2);

    assertNull(decode(chunk1, resolver, reassembler).failure());

    // the attacker's unsecured chunk: same (PublisherId, DataSetWriterId), NEWER sequence number
    byte[] spoofed = chunkMessage(8, 0, DSM_BYTES.length, Arrays.copyOfRange(DSM_BYTES, 0, 6));
    DecodedNetworkMessage spoofDecode = decode(spoofed, resolver, reassembler);
    assertNull(spoofDecode.failure());
    assertTrue(spoofDecode.messages().isEmpty());

    // the secured assembly is untouched: its second chunk still completes the DataSetMessage
    DecodedNetworkMessage completed = decode(chunk2, resolver, reassembler);
    assertNull(completed.failure());
    assertEquals(1, completed.messages().size());
    assertEquals(
        List.of(
            new DecodedField(0, goodValue(Variant.ofInt32(42))),
            new DecodedField(1, goodValue(Variant.ofBoolean(true)))),
        completed.messages().get(0).fields());
  }

  // endregion

  // region chunk failure taxonomy

  /** Without a reassembler on the DecodeContext, chunked messages drop with Bad_NotSupported. */
  @Test
  void chunkWithoutReassemblerFailsWithChunkReason() {
    byte[] chunk = chunkMessage(7, 0, DSM_BYTES.length, Arrays.copyOfRange(DSM_BYTES, 0, 6));

    DecodedNetworkMessage decoded = decode(chunk, null, null);

    assertTrue(decoded.messages().isEmpty());
    assertNotNull(decoded.failure());
    assertEquals(StatusCodes.Bad_NotSupported, decoded.failure().statusCode().value());
    assertEquals(DecodedNetworkMessage.Failure.Reason.CHUNK, decoded.failure().reason());
  }

  /** Chunked discovery announcements are not reassembled in this version. */
  @Test
  void chunkedDiscoveryMessageIsUnsupported() {
    byte[] message =
        bytes(
            0x91, // byte 0: version 1 | PublisherId 0x10 | ExtendedFlags1 0x80
            0x80, // ExtendedFlags1: PublisherId type Byte | ExtendedFlags2 present
            0x09, // ExtendedFlags2: chunk 0x01 | NM type discovery announcement (010 << 2)
            0x2A, // PublisherId: Byte = 42
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00); // (chunk fields, not decoded)

    DecodedNetworkMessage decoded = decode(message, null, ChunkReassembler.create());

    assertTrue(decoded.messages().isEmpty());
    assertNotNull(decoded.failure());
    assertEquals(StatusCodes.Bad_NotSupported, decoded.failure().statusCode().value());
    assertEquals(DecodedNetworkMessage.Failure.Reason.CHUNK, decoded.failure().reason());
  }

  /** A chunked data message without a PayloadHeader cannot be keyed (Table 158). */
  @Test
  void chunkedDataMessageWithoutPayloadHeaderFails() {
    byte[] message =
        bytes(
            0x91, // byte 0: version 1 | PublisherId 0x10 | ExtendedFlags1 0x80; NO PayloadHeader
            0x80, // ExtendedFlags1: PublisherId type Byte | ExtendedFlags2 present
            0x01, // ExtendedFlags2: chunk, NM type data
            0x2A, // PublisherId: Byte = 42
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00); // (chunk fields, not decoded)

    DecodedNetworkMessage decoded = decode(message, null, ChunkReassembler.create());

    assertTrue(decoded.messages().isEmpty());
    assertNotNull(decoded.failure());
    assertEquals(StatusCodes.Bad_DecodingError, decoded.failure().statusCode().value());
    assertEquals(DecodedNetworkMessage.Failure.Reason.CHUNK, decoded.failure().reason());
  }

  /** A ChunkData length promising more bytes than arrived is a truncation signature. */
  @Test
  void truncatedChunkDataFails() {
    byte[] message =
        concat(
            chunkHeader(),
            bytes(
                0x07, 0x00, // MessageSequenceNumber = 7
                0x00, 0x00, 0x00, 0x00, // ChunkOffset = 0
                0x0A, 0x00, 0x00, 0x00, // TotalSize = 10
                0x0A, 0x00, 0x00, 0x00, // ChunkData length = 10, but only 2 bytes follow
                0x01, 0x02));

    DecodedNetworkMessage decoded = decode(message, null, ChunkReassembler.create());

    assertTrue(decoded.messages().isEmpty());
    assertNotNull(decoded.failure());
    assertEquals(StatusCodes.Bad_DecodingError, decoded.failure().statusCode().value());
    assertEquals(DecodedNetworkMessage.Failure.Reason.CHUNK, decoded.failure().reason());
  }

  /** A TotalSize beyond the reassembler's per-message cap is rejected and surfaced. */
  @Test
  void oversizeTotalSizeIsRejected() {
    ChunkReassembler reassembler = ChunkReassembler.create(16, 1024, Duration.ofSeconds(10));

    byte[] message =
        concat(
            chunkHeader(),
            bytes(
                0x07, 0x00, // MessageSequenceNumber = 7
                0x00, 0x00, 0x00, 0x00, // ChunkOffset = 0
                0x20, 0x00, 0x00, 0x00, // TotalSize = 32: exceeds the 16-byte cap
                0x02, 0x00, 0x00, 0x00, // ChunkData length = 2
                0x01, 0x02));

    DecodedNetworkMessage decoded = decode(message, null, reassembler);

    assertTrue(decoded.messages().isEmpty());
    assertNotNull(decoded.failure());
    assertEquals(StatusCodes.Bad_EncodingLimitsExceeded, decoded.failure().statusCode().value());
    assertEquals(DecodedNetworkMessage.Failure.Reason.CHUNK, decoded.failure().reason());
  }

  // endregion

  // region helpers

  private static byte[] bytes(int... values) {
    byte[] bs = new byte[values.length];
    for (int i = 0; i < values.length; i++) {
      bs[i] = (byte) values[i];
    }
    return bs;
  }

  private static byte[] sequentialBytes(int length, int firstValue) {
    byte[] bs = new byte[length];
    for (int i = 0; i < length; i++) {
      bs[i] = (byte) (firstValue + i);
    }
    return bs;
  }

  private static byte[] concat(byte[]... arrays) {
    int length = 0;
    for (byte[] array : arrays) {
      length += array.length;
    }
    byte[] result = new byte[length];
    int offset = 0;
    for (byte[] array : arrays) {
      System.arraycopy(array, 0, result, offset, array.length);
      offset += array.length;
    }
    return result;
  }

  /**
   * The unsecured chunk NetworkMessage header: PublisherId Byte = 42, chunk PayloadHeader with
   * DataSetWriterId = 1 (Table 158, no Count byte).
   */
  private static byte[] chunkHeader() {
    return bytes(
        0xD1, // byte 0: version 1 | PublisherId 0x10 | PayloadHeader 0x40 | ExtFlags1 0x80
        0x80, // ExtendedFlags1: PublisherId type Byte (000) | ExtendedFlags2 present 0x80
        0x01, // ExtendedFlags2: chunk 0x01, NM type data (000)
        0x2A, // PublisherId: Byte = 42
        0x01, 0x00); // PayloadHeader (chunk form): DataSetWriterId = 1 (UInt16 LE)
  }

  /** The Table 159 chunk payload fields. */
  private static byte[] chunkFields(
      int sequenceNumber, int chunkOffset, int totalSize, byte[] data) {
    return concat(
        bytes(
            sequenceNumber & 0xFF,
            (sequenceNumber >>> 8) & 0xFF, // MessageSequenceNumber (LE)
            chunkOffset & 0xFF,
            (chunkOffset >>> 8) & 0xFF,
            (chunkOffset >>> 16) & 0xFF,
            (chunkOffset >>> 24) & 0xFF, // ChunkOffset (UInt32 LE)
            totalSize & 0xFF,
            (totalSize >>> 8) & 0xFF,
            (totalSize >>> 16) & 0xFF,
            (totalSize >>> 24) & 0xFF, // TotalSize (UInt32 LE)
            data.length & 0xFF,
            (data.length >>> 8) & 0xFF,
            (data.length >>> 16) & 0xFF,
            (data.length >>> 24) & 0xFF), // ChunkData length (ByteString, Int32 LE)
        data);
  }

  /** One complete unsecured chunk NetworkMessage. */
  private static byte[] chunkMessage(
      int sequenceNumber, int chunkOffset, int totalSize, byte[] data) {

    return concat(chunkHeader(), chunkFields(sequenceNumber, chunkOffset, totalSize, data));
  }

  /**
   * One complete SignAndEncrypt chunk NetworkMessage (PubSub-Aes128-CTR): the Table 159 fields are
   * the encrypted payload region; the signature covers the whole NetworkMessage.
   */
  private static byte[] securedChunkMessage(
      int sequenceNumber, int chunkOffset, int totalSize, byte[] data, byte[] messageNonce)
      throws Exception {

    byte[] header =
        concat(
            bytes(
                0xD1, // byte 0: version 1 | PublisherId | PayloadHeader | ExtFlags1
                0x90, // ExtendedFlags1: SecurityHeader 0x10 | ExtendedFlags2 present 0x80
                0x01, // ExtendedFlags2: chunk, NM type data
                0x2A, // PublisherId: Byte = 42
                0x01, 0x00, // PayloadHeader (chunk form): DataSetWriterId = 1
                0x03, // SecurityFlags: signed | encrypted
                0x03, 0x00, 0x00, 0x00, // SecurityTokenId = 3
                0x08), // NonceLength = 8
            messageNonce);

    byte[] plaintext = chunkFields(sequenceNumber, chunkOffset, totalSize, data);
    byte[] ciphertext = aesCtr(ENCRYPTING_KEY_128, KEY_NONCE, messageNonce, plaintext);

    byte[] signedRegion = concat(header, ciphertext);

    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(SIGNING_KEY, "HmacSHA256"));
    byte[] signature = mac.doFinal(signedRegion);

    return concat(signedRegion, signature);
  }

  /**
   * AES-CTR computed directly with javax.crypto: counter block = KeyNonce(4) || MessageNonce(8) ||
   * 00000001 (Part 14 Table 157), block counter big-endian starting at 1.
   */
  private static byte[] aesCtr(byte[] key, byte[] keyNonce, byte[] messageNonce, byte[] data)
      throws Exception {

    byte[] counterBlock = new byte[16];
    System.arraycopy(keyNonce, 0, counterBlock, 0, 4);
    System.arraycopy(messageNonce, 0, counterBlock, 4, 8);
    counterBlock[15] = 0x01;

    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
    cipher.init(
        Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(counterBlock));
    return cipher.doFinal(data);
  }

  private static DataValue goodValue(Variant value) {
    return new DataValue(value, StatusCode.GOOD, null, null, null, null);
  }

  private DecodedNetworkMessage decode(
      byte[] message, SecurityContextResolver resolver, ChunkReassembler reassembler) {

    ByteBuf buffer = Unpooled.wrappedBuffer(message);
    try {
      return new UadpMessageMapping()
          .decode(DecodeContext.of(encodingContext, resolver, reassembler), buffer);
    } finally {
      buffer.release();
    }
  }

  // endregion
}
