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
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetWriterConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublishedDataSetRef;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublisherId;
import org.eclipse.milo.opcua.sdk.pubsub.config.UadpDataSetWriterSettings;
import org.eclipse.milo.opcua.sdk.pubsub.config.UadpWriterGroupSettings;
import org.eclipse.milo.opcua.sdk.pubsub.config.WriterGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.security.MessageSecurityContext;
import org.eclipse.milo.opcua.sdk.pubsub.security.PubSubSecurityPolicy;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityContextResolver;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeyMaterial;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.encoding.DefaultEncodingContext;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingContext;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.ConfigurationVersionDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.DataSetFieldContentMask;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpDataSetMessageContentMask;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpNetworkMessageContentMask;
import org.junit.jupiter.api.Test;

/**
 * Message security vectors for the UADP codec (OPC UA Part 14 §7.2.4.4.3): computed golden vectors
 * for Sign and SignAndEncrypt with a fixed injectable MessageNonce, decode round trips, tamper
 * drops, resolver interactions, and both sign-only SecurityHeader forms.
 *
 * <p>The plaintext layout of every vector is hand-derived byte by byte from Table 154 / Annex
 * A.2.1.5-6; the ciphertext and signature bytes are computed <b>in the test</b> directly with
 * {@code javax.crypto} ({@code AES/CTR/NoPadding} with the Table 157 counter block, {@code
 * HmacSHA256}) — independent of the {@code UadpMessageSecurity} implementation the codec uses — so
 * encoder and primitives cross-check each other.
 */
class UadpSecurityCodecTest {

  /** SigningKey: 32 bytes 0x00..0x1F (both policies use a 32-byte HMAC-SHA2-256 key). */
  private static final byte[] SIGNING_KEY = sequentialBytes(32, 0x00);

  /** EncryptingKey for PubSub-Aes128-CTR: 16 bytes 0x40..0x4F. */
  private static final byte[] ENCRYPTING_KEY_128 = sequentialBytes(16, 0x40);

  /** EncryptingKey for PubSub-Aes256-CTR: 32 bytes 0x40..0x5F. */
  private static final byte[] ENCRYPTING_KEY_256 = sequentialBytes(32, 0x40);

  /** KeyNonce: 4 bytes (Table 155). */
  private static final byte[] KEY_NONCE = bytes(0xA0, 0xA1, 0xA2, 0xA3);

  /** Fixed MessageNonce: Random = DE AD BE EF, nonce SequenceNumber = 1 (UInt32 LE, Table 156). */
  private static final byte[] MESSAGE_NONCE = bytes(0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x00, 0x00, 0x00);

  private static final UInteger TOKEN_ID = uint(3);

  /**
   * The plaintext NetworkMessage header of the golden vectors, including the SecurityHeader, for
   * the given SecurityFlags: PublisherId Byte = 42, PayloadHeader with one DataSetMessage from
   * DataSetWriterId 1, SecurityTokenId = 3, NonceLength = 8, the fixed MessageNonce.
   */
  private static byte[] vectorHeader(int securityFlags) {
    return concat(
        bytes(
            0xD1, // byte 0: version 1 | PublisherId 0x10 | PayloadHeader 0x40 | ExtFlags1 0x80
            0x10, // ExtendedFlags1: PublisherId type Byte (000) | SecurityHeader 0x10
            0x2A, // PublisherId: Byte = 42
            0x01, // PayloadHeader: Count = 1
            0x01,
            0x00, // PayloadHeader: DataSetWriterIds[0] = 1 (UInt16 LE)
            securityFlags, // SecurityFlags (Table 154)
            0x03,
            0x00,
            0x00,
            0x00, // SecurityTokenId = 3 (IntegerId, UInt32 LE)
            0x08), // NonceLength = 8
        MESSAGE_NONCE); // MessageNonce: Random[4] || NonceSequenceNumber (UInt32 LE)
  }

  /** The plaintext payload of the golden vectors: one key frame, Int32 42 + Boolean true. */
  private static final byte[] VECTOR_PAYLOAD =
      bytes(
          0x01, // DataSetFlags1: valid 0x01 | field encoding 00 (Variant)
          0x02, 0x00, // FieldCount = 2 (UInt16 LE)
          0x06, 0x2A, 0x00, 0x00, 0x00, // field 0: Variant, type Int32 (6), value 42
          0x01, 0x01); // field 1: Variant, type Boolean (1), value true

  private final EncodingContext encodingContext = new DefaultEncodingContext();

  // region golden vectors

  /**
   * Sign-only, PubSub-Aes256-CTR: the Annex A.2.1.5 form — SecurityFlags 0x01 with a real
   * SecurityTokenId and 8-byte MessageNonce, plaintext payload, HMAC-SHA256 signature over the
   * whole NetworkMessage appended.
   */
  @Test
  void signOnlyGoldenVector() throws Exception {
    SecurityKeyMaterial material = material(PubSubSecurityPolicy.Aes256Ctr);
    byte[] encoded = encodeSecured(MessageSecurityMode.Sign, PubSubSecurityPolicy.Aes256Ctr);

    byte[] signedRegion = concat(vectorHeader(0x01), VECTOR_PAYLOAD);
    byte[] expected = concat(signedRegion, hmacSha256(SIGNING_KEY, signedRegion));

    assertArrayEquals(expected, encoded);

    DecodedNetworkMessage decoded = decode(encoded, resolver(material), null);

    assertNull(decoded.failure());
    assertNotNull(decoded.security());
    assertEquals(MessageSecurityMode.Sign, decoded.security().mode());
    assertEquals(TOKEN_ID, decoded.security().securityTokenId());
    assertFalse(decoded.security().forceKeyReset());

    assertEquals(1, decoded.messages().size());
    DecodedDataSetMessage message = decoded.messages().get(0);
    assertEquals(ushort(1), message.dataSetWriterId());
    assertTrue(message.valid());
    assertEquals(
        List.of(
            new DecodedField(0, goodValue(Variant.ofInt32(42))),
            new DecodedField(1, goodValue(Variant.ofBoolean(true)))),
        message.fields());
  }

  /**
   * SignAndEncrypt, PubSub-Aes128-CTR: SecurityFlags 0x03, payload region AES-CTR-encrypted with
   * the Table 157 counter block (KeyNonce || MessageNonce || 00000001), then the whole
   * NetworkMessage signed and the signature appended (§7.2.4.4.1 order of operations).
   */
  @Test
  void signAndEncryptGoldenVector() throws Exception {
    SecurityKeyMaterial material = material(PubSubSecurityPolicy.Aes128Ctr);
    byte[] encoded =
        encodeSecured(MessageSecurityMode.SignAndEncrypt, PubSubSecurityPolicy.Aes128Ctr);

    byte[] ciphertext = aesCtr(ENCRYPTING_KEY_128, KEY_NONCE, MESSAGE_NONCE, VECTOR_PAYLOAD);
    byte[] signedRegion = concat(vectorHeader(0x03), ciphertext);
    byte[] expected = concat(signedRegion, hmacSha256(SIGNING_KEY, signedRegion));

    assertArrayEquals(expected, encoded);

    DecodedNetworkMessage decoded = decode(encoded, resolver(material), null);

    assertNull(decoded.failure());
    assertNotNull(decoded.security());
    assertEquals(MessageSecurityMode.SignAndEncrypt, decoded.security().mode());
    assertEquals(TOKEN_ID, decoded.security().securityTokenId());

    assertEquals(1, decoded.messages().size());
    assertEquals(
        List.of(
            new DecodedField(0, goodValue(Variant.ofInt32(42))),
            new DecodedField(1, goodValue(Variant.ofBoolean(true)))),
        decoded.messages().get(0).fields());
  }

  /** The arrival buffer is shared with other mapping providers and must never be mutated. */
  @Test
  void decodeNeverMutatesArrivalBuffer() throws Exception {
    SecurityKeyMaterial material = material(PubSubSecurityPolicy.Aes128Ctr);
    byte[] encoded =
        encodeSecured(MessageSecurityMode.SignAndEncrypt, PubSubSecurityPolicy.Aes128Ctr);
    byte[] original = encoded.clone();

    ByteBuf buffer = Unpooled.wrappedBuffer(encoded);
    try {
      DecodedNetworkMessage decoded =
          new UadpMessageMapping()
              .decode(DecodeContext.of(encodingContext, resolver(material)), buffer);
      assertEquals(1, decoded.messages().size());
    } finally {
      buffer.release();
    }

    // The ciphertext was decrypted into a copy; the arrival bytes are untouched.
    assertArrayEquals(original, encoded);
  }

  // endregion

  // region tamper and drop behavior

  /** A flipped ciphertext byte fails verification: the message yields NO DataSetMessages. */
  @Test
  void tamperedPayloadDropsWholeMessage() throws Exception {
    SecurityKeyMaterial material = material(PubSubSecurityPolicy.Aes128Ctr);
    byte[] encoded =
        encodeSecured(MessageSecurityMode.SignAndEncrypt, PubSubSecurityPolicy.Aes128Ctr);

    // Flip one bit in the first encrypted payload byte (after the 20-byte header:
    // 6 plaintext header bytes + 14-byte SecurityHeader).
    encoded[20] ^= 0x01;

    DecodedNetworkMessage decoded = decode(encoded, resolver(material), null);

    assertTrue(decoded.messages().isEmpty());
    assertNotNull(decoded.failure());
    assertEquals(StatusCodes.Bad_SecurityChecksFailed, decoded.failure().statusCode().value());
    assertEquals(
        DecodedNetworkMessage.Failure.Reason.SIGNATURE_INVALID, decoded.failure().reason());

    // The SecurityHeader values are still surfaced on the dropped message.
    assertNotNull(decoded.security());
    assertEquals(TOKEN_ID, decoded.security().securityTokenId());
  }

  /** A flipped signature byte fails verification the same way. */
  @Test
  void tamperedSignatureDropsWholeMessage() throws Exception {
    SecurityKeyMaterial material = material(PubSubSecurityPolicy.Aes256Ctr);
    byte[] encoded = encodeSecured(MessageSecurityMode.Sign, PubSubSecurityPolicy.Aes256Ctr);

    encoded[encoded.length - 1] ^= 0x01;

    DecodedNetworkMessage decoded = decode(encoded, resolver(material), null);

    assertTrue(decoded.messages().isEmpty());
    assertNotNull(decoded.failure());
    assertEquals(
        DecodedNetworkMessage.Failure.Reason.SIGNATURE_INVALID, decoded.failure().reason());
  }

  /** An empty resolution drops the message; the resolver is the counting point for the reason. */
  @Test
  void emptyResolutionDropsMessage() throws Exception {
    byte[] encoded = encodeSecured(MessageSecurityMode.Sign, PubSubSecurityPolicy.Aes256Ctr);

    DecodedNetworkMessage decoded =
        decode(encoded, (p, w, ids, mode, tokenId) -> Optional.empty(), null);

    assertTrue(decoded.messages().isEmpty());
    assertNotNull(decoded.failure());
    assertEquals(DecodedNetworkMessage.Failure.Reason.UNRESOLVED_KEYS, decoded.failure().reason());
    assertNotNull(decoded.security());
  }

  /** The resolver receives exactly the wire-provided identifiers, in wire order. */
  @Test
  void resolverReceivesWireArguments() throws Exception {
    byte[] encoded = encodeSecured(MessageSecurityMode.Sign, PubSubSecurityPolicy.Aes256Ctr);

    var arguments = new AtomicReference<List<Object>>();
    SecurityContextResolver resolver =
        (publisherId, writerGroupId, dataSetWriterIds, receivedMode, securityTokenId) -> {
          arguments.set(
              Arrays.asList(
                  publisherId, writerGroupId, dataSetWriterIds, receivedMode, securityTokenId));
          return Optional.empty();
        };

    decode(encoded, resolver, null);

    assertEquals(
        List.of(
            PublisherId.ubyte(ubyte(42)), List.of(ushort(1)), MessageSecurityMode.Sign, TOKEN_ID),
        Arrays.asList(
            arguments.get().get(0),
            arguments.get().get(2),
            arguments.get().get(3),
            arguments.get().get(4)));
    // The GroupHeader is disabled in the vector: no WriterGroupId on the wire.
    assertNull(arguments.get().get(1));
  }

  /**
   * The literal Table 154 sign-only form — SecurityTokenId 0, NonceLength 0 — is accepted on decode
   * (K4: NonceLength is self-describing; the nonce is not needed to verify).
   */
  @Test
  void signOnlyLiteralZeroNonceFormAccepted() throws Exception {
    SecurityKeyMaterial material = material(PubSubSecurityPolicy.Aes256Ctr);

    byte[] header =
        bytes(
            0xD1, // byte 0: version 1 | PublisherId | PayloadHeader | ExtFlags1
            0x10, // ExtendedFlags1: PublisherId type Byte | SecurityHeader
            0x2A, // PublisherId: Byte = 42
            0x01, // PayloadHeader: Count = 1
            0x01, 0x00, // PayloadHeader: DataSetWriterIds[0] = 1
            0x01, // SecurityFlags = signed
            0x00, 0x00, 0x00, 0x00, // SecurityTokenId = 0 (literal "bit 1 and 2" reading)
            0x00); // NonceLength = 0, no MessageNonce bytes

    byte[] signedRegion = concat(header, VECTOR_PAYLOAD);
    byte[] message = concat(signedRegion, hmacSha256(SIGNING_KEY, signedRegion));

    DecodedNetworkMessage decoded = decode(message, resolver(material), null);

    assertNull(decoded.failure());
    assertNotNull(decoded.security());
    assertEquals(uint(0), decoded.security().securityTokenId());
    assertEquals(1, decoded.messages().size());
    assertEquals(2, decoded.messages().get(0).fields().size());
  }

  /** The force-key-reset bit (SecurityFlags bit 3) is surfaced on a processed message. */
  @Test
  void forceKeyResetBitSurfaced() throws Exception {
    SecurityKeyMaterial material = material(PubSubSecurityPolicy.Aes256Ctr);

    // Sign-only with bit 3 set: SecurityFlags = 0x09.
    byte[] signedRegion = concat(vectorHeader(0x09), VECTOR_PAYLOAD);
    byte[] message = concat(signedRegion, hmacSha256(SIGNING_KEY, signedRegion));

    DecodedNetworkMessage decoded = decode(message, resolver(material), null);

    assertNull(decoded.failure());
    assertNotNull(decoded.security());
    assertEquals(MessageSecurityMode.Sign, decoded.security().mode());
    assertTrue(decoded.security().forceKeyReset());
    assertEquals(1, decoded.messages().size());
  }

  /**
   * An encrypted message whose MessageNonce is shorter than the 8 bytes the AES-CTR counter block
   * requires (Table 157) cannot be decrypted and is dropped after verification.
   */
  @Test
  void encryptedShortNonceUnsupported() throws Exception {
    SecurityKeyMaterial material = material(PubSubSecurityPolicy.Aes128Ctr);

    byte[] header =
        bytes(
            0xD1, // byte 0: version 1 | PublisherId | PayloadHeader | ExtFlags1
            0x10, // ExtendedFlags1: PublisherId type Byte | SecurityHeader
            0x2A, // PublisherId: Byte = 42
            0x01, // PayloadHeader: Count = 1
            0x01, 0x00, // PayloadHeader: DataSetWriterIds[0] = 1
            0x03, // SecurityFlags = signed | encrypted
            0x03, 0x00, 0x00, 0x00, // SecurityTokenId = 3
            0x04, // NonceLength = 4: too short for the AES-CTR counter block
            0xDE, 0xAD, 0xBE, 0xEF); // MessageNonce (4 bytes)

    // The payload bytes are irrelevant (never decrypted); the signature must verify to reach
    // the nonce-length check.
    byte[] signedRegion = concat(header, VECTOR_PAYLOAD);
    byte[] message = concat(signedRegion, hmacSha256(SIGNING_KEY, signedRegion));

    DecodedNetworkMessage decoded = decode(message, resolver(material), null);

    assertTrue(decoded.messages().isEmpty());
    assertNotNull(decoded.failure());
    assertEquals(StatusCodes.Bad_NotSupported, decoded.failure().statusCode().value());
    assertEquals(
        DecodedNetworkMessage.Failure.Reason.SECURITY_UNSUPPORTED, decoded.failure().reason());
  }

  /** A secured message too short to carry its signature is a truncation, not a bad signature. */
  @Test
  void securedMessageTooShortForSignature() throws Exception {
    SecurityKeyMaterial material = material(PubSubSecurityPolicy.Aes256Ctr);

    // Header + 5 payload bytes, no signature at all: fewer remaining bytes than the 32-byte
    // signature the resolved policy requires.
    byte[] message = concat(vectorHeader(0x01), bytes(0x01, 0x02, 0x00, 0x06, 0x2A));

    DecodedNetworkMessage decoded = decode(message, resolver(material), null);

    assertTrue(decoded.messages().isEmpty());
    assertNotNull(decoded.failure());
    assertEquals(StatusCodes.Bad_DecodingError, decoded.failure().statusCode().value());
    assertEquals(DecodedNetworkMessage.Failure.Reason.DECODING_ERROR, decoded.failure().reason());
  }

  // endregion

  // region encode-side contract

  /** A nonce supplier returning the wrong length is an internal error, never a short header. */
  @Test
  void nonceSupplierWrongLengthIsInternalError() {
    SecurityKeyMaterial material = material(PubSubSecurityPolicy.Aes256Ctr);
    MessageSecurityContext securityContext =
        MessageSecurityContext.of(
            MessageSecurityMode.Sign,
            PubSubSecurityPolicy.Aes256Ctr,
            TOKEN_ID,
            material,
            () -> new byte[4]);

    EncodeContext context = encodeContext(securityContext);

    UaException e = assertThrows(UaException.class, () -> new UadpMessageMapping().encode(context));
    assertEquals(StatusCodes.Bad_InternalError, e.getStatusCode().value());
  }

  /** A null security context produces output byte-identical to the unsecured encoder. */
  @Test
  void nullSecurityContextIsByteIdenticalToUnsecured() throws Exception {
    byte[] unsecured = encodeToBytes(encodeContext(null));

    byte[] expected =
        bytes(
            0x51, // byte 0: version 1 | PublisherId 0x10 | PayloadHeader 0x40; no ExtFlags1
            0x2A, // PublisherId: Byte = 42
            0x01, // PayloadHeader: Count = 1
            0x01, 0x00); // PayloadHeader: DataSetWriterIds[0] = 1

    assertArrayEquals(concat(expected, VECTOR_PAYLOAD), unsecured);
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

  /** HMAC-SHA256 computed directly with javax.crypto, independent of UadpMessageSecurity. */
  private static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));
    return mac.doFinal(data);
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

  private static SecurityKeyMaterial material(PubSubSecurityPolicy policy) {
    byte[] encryptingKey =
        policy == PubSubSecurityPolicy.Aes128Ctr ? ENCRYPTING_KEY_128 : ENCRYPTING_KEY_256;
    return SecurityKeyMaterial.of(policy, SIGNING_KEY, encryptingKey, KEY_NONCE);
  }

  private static SecurityContextResolver resolver(SecurityKeyMaterial material) {
    return (publisherId, writerGroupId, dataSetWriterIds, receivedMode, securityTokenId) ->
        Optional.of(material);
  }

  private static DataValue goodValue(Variant value) {
    return new DataValue(value, StatusCode.GOOD, null, null, null, null);
  }

  private byte[] encodeSecured(MessageSecurityMode mode, PubSubSecurityPolicy policy)
      throws UaException {

    MessageSecurityContext securityContext =
        MessageSecurityContext.of(mode, policy, TOKEN_ID, material(policy), () -> MESSAGE_NONCE);

    return encodeToBytes(encodeContext(securityContext));
  }

  private EncodeContext encodeContext(MessageSecurityContext securityContext) {
    DataSetWriterConfig writer =
        DataSetWriterConfig.builder("writer-1")
            .dataSet(new PublishedDataSetRef("ds"))
            .dataSetWriterId(ushort(1))
            .fieldContentMask(new DataSetFieldContentMask(uint(0x00)))
            .settings(
                UadpDataSetWriterSettings.builder()
                    .dataSetMessageContentMask(new UadpDataSetMessageContentMask(uint(0x00)))
                    .build())
            .build();

    // NM mask 0x41: bit 0 PublisherId | bit 6 PayloadHeader (Table 97).
    WriterGroupConfig group =
        WriterGroupConfig.builder("group")
            .writerGroupId(ushort(258))
            .messageSettings(
                UadpWriterGroupSettings.builder()
                    .networkMessageContentMask(new UadpNetworkMessageContentMask(uint(0x41)))
                    .build())
            .dataSetWriter(writer)
            .build();

    DataSetMessageDraft draft =
        DataSetMessageDraft.of(
            writer,
            uint(0),
            null,
            null,
            new ConfigurationVersionDataType(uint(0), uint(0)),
            false,
            List.of(goodValue(Variant.ofInt32(42)), goodValue(Variant.ofBoolean(true))));

    return EncodeContext.of(
        encodingContext,
        PublisherId.ubyte(ubyte(42)),
        group,
        uint(1),
        ushort(1),
        ushort(16),
        null,
        List.of(draft),
        securityContext);
  }

  private byte[] encodeToBytes(EncodeContext context) throws UaException {
    List<EncodedNetworkMessage> encoded = new UadpMessageMapping().encode(context);
    assertEquals(1, encoded.size(), "UADP encode returns a singleton list");
    try {
      return ByteBufUtil.getBytes(encoded.get(0).data());
    } finally {
      encoded.get(0).data().release();
    }
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
