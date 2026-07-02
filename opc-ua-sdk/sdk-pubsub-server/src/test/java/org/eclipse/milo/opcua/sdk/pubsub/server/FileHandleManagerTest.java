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

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ubyte;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ulong;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UByte;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.junit.jupiter.api.Test;

/** State-machine tests for {@link FileHandleManager} (Phase 5 pins R2/R3). */
class FileHandleManagerTest {

  private static final UByte READ = ubyte(0x01);
  private static final UByte READ_WRITE = ubyte(0x03);
  private static final UByte WRITE_ERASE = ubyte(0x06);

  private static final NodeId SESSION_A = new NodeId(1, "session-a");
  private static final NodeId SESSION_B = new NodeId(1, "session-b");

  private static final byte[] CONTENT = "helloworld".getBytes(StandardCharsets.UTF_8);

  private final AtomicInteger openCount = new AtomicInteger();

  private FileHandleManager manager(long maxByteStringLength) {
    return new FileHandleManager(maxByteStringLength, CONTENT::clone, openCount::set);
  }

  private FileHandleManager manager() {
    return manager(FileHandleManager.DEFAULT_MAX_BYTE_STRING_LENGTH);
  }

  @Test
  void rejectsModesOtherThanTheThreeAllowed() {
    FileHandleManager manager = manager();
    for (int mode : new int[] {0x00, 0x02, 0x04, 0x07, 0x05, 0x09, 0x0B}) {
      UaException e = assertThrows(UaException.class, () -> manager.open(SESSION_A, ubyte(mode)));
      assertEquals(StatusCodes.Bad_InvalidArgument, e.getStatusCode().getValue());
    }
  }

  @Test
  void writeOpenRequiresNoExistingHandle() throws Exception {
    FileHandleManager manager = manager();
    manager.open(SESSION_A, READ);

    UaException e = assertThrows(UaException.class, () -> manager.open(SESSION_B, READ_WRITE));
    assertEquals(StatusCodes.Bad_NotWritable, e.getStatusCode().getValue());
  }

  @Test
  void readOpenFailsOnlyWhileAWriterIsOpen() throws Exception {
    FileHandleManager manager = manager();
    manager.open(SESSION_A, WRITE_ERASE);

    UaException e = assertThrows(UaException.class, () -> manager.open(SESSION_B, READ));
    assertEquals(StatusCodes.Bad_NotReadable, e.getStatusCode().getValue());
  }

  @Test
  void parallelReadersAreAllowed() throws Exception {
    FileHandleManager manager = manager();
    manager.open(SESSION_A, READ);
    manager.open(SESSION_B, READ);
    assertEquals(2, manager.openCount());
    assertEquals(2, openCount.get());
  }

  @Test
  void aForeignSessionHandleIsInvalid() throws Exception {
    FileHandleManager manager = manager();
    UInteger handle = manager.open(SESSION_A, READ);

    UaException e = assertThrows(UaException.class, () -> manager.read(SESSION_B, handle, 10));
    assertEquals(StatusCodes.Bad_InvalidArgument, e.getStatusCode().getValue());
  }

  @Test
  void readReturnsTheSnapshotAndSignalsEofWithAnEmptyString() throws Exception {
    FileHandleManager manager = manager();
    UInteger handle = manager.open(SESSION_A, READ);

    ByteString first = manager.read(SESSION_A, handle, CONTENT.length);
    assertArrayEquals(CONTENT, first.bytesOrEmpty());

    ByteString eof = manager.read(SESSION_A, handle, 10);
    assertEquals(0, eof.length());
  }

  @Test
  void readClampsToMaxByteStringLength() throws Exception {
    FileHandleManager manager = manager(4);
    UInteger handle = manager.open(SESSION_A, READ);

    ByteString first = manager.read(SESSION_A, handle, 100);
    assertEquals(4, first.length());
  }

  @Test
  void readRejectsNonPositiveLength() throws Exception {
    FileHandleManager manager = manager();
    UInteger handle = manager.open(SESSION_A, READ);

    UaException e = assertThrows(UaException.class, () -> manager.read(SESSION_A, handle, 0));
    assertEquals(StatusCodes.Bad_InvalidArgument, e.getStatusCode().getValue());
  }

  @Test
  void readOnAWriteOnlyHandleIsInvalidState() throws Exception {
    FileHandleManager manager = manager();
    UInteger handle = manager.open(SESSION_A, WRITE_ERASE);

    UaException e = assertThrows(UaException.class, () -> manager.read(SESSION_A, handle, 10));
    assertEquals(StatusCodes.Bad_InvalidState, e.getStatusCode().getValue());
  }

  @Test
  void writeOnAReadOnlyHandleIsInvalidState() throws Exception {
    FileHandleManager manager = manager();
    UInteger handle = manager.open(SESSION_A, READ);

    UaException e =
        assertThrows(
            UaException.class,
            () -> manager.write(SESSION_A, handle, ByteString.of(new byte[] {1})));
    assertEquals(StatusCodes.Bad_InvalidState, e.getStatusCode().getValue());
  }

  @Test
  void emptyWriteIsAGoodNoOp() throws Exception {
    FileHandleManager manager = manager();
    UInteger handle = manager.open(SESSION_A, WRITE_ERASE);

    manager.write(SESSION_A, handle, ByteString.NULL_VALUE);
    manager.write(SESSION_A, handle, ByteString.of(new byte[0]));

    assertEquals(ulong(0), manager.getPosition(SESSION_A, handle));
  }

  @Test
  void writeExtendsAndAdvancesThePosition() throws Exception {
    FileHandleManager manager = manager();
    UInteger handle = manager.open(SESSION_A, WRITE_ERASE);

    manager.write(SESSION_A, handle, ByteString.of("abc".getBytes(StandardCharsets.UTF_8)));
    assertEquals(ulong(3), manager.getPosition(SESSION_A, handle));

    byte[] committed = manager.closeForUpdate(SESSION_A, handle);
    assertArrayEquals("abc".getBytes(StandardCharsets.UTF_8), committed);
  }

  @Test
  void setPositionClampsToEndOfFile() throws Exception {
    FileHandleManager manager = manager();
    UInteger handle = manager.open(SESSION_A, READ);

    manager.setPosition(SESSION_A, handle, ulong(1000));
    assertEquals(ulong(CONTENT.length), manager.getPosition(SESSION_A, handle));
  }

  @Test
  void closeAndUpdateTruncatesAtTheFinalWritePositionForReadWrite() throws Exception {
    FileHandleManager manager = manager();
    UInteger handle = manager.open(SESSION_A, READ_WRITE);

    // read-modify-write: rewrite from the start with a shorter payload
    manager.setPosition(SESSION_A, handle, ulong(0));
    manager.write(SESSION_A, handle, ByteString.of("hi".getBytes(StandardCharsets.UTF_8)));

    byte[] committed = manager.closeForUpdate(SESSION_A, handle);
    assertArrayEquals("hi".getBytes(StandardCharsets.UTF_8), committed);
  }

  @Test
  void closeAndUpdateOnAReadOnlyHandleIsInvalidState() throws Exception {
    FileHandleManager manager = manager();
    UInteger handle = manager.open(SESSION_A, READ);

    UaException e =
        assertThrows(UaException.class, () -> manager.closeForUpdate(SESSION_A, handle));
    assertEquals(StatusCodes.Bad_InvalidState, e.getStatusCode().getValue());
  }

  @Test
  void closeDiscardsAndDecrementsOpenCount() throws Exception {
    FileHandleManager manager = manager();
    UInteger handle = manager.open(SESSION_A, READ_WRITE);
    assertEquals(1, openCount.get());

    manager.close(SESSION_A, handle);
    assertEquals(0, openCount.get());

    // the write lock is released, so a new writer may open
    manager.open(SESSION_B, READ_WRITE);
    assertEquals(1, manager.openCount());
  }

  @Test
  void sessionEvictionReleasesHandlesAndTheWriteLock() throws Exception {
    FileHandleManager manager = manager();
    manager.open(SESSION_A, READ_WRITE);
    assertEquals(1, manager.openCount());

    manager.evictSession(SESSION_A);
    assertEquals(0, manager.openCount());
    assertEquals(0, openCount.get());

    // write lock released by eviction
    manager.open(SESSION_B, READ_WRITE);
    assertEquals(1, manager.openCount());
  }
}
