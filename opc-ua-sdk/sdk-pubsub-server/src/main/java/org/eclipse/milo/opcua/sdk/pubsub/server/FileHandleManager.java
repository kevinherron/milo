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

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ulong;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.function.IntConsumer;
import java.util.function.Supplier;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UByte;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.ULong;

/**
 * The FileType state machine for the {@code PublishSubscribe/PubSubConfiguration} FileType object
 * (OPC UA Part 20 §4.2, with the Part 14 §9.1.3.7 overlay). Package-private and self-contained:
 * handle bookkeeping is keyed on {@code (sessionId, fileHandle)} and never touches {@link
 * org.eclipse.milo.opcua.sdk.server.Session} directly, so it is exercisable without a live session
 * (WP-X pin R2). The owning {@code RemoteConfigurationServer} bridges sessions to session {@link
 * NodeId}s and evicts on session close.
 *
 * <p>Contract (WP-X pin R3):
 *
 * <ul>
 *   <li>Only modes {@code Read (0x01)}, {@code Read+Write (0x03)} and {@code Write+EraseExisting
 *       (0x06)} are accepted; anything else (Append, bare Write, reserved bits, mode 0) is {@code
 *       Bad_InvalidArgument} (Part 14 §9.1.3.7.1).
 *   <li>Write is exclusive: opening for write requires zero existing handles ({@code
 *       Bad_NotWritable}); opening for read fails only while a writer is open ({@code
 *       Bad_NotReadable}) — Part 20 §4.2.2 shall-sentences.
 *   <li>A handle is valid only for the session that opened it; a foreign or unknown handle is
 *       {@code Bad_InvalidArgument}.
 *   <li>The read snapshot is materialized at Open, so parallel readers see a stable stream.
 *   <li>Reads clamp to {@code min(length, MaxByteStringLength, remaining)}; a non-positive length
 *       is {@code Bad_InvalidArgument}; an empty return signals end of file.
 *   <li>SetPosition clamps to end of file; Write extends the file; an empty/null Write is a Good
 *       no-op.
 *   <li>{@code CloseAndUpdate} on a {@code Read+Write} handle truncates the buffer at the final
 *       write position (so a shorter rewrite leaves no stale tail); {@code Write+EraseExisting} is
 *       the recommended full-rewrite mode and its buffer is committed verbatim.
 * </ul>
 *
 * <p>All methods are synchronized on this instance; PubSub configuration files are small and rarely
 * contended, so a single lock is sufficient.
 */
final class FileHandleManager {

  static final int MODE_READ = 0x01;
  static final int MODE_WRITE = 0x02;
  static final int MODE_ERASE = 0x04;
  static final int MODE_APPEND = 0x08;

  /** 1 MiB, matching the server's default {@code ServerCapabilities.MaxByteStringLength}. */
  static final long DEFAULT_MAX_BYTE_STRING_LENGTH = 1024L * 1024L;

  private final Map<HandleKey, Handle> handles = new HashMap<>();

  private long nextHandle = 1L;
  private boolean writerOpen = false;

  private final long maxByteStringLength;
  private final Supplier<byte[]> currentBytesSupplier;
  private final IntConsumer openCountListener;

  /**
   * @param maxByteStringLength the per-read/write byte cap (also advertised via the {@code
   *     MaxByteStringLength} property).
   * @param currentBytesSupplier materializes the current configuration bytes; invoked at Open to
   *     snapshot a read/read-write handle's content.
   * @param openCountListener notified with the new open-handle count after every open, close, and
   *     eviction so the owner can update the {@code OpenCount} property.
   */
  FileHandleManager(
      long maxByteStringLength,
      Supplier<byte[]> currentBytesSupplier,
      IntConsumer openCountListener) {

    this.maxByteStringLength = maxByteStringLength;
    this.currentBytesSupplier = currentBytesSupplier;
    this.openCountListener = openCountListener;
  }

  /**
   * Open the file, returning a new file handle for {@code sessionId}.
   *
   * @throws UaException {@code Bad_InvalidArgument} (invalid mode), {@code Bad_NotWritable} (write
   *     open while any handle exists), or {@code Bad_NotReadable} (read open while a writer
   *     exists).
   */
  synchronized UInteger open(NodeId sessionId, UByte mode) throws UaException {
    int m = mode.intValue();

    // Part 14 §9.1.3.7.1: only Read (0x01), Read+Write (0x03), Write+EraseExisting (0x06).
    if (m != MODE_READ && m != (MODE_READ | MODE_WRITE) && m != (MODE_WRITE | MODE_ERASE)) {
      throw new UaException(
          StatusCodes.Bad_InvalidArgument, "invalid mode: 0x" + Integer.toHexString(m));
    }

    boolean forWrite = (m & MODE_WRITE) != 0;

    if (forWrite) {
      if (!handles.isEmpty()) {
        throw new UaException(StatusCodes.Bad_NotWritable, "file is already open");
      }
    } else {
      if (writerOpen) {
        throw new UaException(StatusCodes.Bad_NotReadable, "file is open for writing");
      }
    }

    byte[] content;
    if ((m & MODE_ERASE) != 0) {
      content = new byte[0];
    } else {
      // snapshot the current configuration at Open for both read and read-write handles
      content = currentBytesSupplier.get().clone();
    }

    UInteger handle = uint(nextHandle++);
    handles.put(new HandleKey(sessionId, handle), new Handle(m, content));

    if (forWrite) {
      writerOpen = true;
    }

    openCountListener.accept(handles.size());

    return handle;
  }

  /**
   * Read up to {@code length} bytes from the current position, advancing it by the number returned.
   *
   * @throws UaException {@code Bad_InvalidArgument} (invalid handle or non-positive length) or
   *     {@code Bad_InvalidState} (handle not opened for read).
   */
  synchronized ByteString read(NodeId sessionId, UInteger handle, Integer length)
      throws UaException {

    Handle h = lookup(sessionId, handle);

    if ((h.mode & MODE_READ) == 0) {
      throw new UaException(StatusCodes.Bad_InvalidState, "file was not opened for read access");
    }
    if (length == null || length <= 0) {
      throw new UaException(StatusCodes.Bad_InvalidArgument, "non-positive length");
    }

    long remaining = h.content.length - h.position;
    if (remaining <= 0) {
      return ByteString.of(new byte[0]);
    }

    int n = (int) Math.min(Math.min((long) length, maxByteStringLength), remaining);
    int from = (int) h.position;
    byte[] slice = Arrays.copyOfRange(h.content, from, from + n);
    h.position += n;

    return ByteString.of(slice);
  }

  /**
   * Write {@code data} at the current position, overwriting in place and extending as needed;
   * advances the position and remembers the final write position for {@code CloseAndUpdate}
   * truncation.
   *
   * @throws UaException {@code Bad_InvalidArgument} (invalid handle) or {@code Bad_InvalidState}
   *     (handle not opened for write).
   */
  synchronized void write(NodeId sessionId, UInteger handle, ByteString data) throws UaException {
    Handle h = lookup(sessionId, handle);

    if ((h.mode & MODE_WRITE) == 0) {
      throw new UaException(StatusCodes.Bad_InvalidState, "file was not opened for write access");
    }
    if (data == null || data.isNullOrEmpty()) {
      // Part 20 §4.2.5: an empty or null write is a Good no-op with no effect on the file.
      return;
    }

    byte[] bytes = data.bytesOrEmpty();
    int start = (int) h.position;
    int end = start + bytes.length;

    if (end > h.content.length) {
      h.content = Arrays.copyOf(h.content, end);
    }
    System.arraycopy(bytes, 0, h.content, start, bytes.length);

    h.position = end;
    h.lastWriteEnd = end;
    h.written = true;
  }

  /**
   * Get the current position of {@code handle}.
   *
   * @throws UaException {@code Bad_InvalidArgument} if the handle is invalid.
   */
  synchronized ULong getPosition(NodeId sessionId, UInteger handle) throws UaException {
    return ulong(lookup(sessionId, handle).position);
  }

  /**
   * Set the current position of {@code handle}, clamping to end of file.
   *
   * @throws UaException {@code Bad_InvalidArgument} if the handle is invalid.
   */
  synchronized void setPosition(NodeId sessionId, UInteger handle, ULong position)
      throws UaException {

    Handle h = lookup(sessionId, handle);
    long requested = position != null ? position.longValue() : 0L;
    // Part 20 §4.2.7: clamp to end of file, not an error.
    h.position = Math.max(0L, Math.min(requested, h.content.length));
  }

  /**
   * Close {@code handle}, discarding any buffered writes.
   *
   * @throws UaException {@code Bad_InvalidArgument} if the handle is invalid.
   */
  synchronized void close(NodeId sessionId, UInteger handle) throws UaException {
    HandleKey key = new HandleKey(sessionId, handle);
    Handle h = handles.get(key);
    if (h == null) {
      throw new UaException(StatusCodes.Bad_InvalidArgument, "invalid file handle in call");
    }
    remove(key, h);
  }

  /**
   * Validate {@code handle} for a {@code CloseAndUpdate} commit and close it, returning the bytes
   * to apply. The handle is closed whether or not the caller ultimately applies the returned bytes
   * (Part 14 §9.1.3.7.6: CloseAndUpdate closes the file).
   *
   * @throws UaException {@code Bad_InvalidArgument} (invalid handle) or {@code Bad_InvalidState}
   *     (handle not opened for write) — the two method-level codes CloseAndUpdate can raise from
   *     handle state.
   */
  synchronized byte[] closeForUpdate(NodeId sessionId, UInteger handle) throws UaException {
    HandleKey key = new HandleKey(sessionId, handle);
    Handle h = handles.get(key);
    if (h == null) {
      throw new UaException(StatusCodes.Bad_InvalidArgument, "the file handle is not valid");
    }
    if ((h.mode & MODE_WRITE) == 0) {
      throw new UaException(
          StatusCodes.Bad_InvalidState, "the file was not opened for write access");
    }

    byte[] committed;
    if ((h.mode & MODE_ERASE) != 0 || !h.written) {
      // erase-mode buffer is committed verbatim; a write handle that never wrote commits its
      // (possibly snapshot) content unchanged
      committed = h.content.clone();
    } else {
      // Read+Write: truncate at the final write position so a shorter rewrite leaves no stale tail
      committed = Arrays.copyOf(h.content, h.lastWriteEnd);
    }

    remove(key, h);
    return committed;
  }

  /**
   * Evict every handle owned by {@code sessionId}; releases the write lock if the session held it.
   */
  synchronized void evictSession(NodeId sessionId) {
    boolean changed = false;
    var it = handles.entrySet().iterator();
    while (it.hasNext()) {
      Map.Entry<HandleKey, Handle> entry = it.next();
      if (entry.getKey().sessionId().equals(sessionId)) {
        if ((entry.getValue().mode & MODE_WRITE) != 0) {
          writerOpen = false;
        }
        it.remove();
        changed = true;
      }
    }
    if (changed) {
      openCountListener.accept(handles.size());
    }
  }

  /** The current number of valid file handles (the {@code OpenCount} property value). */
  synchronized int openCount() {
    return handles.size();
  }

  private Handle lookup(NodeId sessionId, UInteger handle) throws UaException {
    Handle h = handles.get(new HandleKey(sessionId, handle));
    if (h == null) {
      // includes handles opened by a different session: identity is (session, handle)
      throw new UaException(StatusCodes.Bad_InvalidArgument, "invalid file handle in call");
    }
    return h;
  }

  private void remove(HandleKey key, Handle h) {
    handles.remove(key);
    if ((h.mode & MODE_WRITE) != 0) {
      writerOpen = false;
    }
    openCountListener.accept(handles.size());
  }

  private record HandleKey(NodeId sessionId, UInteger handle) {}

  private static final class Handle {
    final int mode;
    byte[] content;
    long position;
    int lastWriteEnd;
    boolean written;

    Handle(int mode, byte[] content) {
      this.mode = mode;
      this.content = content;
      // Append is never a legal mode here, so the initial position is always 0
      this.position = 0L;
    }
  }
}
