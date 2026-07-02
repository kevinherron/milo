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

import org.eclipse.milo.opcua.sdk.pubsub.ReconfigureResult;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;

/**
 * Notified by {@link RemoteConfigurationServer} after a {@code CloseAndUpdate} applies a
 * configuration change, carrying the new {@link PubSubConfig} and the engine's {@link
 * ReconfigureResult}.
 *
 * <p>This is the hand-off seam between remote-configuration application and information-model
 * rebuild: the server supplies the applied configuration and the added/removed/restarted
 * accounting; the listener implements the incremental, name-path-keyed rebuild of the
 * config-derived information-model subtrees. Until a real implementation is wired, {@link #NO_OP}
 * is installed and reconfiguration does not rebuild the (read-only) information model — the
 * documented v1 limitation of {@code PubSubInfoModelFragment}.
 */
interface RemoteConfigurationListener {

  /** A listener that does nothing; the default until a rebuild is wired. */
  RemoteConfigurationListener NO_OP = (config, result) -> {};

  /**
   * Called (on the thread that ran {@code CloseAndUpdate}) after a successful reconfigure.
   *
   * @param config the applied configuration.
   * @param result the engine's added/removed/restarted accounting.
   */
  void onReconfigured(PubSubConfig config, ReconfigureResult result);
}
