/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub;

import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState;

/**
 * A state change of a PubSub component, delivered to {@link PubSubStateListener}s.
 *
 * @param component the handle of the component that changed state.
 * @param oldState the state the component transitioned from.
 * @param newState the state the component transitioned to.
 * @param statusCode a status code describing the reason for the transition.
 * @param cause the trigger category of the transition (see {@link Cause}).
 */
public record PubSubStateChangeEvent(
    PubSubHandle component,
    PubSubState oldState,
    PubSubState newState,
    StatusCode statusCode,
    Cause cause) {

  /**
   * The trigger category of a {@link PubSubStateChangeEvent}, distinguishing the Part 14 §9.1.11
   * {@code State*} counter conditions that the state and status code alone cannot.
   *
   * <p>It disambiguates the two ways a component reaches {@code Disabled} — an explicit disable
   * ({@link #METHOD}) versus subtree teardown on reconfigure-removal or shutdown ({@link #DISPOSE},
   * which is <b>not</b> counted as {@code StateDisabledByMethod}) — and lets the engine remember,
   * across the deferred startup of a DataSetReader, whether a component entered {@code
   * PreOperational} by an explicit enable or by a parent recovering, so the eventual {@code
   * Operational} transition (reported with {@link #STARTUP}) is attributed to {@code
   * StateOperationalByMethod} or {@code StateOperationalByParent} accordingly.
   */
  public enum Cause {

    /**
     * Triggered by an explicit enable/disable of this component (an Enable/Disable Method call).
     */
    METHOD,

    /**
     * Triggered by a change in the state of this component's parent (a state recompute cascade).
     */
    PARENT,

    /**
     * An error-driven transition: this component failing into {@code Error} (a pending error, an
     * activation failure, or a transport disconnect), or recovering from {@code Error} back to
     * {@code Operational}.
     */
    ERROR_RECOVERY,

    /**
     * A {@code PreOperational} component completing its startup and reaching {@code Operational}.
     */
    STARTUP,

    /**
     * Subtree teardown ahead of removal from the runtime tree (reconfigure-removal or service
     * shutdown). A {@code Disabled} transition with this cause is not counted as {@code
     * StateDisabledByMethod}.
     */
    DISPOSE
  }
}
