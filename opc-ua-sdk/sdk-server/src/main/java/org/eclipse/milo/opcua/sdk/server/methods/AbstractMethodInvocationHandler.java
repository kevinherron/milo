/*
 * Copyright (c) 2025 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.server.methods;

import static java.util.Objects.requireNonNullElse;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import org.eclipse.milo.opcua.sdk.core.typetree.DataType;
import org.eclipse.milo.opcua.sdk.core.typetree.DataTypeTree;
import org.eclipse.milo.opcua.sdk.server.AccessContext;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.Session;
import org.eclipse.milo.opcua.sdk.server.nodes.UaMethodNode;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.encoding.DataTypeCodec;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingContext;
import org.eclipse.milo.opcua.stack.core.types.DataTypeManager;
import org.eclipse.milo.opcua.stack.core.types.UaStructuredType;
import org.eclipse.milo.opcua.stack.core.types.builtin.DiagnosticInfo;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExtensionObject;
import org.eclipse.milo.opcua.stack.core.types.builtin.Matrix;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.structured.Argument;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult;

/**
 * A partial implementation of {@link MethodInvocationHandler} that handles checking the Executable
 * and UserExecutable attributes as well as validating the supplied input values against the input
 * {@link Argument}s.
 */
public abstract class AbstractMethodInvocationHandler implements MethodInvocationHandler {

  private final UaMethodNode node;

  /**
   * @param node the {@link UaMethodNode} this handler will be installed on.
   */
  public AbstractMethodInvocationHandler(UaMethodNode node) {
    this.node = node;
  }

  public UaMethodNode getNode() {
    return node;
  }

  @Override
  public final CallMethodResult invoke(AccessContext accessContext, CallMethodRequest request) {
    try {
      Variant[] inputArgumentValues =
          requireNonNullElse(request.getInputArguments(), new Variant[0]);

      if (inputArgumentValues.length < getInputArguments().length) {
        throw new UaException(StatusCodes.Bad_ArgumentsMissing);
      }
      if (inputArgumentValues.length > getInputArguments().length) {
        throw new UaException(StatusCodes.Bad_TooManyArguments);
      }

      StatusCode[] inputDataTypeCheckResults = new StatusCode[inputArgumentValues.length];

      for (int i = 0; i < inputArgumentValues.length; i++) {
        Argument argument = getInputArguments()[i];

        Variant variant = inputArgumentValues[i];
        Object value = variant.value();

        boolean dataTypeMatch = true;

        if (value != null) {
          NodeId argDataTypeId = argument.getDataType();

          NodeId valueDataTypeId =
              variant
                  .getDataTypeId()
                  .flatMap(xni -> xni.toNodeId(node.getNodeContext().getNamespaceTable()))
                  .orElse(NodeId.NULL_VALUE);

          DataTypeTree dataTypeTree = node.getNodeContext().getServer().getDataTypeTree();

          // Whether the argument's DataType is a structure. isStructType() alone misses the
          // abstract Structure root because a type is not its own subtype, so test for it
          // explicitly. This also matters because the Structure DataType's NodeId (i=22) collides
          // with the builtin ExtensionObject id that a raw wire value reports for its own
          // DataType, which defeats the plain argDataTypeId-vs-valueDataTypeId comparison.
          boolean argIsStruct =
              NodeIds.Structure.equals(argDataTypeId) || dataTypeTree.isStructType(argDataTypeId);

          if (argIsStruct
              && (value instanceof ExtensionObject || value instanceof ExtensionObject[])) {
            EncodingContext encodingContext =
                node.getNodeContext().getServer().getStaticEncodingContext();

            DataType argType = dataTypeTree.getType(argDataTypeId);
            boolean isAbstract = argType != null && argType.isAbstract();

            // A struct-typed argument arrives on the wire as a scalar ExtensionObject or, for an
            // array-valued argument (e.g. a method taking a Structure[]), an ExtensionObject[].
            // The generated method skeleton casts the value to its concrete Java type, so decode
            // the wire ExtensionObject(s) and replace the value with the decoded structure(s). This
            // must run even when argDataTypeId equals valueDataTypeId: an abstract Structure
            // argument shares the ExtensionObject NodeId that raw wire values report, so the ids
            // coincide yet the value still needs decoding. The value-rank check below independently
            // enforces the scalar-vs-array shape.
            if (value instanceof ExtensionObject xo) {
              UaStructuredType decoded = xo.decode(encodingContext);

              if (decoded == null) {
                // A null-bodied scalar ExtensionObject carries no concrete structure for a
                // struct-typed argument; treat it as a type mismatch rather than dereferencing.
                dataTypeMatch = false;
              } else {
                valueDataTypeId =
                    decoded
                        .getTypeId()
                        .toNodeId(node.getNodeContext().getNamespaceTable())
                        .orElse(NodeId.NULL_VALUE);

                dataTypeMatch =
                    isAbstract
                        ? dataTypeTree.isSubtypeOf(valueDataTypeId, argDataTypeId)
                        : Objects.equals(valueDataTypeId, argDataTypeId);

                if (dataTypeMatch) {
                  inputArgumentValues[i] = new Variant(decoded);
                }
              }
            } else if (value instanceof ExtensionObject[] array) {
              // Decode and type-check EVERY element rather than only a representative: a
              // heterogeneous array — mixed concrete subtypes under an abstract argument, or a
              // stray mismatched element under a concrete argument — must be validated
              // element-by-element, or a bad element would slip past validation and later fail
              // the skeleton's array store as an unhandled ArrayStoreException.
              UaStructuredType[] decodedElements = new UaStructuredType[array.length];
              boolean allElementsMatch = true;

              for (int j = 0; j < array.length && allElementsMatch; j++) {
                ExtensionObject element = array[j];
                if (element == null || element.isNull()) {
                  // A null element carries no concrete type; it decodes to a null slot.
                  continue;
                }

                UaStructuredType decoded = element.decode(encodingContext);
                decodedElements[j] = decoded;

                NodeId elementDataTypeId =
                    decoded
                        .getTypeId()
                        .toNodeId(node.getNodeContext().getNamespaceTable())
                        .orElse(NodeId.NULL_VALUE);

                allElementsMatch =
                    isAbstract
                        ? dataTypeTree.isSubtypeOf(elementDataTypeId, argDataTypeId)
                        : Objects.equals(elementDataTypeId, argDataTypeId);
              }

              dataTypeMatch = allElementsMatch;

              if (dataTypeMatch) {
                // Allocate the decoded array with the argument's concrete Java component type so
                // the skeleton's cast to ConcreteType[] succeeds — including for an empty or
                // all-null array, which carries no element to infer the type from.
                Class<?> componentType =
                    structArrayComponentType(
                        encodingContext.getDataTypeManager(), argDataTypeId, decodedElements);

                Object decodedArray = Array.newInstance(componentType, array.length);
                for (int j = 0; j < array.length; j++) {
                  if (decodedElements[j] != null) {
                    Array.set(decodedArray, j, decodedElements[j]);
                  }
                }
                inputArgumentValues[i] = new Variant(decodedArray);
              }
            }
          } else if (!argDataTypeId.equals(valueDataTypeId)) {
            // Either a non-struct argument (checked against its backing class) or a struct-typed
            // argument given a value that is neither an ExtensionObject nor an ExtensionObject[],
            // which cannot be the expected structure.
            dataTypeMatch =
                !argIsStruct && dataTypeTree.isAssignable(argDataTypeId, value.getClass());
          }
        }

        int valueRank = argument.getValueRank();

        if (valueRank == -1) {
          // scalar
          if (value != null && (value.getClass().isArray() || value instanceof Matrix)) {
            dataTypeMatch = false;
          }
        } else if (valueRank == 1) {
          // one dimension
          if (value != null && !value.getClass().isArray()) {
            dataTypeMatch = false;
          }
        } else if (valueRank == 0) {
          // one or more dimension
          if (value != null && !(value.getClass().isArray() || value instanceof Matrix)) {
            dataTypeMatch = false;
          }
        } else if (valueRank > 1) {
          // matrix (2+ dimensions)
          if (value != null && !(value instanceof Matrix)) {
            dataTypeMatch = false;
          }
        }

        if (dataTypeMatch) {
          inputDataTypeCheckResults[i] = StatusCode.GOOD;
        } else {
          inputDataTypeCheckResults[i] = new StatusCode(StatusCodes.Bad_TypeMismatch);
        }
      }

      if (Arrays.stream(inputDataTypeCheckResults).anyMatch(StatusCode::isBad)) {
        throw new InvalidArgumentException(inputDataTypeCheckResults);
      }

      validateInputArgumentValues(inputArgumentValues);

      InvocationContext invocationContext =
          new InvocationContext() {
            @Override
            public OpcUaServer getServer() {
              return node.getNodeContext().getServer();
            }

            @Override
            public NodeId getObjectId() {
              return request.getObjectId();
            }

            @Override
            public UaMethodNode getMethodNode() {
              return node;
            }

            @Override
            public Optional<Session> getSession() {
              return accessContext.getSession();
            }
          };

      Variant[] outputValues = invoke(invocationContext, inputArgumentValues);

      return new CallMethodResult(
          StatusCode.GOOD, new StatusCode[0], new DiagnosticInfo[0], outputValues);
    } catch (InvalidArgumentException e) {
      return new CallMethodResult(
          e.getStatusCode(),
          e.getInputArgumentResults(),
          e.getInputArgumentDiagnosticInfos(),
          new Variant[0]);
    } catch (UaException e) {
      return new CallMethodResult(
          e.getStatusCode(), new StatusCode[0], new DiagnosticInfo[0], new Variant[0]);
    }
  }

  /**
   * Determine the Java component type to use for a decoded structure array so the generated method
   * skeleton's cast to its concrete argument type (e.g. {@code (FooDataType[])}) succeeds.
   *
   * <p>A concrete structure DataType has a registered {@link DataTypeCodec} whose {@link
   * DataTypeCodec#getType() type} names the class exactly; this also covers empty or all-null
   * arrays, which carry no element to infer the type from. An abstract structure DataType has no
   * codec, so fall back to the nearest common superclass of the decoded elements — for the OPC UA
   * single-inheritance structure hierarchy this resolves to the abstract type's own Java class,
   * which the skeleton casts to — or to {@link UaStructuredType} when there are no elements.
   *
   * @param dataTypeManager the {@link DataTypeManager} to resolve the argument's codec from.
   * @param argDataTypeId the {@link NodeId} of the argument's structure DataType.
   * @param decodedElements the decoded array elements (may contain nulls for null wire elements).
   * @return the component type to allocate the decoded array with.
   */
  private static Class<?> structArrayComponentType(
      DataTypeManager dataTypeManager, NodeId argDataTypeId, UaStructuredType[] decodedElements) {
    DataTypeCodec codec = dataTypeManager.getCodec(argDataTypeId);
    if (codec != null) {
      return codec.getType();
    }

    Class<?> componentType = null;
    for (UaStructuredType element : decodedElements) {
      if (element == null) {
        continue;
      }
      componentType =
          componentType == null
              ? element.getClass()
              : nearestCommonSuperclass(componentType, element.getClass());
    }

    return componentType != null ? componentType : UaStructuredType.class;
  }

  /**
   * Find the nearest common superclass of {@code a} and {@code b} by walking {@code a}'s superclass
   * chain until it is assignable from {@code b}.
   *
   * @param a a class.
   * @param b a class.
   * @return the nearest common superclass, or {@link Object} if none is found.
   */
  private static Class<?> nearestCommonSuperclass(Class<?> a, Class<?> b) {
    Class<?> candidate = a;
    while (candidate != null && !candidate.isAssignableFrom(b)) {
      candidate = candidate.getSuperclass();
    }
    return candidate != null ? candidate : Object.class;
  }

  /**
   * Get the input {@link Argument}s expected by the Method this handler is installed on.
   *
   * @return the input {@link Argument}s expected by the Method this handler is installed on.
   */
  public abstract Argument[] getInputArguments();

  /**
   * Get the output {@link Argument}s expected by the Method this handler is installed on.
   *
   * @return the output {@link Argument}s expected by the Method this handler is installed on.
   */
  public abstract Argument[] getOutputArguments();

  /**
   * Invoke this method and return the values for its output arguments, if any.
   *
   * <p>The Executable and UserExecutable attributes have already been checked to ensure this method
   * is allowed to execute.
   *
   * @param invocationContext the {@link InvocationContext}.
   * @param inputValues the user-supplied values for the input arguments. Each value has been
   *     verified to be of the type specified by its {@link Argument}.
   * @return this output values matching this Method's output arguments, if any.
   * @throws UaException if invocation has failed for some reason.
   */
  protected abstract Variant[] invoke(InvocationContext invocationContext, Variant[] inputValues)
      throws UaException;

  /**
   * Validate the input values against the expected input arguments.
   *
   * <p>The DataType of each input value has already been verified; implementations need only verify
   * the value is "valid", if applicable, and throw InvalidArgumentException with a StatusCode of
   * Bad_OutOfRange for any invalid input values.
   *
   * @param inputArgumentValues the input values provided by the client for the current method call.
   * @throws InvalidArgumentException if one or more input argument values are invalid.
   */
  protected void validateInputArgumentValues(Variant[] inputArgumentValues)
      throws InvalidArgumentException {}

  /**
   * Extends {@link AccessContext} to provide additional context to implementations of {@link
   * AbstractMethodInvocationHandler}.
   */
  public interface InvocationContext extends AccessContext {

    /**
     * Get the {@link OpcUaServer} instance.
     *
     * @return the {@link OpcUaServer} instance.
     */
    OpcUaServer getServer();

    /**
     * Get the {@link NodeId} of the ObjectNode the method being invoked belongs to.
     *
     * @return the {@link NodeId} of the ObjectNode the method being invoked belongs to.
     */
    NodeId getObjectId();

    /**
     * Get the {@link UaMethodNode} being invoked.
     *
     * @return the {@link UaMethodNode} being invoked.
     */
    UaMethodNode getMethodNode();
  }
}
