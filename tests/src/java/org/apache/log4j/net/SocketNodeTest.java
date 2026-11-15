/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.log4j.net;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Vector;

import junit.framework.TestCase;

import org.apache.log4j.Hierarchy;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.log4j.NDC;
import org.apache.log4j.VectorAppender;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.RootLogger;

/**
 * Sends serialized objects to a {@link SocketNode} over a real socket and
 * checks that only logging events are deserialized (CVE-2019-17571).
 */
public class SocketNodeTest extends TestCase {

  private static final String MDC_KEY = "socketNodeTestKey";

  public SocketNodeTest(final String testName) {
    super(testName);
  }

  protected void setUp() {
    Gadget.deserializationCount = 0;
    MDC.remove(MDC_KEY);
    NDC.remove();
  }

  protected void tearDown() {
    MDC.remove(MDC_KEY);
    NDC.remove();
  }

  /**
   * Legitimate events, including NDC, MDC, location and throwable
   * information, must still reach the appenders.
   */
  public void testLoggingEventsAreProcessed() throws Exception {
    NDC.push("ndc-value");
    MDC.put(MDC_KEY, "mdc-value");
    LoggingEvent first = createEvent("first", new Exception("testing"));
    first.getLocationInformation();
    MDC.remove(MDC_KEY);
    NDC.remove();
    LoggingEvent second = createEvent("second", null);

    Vector received = sendToSocketNode(new Object[] { first, second });

    assertEquals(2, received.size());
    LoggingEvent event = (LoggingEvent) received.elementAt(0);
    assertEquals("first", event.getRenderedMessage());
    assertEquals("ndc-value", event.getNDC());
    assertEquals("mdc-value", event.getMDC(MDC_KEY));
    assertEquals("java.lang.Exception: testing", event.getThrowableStrRep()[0]);
    assertEquals(first.getLocationInformation().getMethodName(),
        event.getLocationInformation().getMethodName());
    assertEquals("second", ((LoggingEvent) received.elementAt(1)).getRenderedMessage());
  }

  /**
   * A gadget sent in place of a logging event must never be deserialized.
   */
  public void testGadgetInsteadOfLoggingEventIsNotDeserialized() throws Exception {
    Vector received = sendToSocketNode(new Object[] {
        createEvent("before", null), new Gadget("payload"), createEvent("after", null) });

    assertEquals("gadget was deserialized", 0, Gadget.deserializationCount);
    assertEquals(1, received.size());
    assertEquals("before", ((LoggingEvent) received.elementAt(0)).getRenderedMessage());
  }

  /**
   * A gadget nested in the MDC of a well-formed logging event must never be
   * deserialized and the event must not be logged.
   */
  public void testGadgetInMDCIsNotDeserialized() throws Exception {
    LoggingEvent legit = createEvent("legit", null);
    MDC.put(MDC_KEY, new Gadget("payload"));
    LoggingEvent malicious = createEvent("malicious", null);
    byte[] bytes = serialize(new Object[] { legit, malicious });
    MDC.remove(MDC_KEY);

    Vector received = sendToSocketNode(bytes);

    assertEquals("gadget was deserialized", 0, Gadget.deserializationCount);
    assertEquals(1, received.size());
    assertEquals("legit", ((LoggingEvent) received.elementAt(0)).getRenderedMessage());
  }

  /**
   * A gadget wrapped in authorized java.lang / java.util containers must
   * never be deserialized.
   */
  public void testGadgetInsideContainersIsNotDeserialized() throws Exception {
    Vector container = new Vector();
    container.addElement(new Object[] { "a", new Gadget("payload") });
    MDC.put(MDC_KEY, container);
    LoggingEvent malicious = createEvent("malicious", null);
    byte[] bytes = serialize(new Object[] { malicious });
    MDC.remove(MDC_KEY);

    Vector received = sendToSocketNode(bytes);

    assertEquals("gadget was deserialized", 0, Gadget.deserializationCount);
    assertEquals(0, received.size());
  }

  /**
   * Creates an event and snapshots the current NDC and MDC into it.
   */
  private static LoggingEvent createEvent(final String message, final Throwable t) {
    Logger logger = Logger.getLogger(SocketNodeTest.class);
    LoggingEvent event = new LoggingEvent(Logger.class.getName(), logger, Level.INFO, message, t);
    event.getThreadName();
    event.getNDC();
    event.getMDCCopy();
    return event;
  }

  private static byte[] serialize(final Object[] objects) throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(bytes);
    for (int i = 0; i < objects.length; i++) {
      oos.writeObject(objects[i]);
    }
    oos.close();
    return bytes.toByteArray();
  }

  private static Vector sendToSocketNode(final Object[] objects) throws Exception {
    return sendToSocketNode(serialize(objects));
  }

  /**
   * Writes the given stream to a socket, then lets a SocketNode read it
   * until the stream ends or the node closes the connection.
   */
  private static Vector sendToSocketNode(final byte[] bytes) throws Exception {
    InetAddress localhost = InetAddress.getByName("127.0.0.1");
    ServerSocket serverSocket = new ServerSocket(0, 1, localhost);
    Socket client = null;
    try {
      client = new Socket(localhost, serverSocket.getLocalPort());
      OutputStream out = client.getOutputStream();
      out.write(bytes);
      out.flush();
      client.shutdownOutput();

      Socket accepted = serverSocket.accept();
      accepted.setSoTimeout(10000);

      Hierarchy hierarchy = new Hierarchy(new RootLogger(Level.DEBUG));
      VectorAppender appender = new VectorAppender();
      hierarchy.getRootLogger().addAppender(appender);

      SocketNode node = new SocketNode(accepted, hierarchy);
      node.run();
      // SocketNode re-asserts the interrupt flag on InterruptedIOException.
      Thread.interrupted();
      return appender.getVector();
    } finally {
      if (client != null) {
        try {
          client.close();
        } catch (IOException e) {
        }
      }
      serverSocket.close();
    }
  }

  /**
   * Stands in for a deserialization gadget: records whenever it is
   * deserialized.
   */
  public static class Gadget implements Serializable {
    private static final long serialVersionUID = 1L;

    static int deserializationCount = 0;

    private final String command;

    public Gadget(final String command) {
      this.command = command;
    }

    public String toString() {
      return "Gadget[" + command + "]";
    }

    private void readObject(final ObjectInputStream in) throws IOException, ClassNotFoundException {
      in.defaultReadObject();
      deserializationCount++;
    }
  }
}
