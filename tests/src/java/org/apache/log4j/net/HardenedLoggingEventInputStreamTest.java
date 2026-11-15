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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;

import junit.framework.TestCase;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.log4j.NDC;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.xml.XLevel;

/**
 * Tests that {@link HardenedLoggingEventInputStream} and
 * {@link HardenedObjectInputStream} only deserialize whitelisted classes
 * (CVE-2019-17571).
 */
public class HardenedLoggingEventInputStreamTest extends TestCase {

  private static final String MDC_KEY = "hardenedTestKey";

  public HardenedLoggingEventInputStreamTest(final String testName) {
    super(testName);
  }

  protected void setUp() {
    Harmless.deserializationCount = 0;
    MDC.remove(MDC_KEY);
    NDC.remove();
  }

  protected void tearDown() {
    MDC.remove(MDC_KEY);
    NDC.remove();
  }

  /**
   * A legitimate logging event carrying NDC, MDC, location and throwable
   * information must still be deserialized.
   */
  public void testLoggingEventIsAccepted() throws Exception {
    Logger logger = Logger.getLogger(HardenedLoggingEventInputStreamTest.class);
    NDC.push("ndc-value");
    MDC.put(MDC_KEY, "mdc-value");
    LoggingEvent event = new LoggingEvent(Logger.class.getName(), logger,
        Level.WARN, "hello", new Exception("testing"));
    event.getLocationInformation();

    LoggingEvent read = (LoggingEvent) readHardened(serialize(event));

    assertEquals(logger.getName(), read.getLoggerName());
    assertEquals(Level.WARN, read.getLevel());
    assertEquals("hello", read.getRenderedMessage());
    assertEquals("ndc-value", read.getNDC());
    assertEquals("mdc-value", read.getMDC(MDC_KEY));
    assertEquals(event.getTimeStamp(), read.getTimeStamp());
    String[] rep = read.getThrowableStrRep();
    assertNotNull(rep);
    assertEquals("java.lang.Exception: testing", rep[0]);
    assertEquals(event.getLocationInformation().getClassName(),
        read.getLocationInformation().getClassName());
    assertEquals(event.getLocationInformation().getLineNumber(),
        read.getLocationInformation().getLineNumber());
  }

  /**
   * Custom levels are transmitted by class name and must keep working.
   */
  public void testCustomLevelEventIsAccepted() throws Exception {
    Logger logger = Logger.getLogger(HardenedLoggingEventInputStreamTest.class);
    LoggingEvent event = new LoggingEvent(Logger.class.getName(), logger,
        XLevel.TRACE, "trace message", null);

    LoggingEvent read = (LoggingEvent) readHardened(serialize(event));

    assertEquals(XLevel.TRACE, read.getLevel());
    assertEquals("trace message", read.getRenderedMessage());
  }

  /**
   * Classes from java.lang and java.util, and arrays of java.lang classes,
   * are always authorized.
   */
  public void testJavaLangAndJavaUtilAreAccepted() throws Exception {
    Hashtable table = new Hashtable();
    table.put("int", new Integer(1));
    table.put("strings", new String[] { "a", "b" });

    Hashtable read = (Hashtable) readHardened(serialize(table));

    assertEquals(new Integer(1), read.get("int"));
    String[] strings = (String[]) read.get("strings");
    assertEquals(2, strings.length);
    assertEquals("b", strings[1]);
  }

  /**
   * An arbitrary serializable object sent in place of a logging event must
   * be rejected before its readObject method runs.
   */
  public void testBadPayloadIsRejected() throws Exception {
    assertRejected(serialize(new BadPayload("x")), BadPayload.class.getName());
  }

  /**
   * A gadget smuggled inside the MDC of a well-formed logging event must be
   * rejected before its readObject method runs.
   */
  public void testBadPayloadInMDCIsRejected() throws Exception {
    Logger logger = Logger.getLogger(HardenedLoggingEventInputStreamTest.class);
    MDC.put(MDC_KEY, new BadPayload("aValue"));
    LoggingEvent event = new LoggingEvent(Logger.class.getName(), logger,
        Level.INFO, "hello", null);
    event.getMDCCopy();
    byte[] bytes = serialize(event);
    MDC.remove(MDC_KEY);

    assertRejected(bytes, BadPayload.class.getName());
  }

  /**
   * URLDNS style payload: a java.util.HashMap keyed by a java.net.URL. The
   * map itself is authorized but the URL must be rejected.
   */
  public void testUrlInsideHashMapIsRejected() throws Exception {
    HashMap map = new HashMap();
    map.put(new URL("http://127.0.0.1/"), "value");

    assertRejected(serialize(map), URL.class.getName());
  }

  /**
   * Arrays of non authorized classes must be rejected.
   */
  public void testArrayOfUnauthorizedClassIsRejected() throws Exception {
    Harmless[] array = new Harmless[] { new Harmless() };

    assertRejected(serialize(array), Harmless[].class.getName());
    assertEquals(0, Harmless.deserializationCount);
  }

  /**
   * Unauthorized classes hidden inside an authorized array must be rejected.
   */
  public void testUnauthorizedClassInsideObjectArrayIsRejected() throws Exception {
    Object[] array = new Object[] { "a", new Harmless() };

    assertRejected(serialize(array), Harmless.class.getName());
    assertEquals(0, Harmless.deserializationCount);
  }

  /**
   * Callers may explicitly authorize additional classes.
   */
  public void testAdditionalAuthorizedClasses() throws Exception {
    List additional = new ArrayList();
    additional.add(Harmless.class.getName());
    ObjectInputStream ois = new HardenedLoggingEventInputStream(
        new ByteArrayInputStream(serialize(new Harmless())), additional);
    try {
      Object read = ois.readObject();
      assertTrue(read instanceof Harmless);
      assertEquals(1, Harmless.deserializationCount);
    } finally {
      ois.close();
    }
  }

  /**
   * The String[] based constructor only authorizes the listed classes.
   */
  public void testHardenedObjectInputStreamStringArrayWhitelist() throws Exception {
    byte[] bytes = serialize(new Harmless());

    ObjectInputStream ois = new HardenedObjectInputStream(
        new ByteArrayInputStream(bytes), new String[] { Harmless.class.getName() });
    try {
      assertTrue(ois.readObject() instanceof Harmless);
    } finally {
      ois.close();
    }

    ois = new HardenedObjectInputStream(new ByteArrayInputStream(bytes), (String[]) null);
    try {
      ois.readObject();
      fail("Expected InvalidClassException");
    } catch (InvalidClassException e) {
      assertRejectedClass(e, Harmless.class.getName());
    } finally {
      ois.close();
    }
  }

  private static byte[] serialize(final Object o) throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(bytes);
    oos.writeObject(o);
    oos.close();
    return bytes.toByteArray();
  }

  private static Object readHardened(final byte[] bytes) throws Exception {
    ObjectInputStream ois = new HardenedLoggingEventInputStream(new ByteArrayInputStream(bytes));
    try {
      return ois.readObject();
    } finally {
      ois.close();
    }
  }

  private static void assertRejected(final byte[] bytes, final String className) throws Exception {
    try {
      Object o = readHardened(bytes);
      fail("Expected InvalidClassException, deserialized " + o);
    } catch (InvalidClassException e) {
      assertRejectedClass(e, className);
    } catch (IllegalStateException e) {
      fail("Unauthorized class was deserialized: " + e.getMessage());
    }
  }

  private static void assertRejectedClass(final InvalidClassException e, final String className) {
    String message = e.getMessage();
    assertTrue(message, message.indexOf("Unauthorized deserialization attempt") >= 0);
    assertTrue(message, message.endsWith("; " + className));
  }

  /**
   * A serializable class that is not authorized by default.
   */
  public static class Harmless implements Serializable {
    private static final long serialVersionUID = 1L;

    static int deserializationCount = 0;

    private void readObject(final ObjectInputStream in) throws IOException, ClassNotFoundException {
      in.defaultReadObject();
      deserializationCount++;
    }
  }
}
