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

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Hashtable;
import java.util.Vector;

import javax.jms.Topic;
import javax.jms.TopicConnectionFactory;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.spi.InitialContextFactory;

import junit.framework.TestCase;

/**
 * Tests that {@link JMSSink} only performs JNDI lookups in the
 * <code>java:</code> namespace (CVE-2022-23302).
 */
public class JMSSinkTest extends TestCase {

  private static final String TCF_NAME = "java:comp/env/jms/TopicConnectionFactory";
  private static final String TOPIC_NAME = "java:comp/env/jms/Topic";

  /** Names looked up in the stub naming context. */
  static final Vector lookups = new Vector();

  /** Message listeners registered on stub topic subscribers. */
  static final Vector listeners = new Vector();

  private String previousFactory;
  private AttackerServer attacker;

  public JMSSinkTest(final String testName) {
    super(testName);
  }

  protected void setUp() throws Exception {
    lookups.clear();
    listeners.clear();
    previousFactory = System.getProperty(Context.INITIAL_CONTEXT_FACTORY);
    System.setProperty(Context.INITIAL_CONTEXT_FACTORY,
                       StubContextFactory.class.getName());
    attacker = new AttackerServer();
    attacker.start();
  }

  protected void tearDown() throws Exception {
    attacker.shutdown();
    if (previousFactory == null) {
      System.getProperties().remove(Context.INITIAL_CONTEXT_FACTORY);
    } else {
      System.setProperty(Context.INITIAL_CONTEXT_FACTORY, previousFactory);
    }
    lookups.clear();
    listeners.clear();
  }

  /**
   * A TopicConnectionFactoryBindingName pointing at an attacker controlled
   * LDAP server must not be looked up.
   */
  public void testLdapTopicConnectionFactoryBindingNameIsNotLookedUp()
      throws Exception {
    new JMSSink(attacker.getUrl("ldap"), TOPIC_NAME, "user", "password");

    assertFalse("JMSSink contacted the LDAP server", attacker.wasContacted());
    assertTrue(lookups.isEmpty());
    assertTrue(listeners.isEmpty());
  }

  /**
   * A TopicBindingName pointing at an attacker controlled LDAP server must
   * not be looked up.
   */
  public void testLdapTopicBindingNameIsNotLookedUp() throws Exception {
    new JMSSink(TCF_NAME, attacker.getUrl("ldap"), "user", "password");

    assertFalse("JMSSink contacted the LDAP server", attacker.wasContacted());
    assertEquals(1, lookups.size());
    assertEquals(TCF_NAME, lookups.get(0));
    assertTrue(listeners.isEmpty());
  }

  /**
   * An RMI TopicConnectionFactoryBindingName must not be looked up.
   */
  public void testRmiTopicConnectionFactoryBindingNameIsNotLookedUp()
      throws Exception {
    new JMSSink(attacker.getUrl("rmi"), TOPIC_NAME, "user", "password");

    assertFalse("JMSSink contacted the RMI registry", attacker.wasContacted());
    assertTrue(lookups.isEmpty());
    assertTrue(listeners.isEmpty());
  }

  /**
   * Names outside of the java: namespace are rejected by the lookup helper
   * before reaching the naming context.
   */
  public void testLookupRejectsNonJavaNamespace() throws Exception {
    Context ctx = (Context) newStub(new Class[] {Context.class});
    String[] names = new String[] {
        attacker.getUrl("ldap"), attacker.getUrl("rmi"),
        "dns://" + attacker.getHost() + "/Exploit",
        " " + TCF_NAME, "JAVA:comp/env/jms/Topic"
    };
    for (int i = 0; i < names.length; i++) {
      try {
        JMSSink.lookup(ctx, names[i]);
        fail("Lookup of [" + names[i] + "] should have been refused");
      } catch (NamingException e) {
        assertTrue(e.getMessage().startsWith(JNDIUtil.RESTRICTION_MSG));
      }
    }
    assertTrue(lookups.isEmpty());
    assertFalse(attacker.wasContacted());
  }

  /**
   * Lookups in the java: namespace keep working.
   */
  public void testJavaNamespaceBindingNamesAreLookedUp() throws Exception {
    JMSSink sink = new JMSSink(TCF_NAME, TOPIC_NAME, "user", "password");

    assertEquals(2, lookups.size());
    assertEquals(TCF_NAME, lookups.get(0));
    assertEquals(TOPIC_NAME, lookups.get(1));
    assertEquals(1, listeners.size());
    assertSame(sink, listeners.get(0));

    Context ctx = (Context) newStub(new Class[] {Context.class});
    assertNotNull(JMSSink.lookup(ctx, TOPIC_NAME));
    assertEquals(3, lookups.size());
    assertFalse(attacker.wasContacted());
  }

  static Object newStub(final Class[] interfaces) {
    return Proxy.newProxyInstance(JMSSinkTest.class.getClassLoader(),
                                  interfaces, new StubHandler());
  }

  /**
   * Answers every interface method: lookups return a stub implementing both
   * TopicConnectionFactory and Topic, interface return types get a stub of
   * that interface, everything else returns null.
   */
  static final class StubHandler implements InvocationHandler {
    public Object invoke(final Object proxy, final Method method,
                         final Object[] args) {
      String name = method.getName();
      if (method.getDeclaringClass() == Object.class) {
        if ("equals".equals(name)) {
          return (proxy == args[0]) ? Boolean.TRUE : Boolean.FALSE;
        }
        if ("hashCode".equals(name)) {
          return new Integer(System.identityHashCode(proxy));
        }
        return "stub";
      }
      if ("lookup".equals(name)) {
        lookups.addElement(String.valueOf(args[0]));
        return newStub(new Class[] {TopicConnectionFactory.class, Topic.class});
      }
      if ("setMessageListener".equals(name)) {
        listeners.addElement(args[0]);
        return null;
      }
      Class returnType = method.getReturnType();
      if (returnType.isInterface()) {
        return newStub(new Class[] {returnType});
      }
      return null;
    }
  }

  /**
   * Initial context factory used through the
   * <code>java.naming.factory.initial</code> system property.
   */
  public static final class StubContextFactory implements InitialContextFactory {
    public Context getInitialContext(final Hashtable environment) {
      return (Context) newStub(new Class[] {Context.class});
    }
  }

  /**
   * Local server standing in for an attacker controlled LDAP/RMI service,
   * it records whether a client connected to it.
   */
  static final class AttackerServer extends Thread {
    private final ServerSocket serverSocket;
    private boolean contacted;

    AttackerServer() throws IOException {
      serverSocket = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
      setDaemon(true);
    }

    String getHost() {
      return "127.0.0.1:" + serverSocket.getLocalPort();
    }

    String getUrl(final String scheme) {
      return scheme + "://" + getHost() + "/Exploit";
    }

    public void run() {
      while (true) {
        try {
          Socket socket = serverSocket.accept();
          synchronized (this) {
            contacted = true;
          }
          socket.close();
        } catch (IOException e) {
          return;
        }
      }
    }

    synchronized boolean wasContacted() {
      return contacted;
    }

    void shutdown() throws Exception {
      try {
        serverSocket.close();
      } catch (IOException e) {
      }
      join(5000);
    }
  }
}
