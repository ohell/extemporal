/*
	Copyright Amit Jain 2013

	This file is part of extemporal encryption scheme implementation.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package net.extemporal.test;

import net.extemporal.Engine;
import net.extemporal.Platform;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.util.Hashtable;

/**
 * A simple synchronous implementation of {@link Platform}. Key are stored in a shared hash table, shared secrets
 * are generated simply by applying a symmetric operation on endpoints, messages are 'sent' by calling a function
 * on the the instance of this class corresponding to the endpoint. <br/>
 */
public class SimpleTestPlatform implements Platform {
	SimpleTestPlatform(String myEndpoint)
	{
		mEndpoint = myEndpoint.trim();
		if (sDestinations.get(mEndpoint) != null)
			throw new IllegalStateException("Multiple platforms with the same endpoint: " + myEndpoint);

		mMessagingEngine = new Engine(this);
		sDestinations.put(mEndpoint, this);
	}

	void shutdown()
	{
		sDestinations.remove(mEndpoint);
	}

	boolean sendMessage(String to, String message)
	{
		try {
			ByteBuffer buff = ByteBuffer.wrap(message.getBytes());
			if (mMessagingEngine.sendMessage(0, to, buff))
				return true;
		}
		catch (Exception e) {
			processException(e);
		}
		return false;
	}

	@Override
	public byte[] retrieveSharedSecret(String endpoint, Object platformContext)
	{
		if (endpoint == null)
			return null;

		int hash = mEndpoint.hashCode() + endpoint.hashCode();	// just something simple for testing
		ByteBuffer b = ByteBuffer.allocate(4);
		b.putInt(hash);
		return b.array();
	}

	@Override
	public int temporarilyStoreKey(Object platformContext, TemporalKey key, String endpoint)
	{
		int ref = (int)key.createdTime;	// lowest 4 bytes
		mTable.put(String.valueOf(ref) + '~' + endpoint, key);
		return ref;
	}

	@Override
	public TemporalKey retrieveKey(Object platformContext, int reference, String endpoint)
	{
		return mTable.get(String.valueOf(reference) + '~' + endpoint);
	}

	@Override
	public boolean destroyKey(Object platformContext, int reference, String endpoint)
	{
		return mTable.remove(String.valueOf(reference) + '~' + endpoint) != null;
	}

	@Override
	public boolean openReceivedEnvelope(String from, int commType, MutablePlatformContext wrapper, boolean verifiable, Integer ourRefIfAny, Integer theirRefIfAny)
	{
		/*
		just to illustrate the point of 'verifiable'. In practice, a scheme could be used where only
		the first message in a 'session' is verified (retrieveSharedSecret() would have to be modified accordingly)
		 */
		final boolean haveSharedSecretWithSender = retrieveSharedSecret(from, null) != null;
		if (verifiable != haveSharedSecretWithSender)
			return false;	//

		return (commType == Engine.flagMsg && theirRefIfAny != null) ||
				mTable.containsKey(ourRefIfAny.toString() + '~' + from);
	}

	@Override
	public boolean transmitBytes(Object platformContext, String endpoint, ByteBuffer messageBytes)
	{
		SimpleTestPlatform other = sDestinations.get(endpoint);
		if (other == null || other == this)
			throw new IllegalArgumentException("Can't send message to null or myself!");

		try {
			byte[] b = new byte[messageBytes.remaining()];
			messageBytes.get(b);
			String s = new String(b, sEncryptedEncoding);
			return other.receiveMessage(mEndpoint, s);
		}
		catch (Exception e) {
			processException(e);
		}
		return false;
	}

	@Override
	public boolean handleReceivedMessage(Object platformContext, String endpoint, ByteBuffer messageBytes)
	{
		PrintStream writ = System.out;
		writ.print(mEndpoint);
		writ.print(": new message from ");
		writ.print(endpoint);
		writ.print(":: ");
		try {
			byte[] b = new byte[messageBytes.remaining()];
			messageBytes.get(b);
			String s = new String(b);
			writ.println(s);
			return true;
		}
		catch (Exception e) {
			writ.print("<%$#@~~~~~~~~~~~~~>\n");
			processException(e);
		}
		writ.flush();
		return false;
	}

	@Override
	public void executeAsynchronously(Runnable function)
	{
		function.run();
	}

	@Override
	public byte getTypeIdentifier()
	{
		return 'T';
	}

	@Override
	public void processException(Exception e)
	{
		System.out.printf("Exception occurred! %s\n", e.toString());
		e.printStackTrace();
	}

	protected boolean receiveMessage(String from, String message)
	{
		try {
			ByteBuffer buff = ByteBuffer.wrap(message.getBytes(sEncryptedEncoding));
			switch(mMessagingEngine.processReceivedEnvelope(0, from, buff)) {
				case Processed:
					return true;
				case Ignored:
					return handleReceivedMessage(0, from, buff);
				case Failed:
					System.err.println("Can't process message from " + from + "! Decryption/Authentication failed.");
			}
		}
		catch (Exception e) {
			processException(e);
		}
		return false;
	}

	final String mEndpoint;
	protected final Engine mMessagingEngine;
	private final Hashtable<String, TemporalKey> mTable  = new Hashtable<String, TemporalKey>();

	private static final Hashtable<String, SimpleTestPlatform> sDestinations = new Hashtable<String, SimpleTestPlatform>();
	private static final String sEncryptedEncoding = "ISO-8859-1"; // loss-less fixed width encoding
}
