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
package net.extemporal;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * The main class that implements the secure message exchange scheme. Uses the {@link Platform} object
 * to execute storage/retrieval/transmission operations. The exchange is as follows: <br/>
 * <br/>
 * Alice calls sendMessage("Bob", msgData) to send a message to Bob. msgData is encrypted using the
 * {@link Cryptologistics} class, and sent to Bob. <br/>
 * Bob receives a message, and calls his {@link Engine}.processReceivedEnvelope("Alice", cipherData). This encrypts the
 * cipher with Bob's key and sends it back to Alice (acknowledgement). <br/>
 * Alice calls her {@link Engine}.processReceivedEnvelope("Bob", ackData). This authenticates the sender, decrypts the
 * received ackData, and sends to Bob (confirmation). <br/>
 * Bob receives the confirmation, and calls his {@link Engine}.processReceivedEnvelope("Alice", confData). <br/>
 * This authenticates the sender, decrypts the cipher with Bob's key and passes the resulting plaintext to its Platform.
 * <br/> <br/>
 * The randomly generated keys never leave Alice and Bob's respective possession, so an eavesdropper hasn't got anything
 * to crack. Man-in-the-middle attack is a possibility, but only if the the attacker is able to impersonate
 * Alice and Bob, and first completes the exchange with Bob and then exchanges the decrypted message with Alice. <br/>
 * <br/>
 * We guard against this by verifying a shared secret at both ends, to authenticate the parties. The insight is that
 * the attacker has to complete the exchanges with Alice and Bob in sequence. So, we securely hash the shared secret
 * with the times at which the message and its reply were generated. This is now secure, because attacker can't generate
 * the secure hash without the secret, and can't use a previously observed hash because all the transmitted hashes are
 * salted with message times, and we check that the times are in the expected order. <br/>
 */
public class Engine {
	public Engine(Platform platform)
	{
		if (platform == null)
			throw new IllegalArgumentException("Engine needs a platform to stand on!");

		mPlatform = platform;
		mCryptologistics = new Cryptologistics();
	}

	/**
	 *
	 * @param platformContext some platform-specific value that will be propagated to all further Platform calls
	 *                           until this message is sent.
	 * @param destination message recipient. This value is also used to query the platform for shared secrets.
	 * @param message message content, plaintext.
	 * @return whether the message was encrypted and transmitted OK.
	 *
	 * Call this method to start a the exchange for a new secure message.
	 */
	public boolean sendMessage(Object platformContext, String destination, ByteBuffer message)
	{   // sends synchronously
		try {
			ByteBuffer encrypted = envelopeMessage(destination, platformContext, message, 0, null);
			if (mPlatform.transmitBytes(platformContext, destination, encrypted))
				return true;
		}
		catch (IllegalStateException e) {
			mPlatform.processException(e);
		}
		return false;
	}

	/**
	 *
	 * @param platformContext some platform-specific value that will be propagated to all further Platform calls,
	 *                           until this message is handled. Platform has a chance to modify it if required.
	 * @param destination message sender. This value is also used to query the platform for shared secrets.
	 * @param message message data, encrypted by the sender
	 * @return the result of processing the message.
	 *
	 * Call this method whenever a new message is received. The message content is inspected for the our header to
	 * detect if this is of interest to us. If not, {@link ProcessingResult}.Ignored is returned. Else appropriate
	 * processing is carried out as per the scheme describe above.
	 *
	 * If this message is a confirmation, it is finally decrypted and passed to the Platform via handleReceivedMessage()
	 */
	public ProcessingResult processReceivedEnvelope(Object platformContext, String destination, ByteBuffer message)
	{   // processes messages asynchronously
		int mStart = message.position();
		byte flag = 0;
		boolean verifiable = false;
		if (message.remaining() >= envelopeHeaderLengthBytes + 2 * Cryptologistics.minCipherChars) {
			for (byte h : envelopeHeader) {
				if (message.get() != h) {
					message.position(mStart);
					return ProcessingResult.Ignored;
				}
			}
			final byte msgV = message.get();
			if (msgV > (version | 1)) {
				message.position(mStart);
				return ProcessingResult.Ignored;
			}
			verifiable = (msgV & 1) == 1;
			message.get();  // ignore platform id
			flag = message.get();
		}

		boolean ok;
		switch(flag) {
		case flagMsg:
			ok = acknowledgeMessage(destination, platformContext, message, verifiable);
			break;
		case flagAck:
			ok = confirmAcknowledgement(destination, platformContext, message, verifiable);
			break;
		case flagCnf:
			ok = decryptConfirmation(destination, platformContext, message, verifiable);
			break;
		default:
			return ProcessingResult.Ignored;
		}
		return ok ? ProcessingResult.Processed : ProcessingResult.Failed;
	}

	private boolean acknowledgeMessage(final String destination, Object platformContext, final ByteBuffer message, boolean verifiable)
	{
		final int theirRef = message.getInt();
		final Platform.MutablePlatformContext wrapper = new Platform.MutablePlatformContext(platformContext);
		if (!mPlatform.openReceivedEnvelope(destination, flagMsg, wrapper, verifiable, null, theirRef))
			return false;

		final int sentTime = verifiable ? verifyTransmittedSecret(destination, platformContext, message, 0) : 0;
		if (sentTime < 0)	// failed authentication
			return false;

		if (message.remaining() < Cryptologistics.minCipherChars || message.remaining() % 2 == 1)
			return false;

		mPlatform.executeAsynchronously(new Runnable() {
			@Override
			public void run()
			{
				try {
					ByteBuffer envelope = envelopeMessage(destination, wrapper.platformContext, message, sentTime, theirRef);
					mPlatform.transmitBytes(wrapper.platformContext, destination, envelope);
				}
				catch (Exception e) {
					mPlatform.processException(e);
				}
			}
		});
		return true;
	}

	private boolean confirmAcknowledgement(final String destination, Object platformContext, final ByteBuffer message, final boolean verifiable)
	{
		final int ourRef = message.getInt(), theirRef = message.getInt();
		final Platform.TemporalKey key = mPlatform.retrieveKey(platformContext, ourRef, destination);
		if (key == null)
			throw new IllegalArgumentException("Unable to find a stored key for " + ourRef);

		final Platform.MutablePlatformContext wrapper = new Platform.MutablePlatformContext(platformContext);
		if (!mPlatform.openReceivedEnvelope(destination, flagAck, wrapper, verifiable, ourRef, theirRef))
			return false;

		final int sentTime = verifiable ? verifyTransmittedSecret(destination, platformContext, message, key.createdTime) : 0;
		if (sentTime < 0)	// failed authentication
			return false;

		if (message.remaining() < Cryptologistics.minCipherChars || message.remaining() % 2 == 1)
			return false;

		mPlatform.executeAsynchronously(new Runnable() {
			@Override
			public void run()
			{
				try {
					ByteBuffer verification = null;
					if (verifiable) {
						final int now = (int)(System.currentTimeMillis() / 1000);	// verified that number of seconds in 50 years = 0x5E0C89C0 < Integer.MAX_VALUE
						verification = generateTransmissionSecret(destination, wrapper.platformContext, now, sentTime);
						if (verification == null)
							throw new IllegalStateException("Unable to retrieve a shared secret for " + destination);
					}
					int hdrLen = verifiable ? envelopeVerifiedHeaderLengthBytes : envelopeHeaderLengthBytes;
					ByteBuffer cipher = ByteBuffer.allocate(Cryptologistics.calculateDecryptedByteLength(message.remaining(), false) + hdrLen);
					cipher.put(envelopeHeader);
					cipher.put(verifiable ? (version | 1) : version);
					cipher.put(mPlatform.getTypeIdentifier());
					cipher.put(flagCnf);
					cipher.putInt(theirRef);
					if (verifiable)
						cipher.put(verification);
					mCryptologistics.decrypt(message, key.bytes, cipher, false);
					cipher.rewind();
					if (mPlatform.transmitBytes(wrapper.platformContext, destination, cipher))
						mPlatform.destroyKey(wrapper.platformContext, ourRef, destination);  // won't need it again
				}
				catch (Exception e) {
					mPlatform.processException(e);
				}
			}
		});
		return true;
	}

	private boolean decryptConfirmation(final String from, Object platformContext, final ByteBuffer cipher, boolean verifiable)
	{
		final int ourRef = cipher.getInt();
		final Platform.MutablePlatformContext wrapper = new Platform.MutablePlatformContext(platformContext);
		if (!mPlatform.openReceivedEnvelope(from, flagCnf, wrapper, verifiable, ourRef, null))
			return false;

		final Platform.TemporalKey key = mPlatform.retrieveKey(platformContext, ourRef, from);
		if (key == null)
			throw new IllegalArgumentException("Unable to find a stored key for " + ourRef);

		final int sentTime = verifiable ? verifyTransmittedSecret(from, platformContext, cipher, key.createdTime) : 0;
		if (sentTime < 0)	// failed authentication
			return false;

		if (cipher.remaining() < Cryptologistics.minCipherChars || cipher.remaining() % 2 == 1)
			return false;

		mPlatform.executeAsynchronously(new Runnable() {
			@Override
			public void run()
			{
				try {
					ByteBuffer plain = ByteBuffer.allocate(Cryptologistics.calculateDecryptedByteLength(cipher.remaining(), true));
					mCryptologistics.decrypt(cipher, key.bytes, plain, true);
					mPlatform.destroyKey(wrapper.platformContext, ourRef, from);  // won't need it again
					mPlatform.handleReceivedMessage(wrapper.platformContext, from, plain);
				}
				catch (Exception e) {
					mPlatform.processException(e);
				}
			}
		});
		return true;
	}

	protected ByteBuffer envelopeMessage(String destination, Object platformContext, ByteBuffer message, int receivedTime, Integer ackRef)
	{
		final int now = (int)(System.currentTimeMillis() / 1000);	// verified that number of seconds in 50 years = 0x5E0C89C0 < Integer.MAX_VALUE
		ByteBuffer verification = generateTransmissionSecret(destination, platformContext, now, receivedTime);
		final boolean isAck = ackRef != null, isVerifiable = verification != null;
		int hdrLen = isVerifiable ? envelopeVerifiedHeaderLengthBytes : envelopeHeaderLengthBytes;
		if (isAck)
			hdrLen += 4;	// 4 bytes for their ref that we need to include in the header

		ByteBuffer encrypted = ByteBuffer.allocate(Cryptologistics.calculateEncryptedByteLength(message.remaining(), !isAck) + hdrLen);

		encrypted.position(hdrLen);
		byte[] key = mCryptologistics.encrypt(message, encrypted, !isAck);
		if (key == null)
			throw new IllegalStateException("Unable to encrypt the message! Please check the state of message buffer");

		final int reference = mPlatform.temporarilyStoreKey(platformContext, new Platform.TemporalKey(key, now), destination);
		encrypted.position(0);
		encrypted.put(envelopeHeader);
		encrypted.put(isVerifiable ? (version | 1) : version);
		encrypted.put(mPlatform.getTypeIdentifier());
		if (ackRef != null) {
			encrypted.put(flagAck);
			encrypted.putInt(ackRef);
		}
		else
			encrypted.put(flagMsg);
		encrypted.putInt(reference);
		if (isVerifiable)
			encrypted.put(verification);
		encrypted.rewind();
		return encrypted;
	}

	protected ByteBuffer generateTransmissionSecret(String endpoint, Object platformContext, int timeNow, int theirTime)
	{
		byte[] sharedSecret = mPlatform.retrieveSharedSecret(endpoint, platformContext);
		if (sharedSecret == null)
			return null;

		try {
			ByteBuffer annoying = ByteBuffer.allocate(Math.max(sharedSecret.length + 4, hashBytes) + 4);
			annoying.putInt(timeNow);
			annoying.putInt(theirTime);
			annoying.put(sharedSecret);
			annoying.flip();
			MessageDigest hashFunc = MessageDigest.getInstance(hashAlgorithm);	// every platform must support MD5, SHA-1 & SHA-256
			hashFunc.update(annoying);
			annoying.clear();
			byte[] b = hashFunc.digest();
			annoying.putInt(timeNow);
			annoying.put(b);
			annoying.flip();
			return annoying;
		}
		catch(NoSuchAlgorithmException nsa) {	// can't happen;
			return null;
		}
	}

	protected int verifyTransmittedSecret(String endpoint, Object platformContext, ByteBuffer secretData, int keyTime)
	{
		byte[] sharedSecret = mPlatform.retrieveSharedSecret(endpoint, platformContext);
		if (sharedSecret == null)
			return -1;	// we do not have shared secret for this endpoint, but they do. Ignore message

		int theirTime = secretData.getInt();
		if (keyTime > theirTime)
			return -2;	// they replied to message before we created it?

		if (secretData.remaining() < hashBytes)
			return -3;

		try {
			MessageDigest hashFunc = MessageDigest.getInstance(hashAlgorithm);	// every platform must support MD5, SHA-1 & SHA-256
			ByteBuffer annoying = ByteBuffer.allocate(Math.max(sharedSecret.length + 4 + 4, hashBytes));
			annoying.putInt(theirTime);
			annoying.putInt(keyTime);
			annoying.put(sharedSecret);
			annoying.flip();
			hashFunc.update(annoying);
			byte[] secretBytes = annoying.capacity() == hashBytes ? annoying.array() : new byte[hashBytes];
			secretData.get(secretBytes);
			if (MessageDigest.isEqual(secretBytes, hashFunc.digest()))
				return theirTime;
		}
		catch(NoSuchAlgorithmException nsa) {
			// can't happen;
		}
		return -4;
	}

	final Platform mPlatform;
	final Cryptologistics mCryptologistics;
	public static final byte envelopeHeader[] = { 'X', 'T', 'M', 'P', 'O' },
						version = 2,	// convention: versions are always even, and LSB indicates whether this is a verified header
						flagMsg = -1,
						flagAck = -11,
						flagCnf = -111;
	public static final int envelopeHeaderLengthBytes = envelopeHeader.length + 1 + 1 + 1 + 4;

	/*
		Number of bytes in the verification field, i.e. hash of secret and time.
		We use SHA-1 because it is only 20 bytes bytes long, against 256 for SHA_256.
		Concerns about the 'crack' discovered in SHA-1 are not relevant to this use case - the message sender
		computes the hash, so collision and 2nd pre-image weakness are not really a concern.
		Even simple 32 bit hashes, e.g. Murmur Hash might suffice, but I don't know enough about theory yet to
		make that decision.
	 */
	static final int hashBytes = 160 / 8;
	static final String hashAlgorithm = "SHA-1";

	/*
		Verified header:= Normal header | sending time | Hash of (shared secret, sending time - receiving time)
		where | signifies append.
	 */
	public static final int envelopeVerifiedHeaderLengthBytes = envelopeHeaderLengthBytes + 4 + hashBytes;

	public static enum ProcessingResult { Ignored, Processed, Failed }
}
