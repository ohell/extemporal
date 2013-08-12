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
import java.nio.CharBuffer;
import java.util.Random;
import java.util.zip.CRC32;

/**
 * This class encrypts/decrypts the messages using a pseudo-random one time pad.
 * The cipher length is always the same as the message length (very short messages are padded, though). <br/>
 * <br/>
 * Messages are terminated with a footer consisting of the CRC32 checksum of the unencrypted message, padding length
 * (if any) and the length of the message. We do not generate key bytes for the padding.<br/>
 * <br/>
 * There are two algorithms available: XOR and SRA. New algorithms can be implemented by extending
 * {@link EncryptionAlgorithm}, but they need to to  meet the criteria that, for a given key c:<br/>
 * Gc(Fc(m)) = m, i.e. a decryption algorithm G should exist,<br/>
 * Fc(m) != Fc(n), i.e. F and G should be one to one,<br/>
 * and Fe(Fc(m)) = Fc(Fe(m)) i.e. process is symmetric w.r.t successive encryption.<br/>
 * <br/>
 * Note that XOR has a weakness that Fc(Fc(m) = m, i.e. Gc = Fc. This is an invitation to MITM attacks.<br/>
 * <br/>
 * SRA is essentially word-wise modular exponentiation, Fc(mi) = mi^ci mod N, mi and ci are the ith words of messages
 * and key. This would be susceptible to discrete logarithm problems, but the attacker never has the key in our message
 * exchange scheme. We use the word size as 2 bytes, N = 2^16 (i.e. Character.MAX + 1). This is mainly for reasons of
 * preserving sanity - 2 byte char is the only unsigned integral type in Java.
 */
public class Cryptologistics {
	public Cryptologistics()
	{
		algorithm = new EncryptionAlgorithm.ModularMultiplication();
	}

	static int calculateEncryptedByteLength(int msgByteLength, boolean isPlaintext)
	{
		return 2 * Math.max((msgByteLength + 1) / 2 + (isPlaintext ? nFooterChars : 0), minCipherChars);
	}

	static int calculateDecryptedByteLength(int cipherByteLength, boolean toPlaintext)
	{
		if (cipherByteLength < 2 * minCipherChars || cipherByteLength % 2 == 1)
			return -1;  // will cause an error somewhere downstream
		return toPlaintext ? cipherByteLength - 2 * nFooterChars : cipherByteLength;
	}

	public byte[] encrypt(ByteBuffer message, ByteBuffer cipherBuffer, boolean msgIsPlaintext)
	{
		final int MAX = Character.MAX_VALUE;
		final int len = message.remaining(), mStart = message.position();
		byte[] padding = {};
		int nC = (len + 1) / 2;	// +1 if odd bytes
		if (msgIsPlaintext) {
			nC += nFooterChars;
			if (nC < minCipherChars) {
				padding = new byte[2 * (minCipherChars - nC)];   // pad at the start
				if (fillGenerator == null)
					fillGenerator = new Random();
				fillGenerator.nextBytes(padding);
				nC = minCipherChars;
			}
		}
		else {
			assert nC >= minCipherChars;
		}
		ensure(cipherBuffer.remaining() >= 2 * nC, "Cipher buffer should have at least " + (2 * nC) + " bytes!");

		byte[] keyBuffer = new byte[2 * nC - padding.length];
		algorithm.obtainOneTimePad(keyBuffer);
		cipherBuffer.put(padding);

		final CharBuffer cipher = cipherBuffer.asCharBuffer(),
						plaintext = message.asCharBuffer(),
						key = ByteBuffer.wrap(keyBuffer).asCharBuffer();

		for (int i = key.position(); plaintext.hasRemaining(); ++i) {
			final int kc = algorithm.encryptChar(plaintext.get(), key.get(), msgIsPlaintext);
			cipher.put((char)kc);
			key.put(i, (char)(kc >>> 16));
		}

		final CRC32 c32 = new CRC32();
		int c = mStart;
		for (int cM = mStart + len; c < cM; ++c)
			c32.update(message.get(c));
		c = (int)c32.getValue();

		if (msgIsPlaintext) {	// write last odd byte, checksum, padding length, and message byte length.
			char[] footer = {0, (char)(c >>> 16), (char)(c & MAX), (char)padding.length, (char)(len >>> 16), (char)(len & MAX)};
			if ((len & 1) == 1) {	// include last byte in plaintext
				footer[0] = (char)((message.get(mStart + len - 1) & 0xFF) << 8);	// java is big-endian
				c = 0;
			}
			else
				c = 1;

			for (nC = key.position(); c < footer.length; ++c) {
				final int kc = algorithm.encryptChar(footer[c], key.get(), true);
				cipher.put((char)kc);
				key.put(nC++, (char)(kc >>> 16));
			}
		}
		else {
			assert len % 2 == 0;
		}

		return keyBuffer;
	}

	public void decrypt(ByteBuffer cipherMsg, byte[] keyBytes, ByteBuffer decryptBuffer, boolean recoveringPlaintext)
	{
		ensure(keyBytes.length % 2 == 0 && (!recoveringPlaintext || keyBytes.length >= 2 * nFooterChars), "The key is too short or has odd number of bytes!");

		int msgBytes = cipherMsg.remaining(), paddingBytes = 0, chkSum = 0;
		ensure(msgBytes >= keyBytes.length || (msgBytes > 2 * minCipherChars && msgBytes % 2 == 1), "The key is not valid for the specified message!");

		final int msgStart = decryptBuffer.position();
		final CharBuffer cipher = cipherMsg.asCharBuffer(), key = ByteBuffer.wrap(keyBytes).asCharBuffer();

		int iC = cipher.length(), iK = key.length();
		if (recoveringPlaintext) {	// read footer, verify after reading rest of message
			char c = algorithm.decryptChar(cipher.get(--iC), key.get(--iK), true);
			msgBytes = c + (algorithm.decryptChar(cipher.get(--iC), key.get(--iK), true) << 16);

			paddingBytes = algorithm.decryptChar(cipher.get(--iC), key.get(--iK), true);

			c = algorithm.decryptChar(cipher.get(--iC), key.get(--iK), true);
			chkSum = c + (algorithm.decryptChar(cipher.get(--iC), key.get(--iK), true) << 16);

			ensure(iK >= (msgBytes + 1) / 2, "The key length does not match the message length specified!");
		}
		else {
			ensure(iK <= (msgBytes + 1) / 2, "The key length does not match the message length specified!");

			if (iC > iK) {	//copy over previous padding chars
				for (int nP = iC - iK; paddingBytes < nP; ++paddingBytes)
					decryptBuffer.putChar(cipher.get(paddingBytes));
				paddingBytes *= 2;
			}
			msgBytes -= paddingBytes;
		}

		ensure(decryptBuffer.remaining() >= msgBytes, "Output buffer too small! Need at least " + keyBytes.length + " bytes.");

		CharBuffer decryptChars = decryptBuffer.asCharBuffer();
		while (--iK >= 0) {
			decryptChars.put(iK, algorithm.decryptChar(cipher.get(--iC), key.get(iK), recoveringPlaintext));
		}

		if (recoveringPlaintext) {
			ensure(iC == 0, "Inconsistent padding encountered!");

			CRC32 verify = new CRC32();
			for (int v = msgStart + paddingBytes, vN = v + msgBytes; v < vN; ++v)
				verify.update(decryptBuffer.get(v));
			ensure(chkSum == (int)verify.getValue(), "Checksum does not match!");

			if (paddingBytes > 0) {
				decryptBuffer.position(msgStart + paddingBytes);
				decryptBuffer.limit(msgStart + paddingBytes + msgBytes);
				ByteBuffer msgPortion = decryptBuffer.slice();
				decryptBuffer.position(msgStart);
				decryptBuffer.put(msgPortion);
				paddingBytes = 0;
			}
		}
		decryptBuffer.position(msgStart);   // constrain output buffer & position so it's ready for reading
		decryptBuffer.limit(msgStart + msgBytes + paddingBytes);
	}

	static final int minCipherChars = 32;
	static final int nFooterChars = 2 + 1 + 2;	// 2 for checksum (4 bytes), 1 for padding (2 bytes), 2 for byte length (4 bytes)

	private Random fillGenerator;
	private final EncryptionAlgorithm algorithm;

	private void ensure(boolean condition, String msg)
	{
		if (!condition)
			throw new IllegalArgumentException(msg);
	}
}
