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

import java.security.SecureRandom;

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
		algorithm = new SRA();
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
			char k = key.get(), m = plaintext.get();

			int cc = algorithm.encryptChar(m, k),
					kk = cc > 1 && cc <= MAX ? algorithm.invertKeyChar(k) : MAX + 1;
			if (kk <= MAX) {
				cipher.put((char)cc);
				key.put(i, (char)kk); // key becomes decryption key
			}
			else {	// either key or cipher is not representable.
				cipher.put(m);
				key.put(i, (char)1);
			}
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
				char k = key.get(), m = footer[c];

				int cc = algorithm.encryptChar(m, k),
						kk = cc > 1 && cc <= MAX ? algorithm.invertKeyChar(k) : MAX + 1;
				if (kk <= MAX) {
					cipher.put((char)cc);
					key.put(nC++, (char)kk); // key becomes decryption key
				}
				else {	// either key or cipher is not representable.
					cipher.put(m);
					key.put(nC++, (char)1);
				}
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
			char c = algorithm.decryptChar(cipher.get(--iC), key.get(--iK));
			msgBytes = c + (algorithm.decryptChar(cipher.get(--iC), key.get(--iK)) << 16);

			paddingBytes = algorithm.decryptChar(cipher.get(--iC), key.get(--iK));

			c = algorithm.decryptChar(cipher.get(--iC), key.get(--iK));
			chkSum = c + (algorithm.decryptChar(cipher.get(--iC), key.get(--iK)) << 16);

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
			decryptChars.put(iK, algorithm.decryptChar(cipher.get(--iC), key.get(iK)));
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

	static abstract class EncryptionAlgorithm {
		abstract void obtainOneTimePad(byte[] pad);
		abstract int encryptChar(char msgChar, char keyChar);
		abstract int invertKeyChar(char keyChar);
		abstract char decryptChar(char cipherChar, char keyChar);

		protected EncryptionAlgorithm(final byte[] randomSeed)
		{
			randomGen = randomSeed != null && randomSeed.length > 0 ? new SecureRandom(randomSeed) : new SecureRandom();
		}
		protected final SecureRandom randomGen;
	}

	/**
	Simple encryption by xor'ing the key and message words.<b/>
	O(1) per word
	*/
	static class XOR extends EncryptionAlgorithm {
		XOR()
		{
			super(null);
		}

		@Override
		public void obtainOneTimePad(byte[] pad)
		{
			randomGen.nextBytes(pad);
		}

		@Override
		public int encryptChar(char msgChar, char keyChar)
		{	// returns int because possibility of result overflowing
			return (char)(msgChar ^ keyChar);
		}

		@Override
		public int invertKeyChar(char keyChar)
		{
			return keyChar;
		}

		@Override
		public char decryptChar(char cipherChar, char keyChar)
		{	// returns char because no possibility of result overflowing
			return (char)(cipherChar ^ keyChar);
		}
	}

	/**
	See http://people.csail.mit.edu/~rivest/ShamirRivestAdleman-MentalPoker.pdf for details.<b/>
	Encryption involves log(16) = 4 multiplications per word, and computation of decryption key
	also involves 4 multiplications.
	*/
	static class SRA extends EncryptionAlgorithm {
		SRA()
		{
			super(null);
		}

		public static boolean testAlgorithm(char b, char e)
		{
			if ((e & 1) == 0)
				++e;

			int c = Arithmetic.powMod(b, e, MOD_char);

			int e2 = Arithmetic.powMod(e, totient_totient - 1, totient);

			int b2 = Arithmetic.powMod(c, e2, MOD_char);
			return b2 == b;
		}

		@Override
		public void obtainOneTimePad(byte[] pad)
		{
			assert pad.length % 2 == 0;

			randomGen.nextBytes(pad);

			CharBuffer cb = ByteBuffer.wrap(pad).asCharBuffer();
			for (int c = 0, nC = cb.length(); c < nC; ++c) {
				int k = cb.get(c);
				if ((k & 1) == 0)	// totient(n) is even for n >= 3 (Wolfram Alpha says)
					++k;
				while (nC < 0 && Arithmetic.gcd(totient, k) > 1) {
					/*
					Our totient is 2^n. Hence, it only has factors of the form 2^k.
					Therefore, GCD check is unnecessary - tweaking each key char to be odd is
					good enough.
					 */
					k += 2;
					if (k == totient - 1)
						break;
				}
				cb.put(c, (char)k);
			}
		}

		@Override
		public int encryptChar(char msgChar, char keyChar)
		{
			return Arithmetic.powMod(msgChar, keyChar, MOD_char);
		}

		@Override
		public int invertKeyChar(char keyChar)
		{
			return Arithmetic.powMod(keyChar, totient_totient - 1, totient);
		}

		@Override
		public char decryptChar(char cipherChar, char keyChar)
		{
			return (char)Arithmetic.powMod(cipherChar, keyChar, MOD_char);
		}

		/*
		* Be warned - these constants are not extensible to integers, since Fermat primes stop at 2^4.
		* Good thing about this scheme is that GCD check is not required, i.e GCD(key, totient) is
		* a given for all odd keys.
		 */
		protected static final int MOD_char = (1 << 16), // Fermat prime
									totient = MOD_char / 2,
									totient_totient = totient / 2;	// totient(p^x) = p^x(1 - 1/p) src: Wolfram Alpha

		static class Arithmetic {
			static int powMod(int b, int e, int m)
			{   // b^e | m
				// IMPORTANT: Java long is signed, so max value 2^63 - 1. Big enough to hold max int (2^31 - 1)^2
				// Note that temptation to create a specialization for chars, with base as int, is pointless since
				// int is signed in Java, and 2^31 - 1 is not big enough to hold (2^16 - 1)^2
				assert b >= 0 && e >= 0 && m > b;

				if (b <= 1)
					return b;

				int result = 1;
				if (e != 0) {
					for (long base = b; true; e >>>= 1) {
						if ((e & 1) == 1) {
							result = (int)((base * result) % m);
							if (e == 1)
								break;
						}
						base = (base * base) % m;
						//if (base == 0)	// check is sound, but maybe a rarely succeeding long comparison is overkill
						//	return 0;
					}
				}
				return result;
			}

			static boolean isPrime(int n)
			{
				if ((n & 1) == 0)   // even number
					return false;

				float xPrev = n, x = 0.5f * (n + 1);
				while (Math.abs(xPrev - n) >= 1.0f) {   // calculate floor(sqrt(x))
					xPrev = x;
					x = 0.5f * (x + x/n);
				}

				for (int i = 3, nS = (int)x; i <= nS; i += 2) { // nS is floor(sqrt(n))
					if (n % i == 0)
						return false;
				}
				return true;
			}

			static int gcd(int a, int b)
			{
				while (a != 0) {
					int x = a;
					a = b % x;
					b = x;
				}
				return b;
			}

			static int gcd_binary(int a, int b)
			{
				if (a == 0)
					return b;
				else if (b == 0)
					return a;

				// Make "a" and "b" odd, keeping track of common power of 2.
				final int aTwos = Integer.numberOfTrailingZeros(a);
				a >>= aTwos;
				final int bTwos = Integer.numberOfTrailingZeros(b);
				b >>= bTwos;
				final int shift = Math.min(aTwos, bTwos);

				// "a" and "b" are positive.
				// If a > b then "gdc(a, b)" is equal to "gcd(a - b, b)".
				// If a < b then "gcd(a, b)" is equal to "gcd(b - a, a)".
				// Hence, in the successive iterations:
				//  "a" becomes the absolute difference of the current values,
				//  "b" becomes the minimum of the current values.
				while (a != b) {
					if (a < b) {
						a = b - a;
						b -= a;
					}
					else
						a -= b;

					a >>= Integer.numberOfTrailingZeros(a);	// Remove any power of 2 in "a" ("b" is guaranteed to be odd).
				}
				return a << shift;	// Recover the common power of 2.
			}
		}
	}

}
