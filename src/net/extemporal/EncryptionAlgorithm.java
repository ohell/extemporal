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
import java.security.SecureRandom;

/**
 * Algorithms to encrypt the messages using a generated key, and also to convert the encryption key
 * into the form needed to decrypt the encrypted messages.<br/>
 *
 * Requirements on an encryption function F using key k to encrypt message m are:
 * <ol>
 * <li>if c = Fk(m), there should exist a function G s.t. m = Gk(c) [i.e. it is possible to decrypt an encrypted message]</li>
 * <li>Gk(Fj(Fk(m))) = Fj(m). This is implied if Fj(Fk(m)) = Fk(Fj(m)) [it should be possible to partially decryt a double encrypted message, in any order]</li>
 * <li>Fk(m) != Fk(n) [i.e. Fk one to one]</li>
 * <li>There should not exist any function Q s.t Q(m, F, Fk(m)) = k [prevent key discovery]</li>
 * </ol>
 *
 * There are 3 implementations given here that satisfy the first 2 conditions. XOR, included just for
 * test purposes, violates the 3rd and the 4th, and hence is not a good encryption function.<br/>
 *
 * ModularExponentiation satisfies all 4, but the 4th condition is practically violated by algorithms that
 * solve the discrete logarithm (e.g. Pohlig Hellman). Hence, this is also not really recommended.<br/>
 *
 * ModularMultiplication satisfies all 4, in the form presented here. We ensure that the modular multiplicative
 * inverse of the cipher does not exist, preserving the last condition.
 */
abstract class EncryptionAlgorithm {
	/**
	 * Generates a symmetric key suitable for symmetric encryption by this algorithm. Uses secure PRNG.
	 *
	 * @param pad generated key is copied here
	 */
	abstract void obtainOneTimePad(byte[] pad);

	/**
	 *
	 * @param msgChar character to encrypt
	 * @param keyChar corresponding key character
	 * @param preProcess true if this is the first encryption (msgChar might be non-transitively transformed for better security)
	 * @return a int, to be interpreted at [k', m'] where k' (high 16 bits) is the decryption key, m' (low 16 bits) is the cipher character.
	 */
	abstract int encryptChar(char msgChar, char keyChar, boolean preProcess);

	/**
	 *
	 * @param cipherChar cipher char generated previously by the encryptChar() function
	 * @param keyChar key char generated previously by the encryptChar() function
	 * @param postProcess true if this is the last decryption (msgChar might have been non-transitively transformed for better security)
	 * @return recovers the original message char passed to encryptChar() previously
	 */
	abstract char decryptChar(char cipherChar, char keyChar, boolean postProcess);

	protected EncryptionAlgorithm(final byte[] randomSeed)
	{
		randomGen = randomSeed != null && randomSeed.length > 0 ? new SecureRandom(randomSeed) : new SecureRandom();
	}
	protected final SecureRandom randomGen;

	/**
	 Encryption by modular multiplication of the key and message words.Before encrypting, we make
	 message words even, so that GCD(m, N) > 1, in order to ensure that modular multiplicative
	 inverse of the cipher will not exist, in case an eavesdropper tries to recover the key.<b/>
	 O(1) per word, while computation of decryption key also involves 4 multiplications.
	 */
	static class ModularMultiplication extends ModularExponentiation {
		@Override
		public int encryptChar(char msgChar, char keyChar, boolean preProcess)
		{
			if (msgChar == 0)
				return (keyChar << 1) & (MOD_char - 1);	// a likely looking random number, with decryption key = 0

			int ec = msgChar;
			if (preProcess) {
				ec <<= 1;	// make message char even
				if ((ec & MOD_char) == MOD_char)	// uh-uh! Overflow. use LSB to keep record of MSB
					ec = (ec | 1) & MOD_char_1;	// this implies that cipher chars >= 2^15 can be inverted, leaking some info.
			}
			ec = (int)((ec * (long)keyChar) % MOD_char);

			return (Arithmetic.powMod(keyChar, totient_1, MOD_char) << 16) | ec;	// [decryption key char, cipherChar]
		}

		@Override
		public char decryptChar(char cipherChar, char keyChar, boolean postProcess)
		{
			int c = (int)((cipherChar * (long)keyChar) % MOD_char);
			if (postProcess) {
				if ((c & 1) == 1)	// i.e. msg char had overflown during encryption
					c |= MOD_char;
				c >>>= 1;
			}
			return (char)c;
		}

		protected static final int totient_1 = totient - 1, MOD_char_1 = MOD_char - 1;
	}

	/**
	 See http://people.csail.mit.edu/~rivest/ShamirRivestAdleman-MentalPoker.pdf for details.<b/>
	 Encryption involves log(16) = 4 multiplications per word, and computation of decryption key
	 also involves 4 multiplications.
	 */
	static class ModularExponentiation extends EncryptionAlgorithm {
		ModularExponentiation()
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
				final int k = cb.get(c);
				/*
							while (nC < 0 && SRA.Arithmetic.gcd(totient, k) > 1) {
								k += 2;
								if (k == totient - 1)
									break;
							}
				*
				*
				Our totient is 2^n. Hence, it only has factors of the form 2^k.
				Therefore, GCD check is unnecessary - tweaking each key char to be odd is
				good enough.
				*/
				cb.put(c, (char)((k & 1) == 1 ? k : k + 1));
			}
		}

		@Override
		public int encryptChar(char msgChar, char keyChar, boolean preProcess)
		{
			int c = Arithmetic.powMod(msgChar, keyChar, MOD_char),
				k = c > 0 ? Arithmetic.powMod(keyChar, totient_totient - 1, totient) : 0;	// decryption key char
			return k > 0 ? ((k << 16) | c) : ((1 << 16) | msgChar);	// k == 0 implies message char not representable
		}

		@Override
		public char decryptChar(char cipherChar, char keyChar, boolean postProcess)
		{
			return (char)Arithmetic.powMod(cipherChar, keyChar, MOD_char);
		}

		/*
		* Be warned - these constants are not extensible to integers, since Fermat primes stop at 2^4.
		* Good thing about this scheme is that GCD check is not required, i.e GCD(key, totient) is
		* a given for all odd keys.
		 */
		protected static final int MOD_char = (1 << 16), // 2^16
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
		public int encryptChar(char msgChar, char keyChar, boolean preProcess)
		{	// returns int because possibility of result overflowing
			return (msgChar ^ keyChar) | (keyChar << 16);
		}

		@Override
		public char decryptChar(char cipherChar, char keyChar, boolean postProcess)
		{	// returns char because no possibility of result overflowing
			return (char)(cipherChar ^ keyChar);
		}
	}
}
