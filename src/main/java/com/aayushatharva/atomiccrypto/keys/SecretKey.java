/* 
 * Copyright (C) 2018 Aayush Atharva
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.aayushatharva.atomiccrypto.keys;

import com.aayushatharva.atomiccrypto.exception.AtomicCryptoException;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Secret Key For Cryptography
 *
 * @author Aayush Atharva
 */
public class SecretKey {

    private byte[] key;

    /**
     * Create a secret key from 32 byte (256 bit) key material
     *
     * @param key a secret key
     */
    public SecretKey(byte[] key) {
        assert key.length == 32;
        this.key = key.clone();
    }

    /**
     * Generate a new 32 byte (256 bit) Secret Key With SecureRandom Selected By
     * Operating System
     *
     * @return a secret key
     * @throws AtomicCryptoException when SecureRandom fails to initialize
     */
    public static SecretKey generate() throws AtomicCryptoException {
        byte[] key = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        return new SecretKey(key);
    }

    /**
     * Generate a new 32 byte (256 bit) Secret Key With Defined SecureRandom
     * Algorithm
     *
     * @param secureRandom SecureRandom
     * @return a secret key
     * @throws AtomicCryptoException when SecureRandom fails to initialize
     */
    public static SecretKey generate(SecureRandom secureRandom) throws AtomicCryptoException {
        byte[] key = new byte[32];
        SecureRandom random = secureRandom;
        random.nextBytes(key);
        return new SecretKey(key);
    }

    /**
     * Retrieve the raw key material
     *
     * @return the 32 byte (256 bit) key material
     */
    public byte[] getBytes() {
        return key.clone();
    }

    /**
     * Get Secret Key In Base64 Encoding
     *
     * @return Base64 Encoded Secret Key As String
     */
    public String getKeyAsBase64() {
        return Base64.getEncoder().encodeToString(getBytes());
    }

    @Override
    public boolean equals(Object o) {

        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        SecretKey that = (SecretKey) o;

        return Arrays.equals(key, that.key);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(key);
    }
}
