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

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Asymmetric Public Key
 * 
 * @author Aayush Atharva
 * @timestamp Oct 22, 2018 10:44:12 PM
 */
public class PublicKey {

    private java.security.PublicKey publicKey;

    PublicKey(java.security.PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Create a public key from DER encoded data
     *
     * @param data the DER encoded data
     * @throws AtomicCryptoException when the private key cannot be loaded
     */
    public PublicKey(byte[] data) throws AtomicCryptoException {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("ECDH");
            this.publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(data));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new AtomicCryptoException(e);
        }
    }

    /**
     * Retrieve underlying public key
     *
     * @return the public key
     */
    public java.security.PublicKey getKey() {
        return publicKey;
    }

    /**
     * Retrieve DER encoded form of the key
     *
     * @return the DER encoded data
     */
    public byte[] getBytes() {
        return this.publicKey.getEncoded();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        PublicKey that = (PublicKey) o;

        return this.publicKey.equals(that.publicKey);
    }

    @Override
    public int hashCode() {
        return publicKey.hashCode();
    }
}
