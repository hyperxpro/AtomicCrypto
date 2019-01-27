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
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Asymmetric Public Key
 * 
 * @author Aayush Atharva
 */
public class PublicKey {

    private java.security.PublicKey publicKey;

    PublicKey(java.security.PublicKey publicKey) {
        this.publicKey = publicKey;
    }

     /**
     * Create A Public Key From DER Encoded Data
     *
     * @param Data DER Encoded Data
     * @throws AtomicCryptoException When The Public Key Cannot Be Loaded
     */
    public PublicKey(byte[] Data) throws AtomicCryptoException {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "BC");
            this.publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Data));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
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
     * Retrieve DER Encoded Form Of The Key
     *
     * @return DER Encoded Key Data
     */
    public byte[] getBytes() {
        return this.publicKey.getEncoded();
    }

}
