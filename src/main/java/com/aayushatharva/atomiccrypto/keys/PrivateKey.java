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
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Asymmetric Private Key
 *
 * @author Aayush Atharva
 */
public class PrivateKey {

    private java.security.PrivateKey privateKey;

    PrivateKey(java.security.PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Create A Private Key From DER Encoded Data
     *
     * @param Data DER Encoded Data
     * @throws AtomicCryptoException When The Private Key Cannot Be Loaded
     */
    public PrivateKey(byte[] Data) throws AtomicCryptoException {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "BC");
            this.privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Data));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new AtomicCryptoException(e);
        }
    }

    /**
     * Retrieve Underlying Private Key
     *
     * @return Private Key
     */
    public java.security.PrivateKey getKey() {
        return privateKey;
    }

    /**
     * Retrieve DER Encoded Form Of The Key
     *
     * @return DER Encoded Key Data
     */
    public byte[] getBytes() {
        return this.privateKey.getEncoded();
    }

}
