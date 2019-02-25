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
package com.aayushatharva.atomiccrypto.cryptography;

import com.aayushatharva.atomiccrypto.exception.AtomicCryptoException;
import com.aayushatharva.atomiccrypto.keys.PrivateKey;
import com.aayushatharva.atomiccrypto.keys.PublicKey;
import com.aayushatharva.atomiccrypto.keys.SecretKey;

import javax.crypto.KeyAgreement;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import org.bouncycastle.jcajce.provider.digest.SHA3;

/**
 * Hub for Asymmetric Cryptography
 *
 * @author Aayush Atharva
 */
public class AsymmetricHub {

    // Keys
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private SymmetricHub symmetricHub;

    /**
     * Create a new box with the given keys
     *
     * @param privateKey the private key
     * @param publicKey the public key
     */
    public AsymmetricHub(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Encrypt The Given Data With SecureRandom Chosen By System
     *
     * @param Data Data To Encrypt
     * @return Encrypted Data
     * @throws AtomicCryptoException When An Error Occurs During Encryption
     */
    public byte[] encrypt(byte[] Data) throws Exception {
        try {
            symmetricHub = this.getSecret();
            return symmetricHub.encrypt(Data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AtomicCryptoException(e);
        }
    }

    /**
     * Encrypt The Given Data With Defined SecureRandom
     *
     * @param Data Data To Encrypt
     * @param secureRandom SecureRandom To Use For Encryption
     * @return Encrypted Data
     * @throws AtomicCryptoException When An Error Occurs During Encryption
     */
    public byte[] encrypt(byte[] Data, SecureRandom secureRandom) throws Exception {
        try {
            symmetricHub = this.getSecret();
            return symmetricHub.encrypt(Data, secureRandom);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AtomicCryptoException(e);
        }
    }

    /**
     * Decrypt The Given Cipher Data
     *
     * @param Data Data To Decrypt
     * @return Decrypted Data
     * @throws AtomicCryptoException When An Error Occurs During Encryption
     */
    public byte[] decrypt(byte[] Data) throws Exception {
        try {
            return this.getSecret().decrypt(Data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AtomicCryptoException(e);
        }
    }

    /**
     * Get Cipher Text As Base64 Encoding
     *
     * @return Base64 Encoded Cipher Data
     */
    public byte[] getCipherDataAsBase64() {
        return symmetricHub.getCipherDataAsBase64();
    }

    private SymmetricHub getSecret() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
        keyAgreement.init(this.privateKey.getKey());
        keyAgreement.doPhase(this.publicKey.getKey(), true);
        byte[] secret = keyAgreement.generateSecret();

        SHA3.DigestSHA3 digestSHA3_256 = new SHA3.Digest256();
        byte[] key = digestSHA3_256.digest(secret);
        return new SymmetricHub(new SecretKey(key));
    }

}
