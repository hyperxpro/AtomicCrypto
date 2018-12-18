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
import java.security.SecureRandom;
import org.bouncycastle.jcajce.provider.digest.SHA3;

/**
 * Hub for Asymmetric Cryptography
 *
 * @author Aayush Atharva
 */
public class AsymmetricHub {

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
     * Encrypt the given plaintext
     *
     * @param plaintext value to encrypt
     * @return the encrypted value
     * @throws AtomicCryptoException when an error occurs during encryption
     */
    public byte[] encrypt(byte[] plaintext) throws AtomicCryptoException {
        try {
            symmetricHub = this.deriveSecretBox();
            return symmetricHub.encrypt(plaintext);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AtomicCryptoException(e);
        }
    }

    /**
     * Encrypt the given plaintext
     *
     * @param plaintext Value To Encrypt
     * @param secureRandom Secure Random
     * @return the encrypted value
     * @throws AtomicCryptoException when an error occurs during encryption
     */
    public byte[] encrypt(byte[] plaintext, SecureRandom secureRandom) throws AtomicCryptoException {
        try {
            symmetricHub = this.deriveSecretBox();
            return symmetricHub.encrypt(plaintext, secureRandom);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AtomicCryptoException(e);
        }
    }

    /**
     * Decrypt the given Cipher Text
     *
     * @param ciphertext value to decrypt
     * @return decrypted value
     * @throws AtomicCryptoException when an error occurs during encryption
     */
    public byte[] decrypt(byte[] ciphertext) throws AtomicCryptoException {
        try {
            return this.deriveSecretBox().decrypt(ciphertext);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AtomicCryptoException(e);
        }
    }

    /**
     * Get Cipher Text As Base64 Encoding
     *
     * @return Base64 Encoded Cipher Text As String
     * @throws java.security.NoSuchAlgorithmException Algorithm Error
     * @throws java.security.InvalidKeyException Invalid Key
     */
    public String getCipherTextAsBase64() throws NoSuchAlgorithmException, InvalidKeyException {
        return symmetricHub.getCipherTextAsBase64();
    }

    private SymmetricHub deriveSecretBox() throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(this.privateKey.getKey());
        keyAgreement.doPhase(this.publicKey.getKey(), true);
        byte[] z = keyAgreement.generateSecret();

        SHA3.DigestSHA3 sha3256 = new SHA3.Digest256();
        byte[] key = sha3256.digest(z);
        return new SymmetricHub(new SecretKey(key));
    }

}
