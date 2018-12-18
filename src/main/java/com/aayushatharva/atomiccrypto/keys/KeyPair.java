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
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/**
 * Key pair for Asymmetric Cryptography
 * 
 * @author Aayush Atharva
 */
public class KeyPair {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    private KeyPair(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Generate A New Asymmetric Key Pair With "Prime256v1" as Elliptic Curve
     * Key Generation Parameter
     *
     * @return an asymmetric key pair
     * @throws AtomicCryptoException when there is an error generating the key
     * pair
     */
    public static KeyPair generate() throws AtomicCryptoException {
        try {
            ECGenParameterSpec spec = new ECGenParameterSpec("prime256v1");
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
            generator.initialize(spec, new SecureRandom());
            java.security.KeyPair pair = generator.generateKeyPair();
            PrivateKey privateKey = new PrivateKey(pair.getPrivate());
            PublicKey publicKey = new PublicKey(pair.getPublic());
            return new KeyPair(privateKey, publicKey);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new AtomicCryptoException(e);
        }
    }

    /**
     * Generate A New Asymmetric Key Pair With Defined Elliptic Curve Key
     * Generation Parameter
     *
     * @param eCGenParameterSpec Elliptic Curve Key Generation Parameter
     * @return an asymmetric key pair
     * @throws AtomicCryptoException when there is an error generating the key
     * pair
     */
    public static KeyPair generate(ECGenParameterSpec eCGenParameterSpec) throws AtomicCryptoException {
        try {
            ECGenParameterSpec spec = eCGenParameterSpec;
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
            generator.initialize(spec, new SecureRandom());
            java.security.KeyPair pair = generator.generateKeyPair();
            PrivateKey privateKey = new PrivateKey(pair.getPrivate());
            PublicKey publicKey = new PublicKey(pair.getPublic());
            return new KeyPair(privateKey, publicKey);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new AtomicCryptoException(e);
        }
    }

    /**
     * Load an Asymmetric Key Pair
     *
     * @param Public Public Key
     * @param Private Private Key
     * @return an asymmetric key pair
     * @throws AtomicCryptoException when there is an error generating the key
     * pair
     */
    public static KeyPair load(byte[] Public, byte[] Private) throws AtomicCryptoException {
        PrivateKey privateKey = new PrivateKey(Private);
        PublicKey publicKey = new PublicKey(Public);
        return new KeyPair(privateKey, publicKey);
    }

    /**
     * Load An Asymmetric Public Key
     *
     * @param Public Public Key
     * @return an asymmetric key pair
     * @throws AtomicCryptoException when there is an error generating the key
     * pair
     */
    public static KeyPair loadPublic(byte[] Public) throws AtomicCryptoException {
        PublicKey publicKey = new PublicKey(Public);
        return new KeyPair(null, publicKey);
    }

    /**
     * Load An Asymmetric Private Key
     *
     * @param Private Private Key
     * @return an asymmetric key pair
     * @throws AtomicCryptoException when there is an error generating the key
     * pair
     */
    public static KeyPair loadPrivate(byte[] Private) throws AtomicCryptoException {
        PrivateKey privateKey = new PrivateKey(Private);
        return new KeyPair(privateKey, null);
    }

    /**
     * Retrieve The Private Key
     *
     * @return The Private Key
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Retrieve The Public Key
     *
     * @return The Private Key
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Get Public Key Base64 Encoded
     *
     * @return The Base64 Encoded Public Key
     */
    public String getPublicKeyAsBase64() {
        return Base64.getEncoder().encodeToString(getPublicKey().getBytes());
    }

    /**
     * Get Private Key Base64 Encoded
     *
     * @return The Base64 Encoded Private Key
     */
    public String getPrivateKeyAsBase64() {
        return Base64.getEncoder().encodeToString(getPrivateKey().getBytes());
    }

}
