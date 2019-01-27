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
import com.aayushatharva.atomiccrypto.keys.SecretKey;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Hub for Symmetric Cryptography
 *
 * @author Aayush Atharva
 */
public class SymmetricHub {

    private final byte[] key;

    private byte[] CipherText;

    /**
     * Create SymmetricHub Using The Provided Secret Key
     *
     * @param Key Secret Key
     */
    public SymmetricHub(SecretKey Key) {
        this.key = Key.getBytes();
    }

    /**
     * Create SymmetricHub Using The Provided Secret Key
     *
     * @param Key Secret Key
     */
    public SymmetricHub(byte[] Key) {
        this.key = Key;
    }

    /**
     * Encrypt The Given Data With SecureRandom Chosen By System
     *
     * @param Data Data To Encrypt
     * @return Encrypted Data
     * @throws AtomicCryptoException When An Error Occurs During Encryption
     */
    public byte[] encrypt(byte[] Data) throws AtomicCryptoException {
        try {

            byte[] nonce = new byte[12];
            SecureRandom random = new SecureRandom();
            random.nextBytes(nonce);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(this.key, "AES"), new IvParameterSpec(nonce));
            ByteArrayOutputStream output = new ByteArrayOutputStream();

            CipherOutputStream cipherStream = new CipherOutputStream(output, cipher);
            cipherStream.write(Data);
            cipherStream.close();

            byte[] ciphertext = output.toByteArray();
            CipherText = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, CipherText, 0, nonce.length);
            System.arraycopy(ciphertext, 0, CipherText, nonce.length, ciphertext.length);

            return CipherText;
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchProviderException | IOException e) {
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
    public byte[] encrypt(byte[] Data, SecureRandom secureRandom) throws AtomicCryptoException {
        try {
            byte[] nonce = new byte[12];
            SecureRandom random = secureRandom;
            random.nextBytes(nonce);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(this.key, "AES"), new IvParameterSpec(nonce));
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            CipherOutputStream cipherStream = new CipherOutputStream(output, cipher);
            cipherStream.write(Data);
            cipherStream.close();

            byte[] ciphertext = output.toByteArray();
            CipherText = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, CipherText, 0, nonce.length);
            System.arraycopy(ciphertext, 0, CipherText, nonce.length, ciphertext.length);

            return CipherText;
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchProviderException | IOException e) {
            throw new AtomicCryptoException(e);
        }
    }

    /**
     * Decrypt The Given Cipher Data
     *
     * @param Data Data To Decrypt
     * @return Decrypted Data
     * @throws AtomicCryptoException when an error occurs during encryption
     */
    public byte[] decrypt(byte[] Data) throws AtomicCryptoException {
        try {
            byte[] nonce = new byte[12];
            System.arraycopy(Data, 0, nonce, 0, nonce.length);

            byte[] input = new byte[Data.length - nonce.length];
            System.arraycopy(Data, nonce.length, input, 0, input.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.key, "AES"), new IvParameterSpec(nonce));
            ByteArrayInputStream inputStream = new ByteArrayInputStream(input);
            CipherInputStream cipherStream = new CipherInputStream(inputStream, cipher);

            return readOutput(cipherStream);
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchProviderException | IOException e) {
            throw new AtomicCryptoException(e);
        }
    }

    /**
     * Get Cipher Text As Base64 Encoding
     *
     * @return Base64 Encoded Cipher Data
     */
    public byte[] getCipherDataAsBase64() {
        return Base64.getEncoder().encode(CipherText);
    }

    private byte[] readOutput(InputStream inputStream) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];

        while (true) {
            int length = inputStream.read(buffer);
            if (length == -1) {
                break;
            }

            outputStream.write(buffer, 0, length);
        }

        return outputStream.toByteArray();
    }

}
