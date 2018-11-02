package examples;

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
import com.aayushatharva.atomiccrypto.cryptography.AsymmetricHub;
import com.aayushatharva.atomiccrypto.cryptography.SymmetricHub;
import com.aayushatharva.atomiccrypto.exception.AtomicCryptoException;
import com.aayushatharva.atomiccrypto.keys.KeyPair;

/**
 *
 * @author Aayush Atharva
 * @timestamp Oct 22, 2018 6:34:26 PM
 */
public class HybridCryptography {

    private byte[] SymmetricKey;
    private byte[] EncryptedSymmetricKey;
    private byte[] EncryptedData;
    private byte[] Data;

    private KeyPair SenderKeyPair;
    private KeyPair ReceiverKeyPair;

    /**
     * Hybrid Cryptography Key 
     * <br/>
     * Instructions: For Encryption, there must be an
     * Sender Private Key and Receiver Public Key. And, For Decryption, Receiver
     * Private Key and Sender Public Key
     * 
     * @param SenderKeyPair Key Of Sender
     * @param ReceiverKeyPair Key Of Receiver
     * @param SymmetricKey For Encryption: Unencrypted Symmetric Key and
     * Decryption: Encrypted Symmetric Key
     * @param Data For Encryption: Unencrypted Data and Decryption: Encrypted
     * Data
     */
    public HybridCryptography(KeyPair SenderKeyPair, KeyPair ReceiverKeyPair, byte[] SymmetricKey, byte[] Data) {
        this.SenderKeyPair = SenderKeyPair;
        this.ReceiverKeyPair = ReceiverKeyPair;
        this.SymmetricKey = SymmetricKey;
        this.Data = Data;
    }

    public void Encrypt() throws AtomicCryptoException {

        // Encrypt Data With Symmetric Key
        {
            SymmetricHub symmetricHub = new SymmetricHub(SymmetricKey);
            setEncryptedData(symmetricHub.encrypt(Data));
        }

        // Encrypt Symmetric Key With Asymmetric Encryption
        {
            AsymmetricHub asymmetricHub = new AsymmetricHub(SenderKeyPair.getPrivateKey(), ReceiverKeyPair.getPublicKey());
            setEncryptedSymmetricKey(asymmetricHub.encrypt(SymmetricKey));
        }

    }

    public void Decrypt() throws AtomicCryptoException {

        // Decrypt Symmetric Key With Asymmetric Encryption
        AsymmetricHub asymmetricHub = new AsymmetricHub(ReceiverKeyPair.getPrivateKey(), SenderKeyPair.getPublicKey());

        byte[] DecryptedKey = asymmetricHub.decrypt(SymmetricKey);

        // Decrypt Data With Symmetric Key
        SymmetricHub symmetricHub = new SymmetricHub(DecryptedKey);

        setData(symmetricHub.decrypt(Data));

    }

    public byte[] getEncryptedSymmetricKey() {
        return EncryptedSymmetricKey;
    }

    public void setEncryptedSymmetricKey(byte[] EncryptedSymmetricKey) {
        this.EncryptedSymmetricKey = EncryptedSymmetricKey;
    }

    public byte[] getEncryptedData() {
        return EncryptedData;
    }

    public void setEncryptedData(byte[] EncryptedData) {
        this.EncryptedData = EncryptedData;
    }

    public byte[] getData() {
        return Data;
    }

    public void setData(byte[] Data) {
        this.Data = Data;
    }

}
