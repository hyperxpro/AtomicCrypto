import com.aayushatharva.atomiccrypto.cryptography.AsymmetricHub;
import com.aayushatharva.atomiccrypto.cryptography.SymmetricHub;
import com.aayushatharva.atomiccrypto.keys.KeyPair;
import com.aayushatharva.atomiccrypto.keys.SecretKey;

/**
 *
 * @author Aayush Atharva
 * @timestamp 26-Feb-2019 02:25:22 AM
 */
public class Crypto {

    public static void SymmetricHub() throws Exception {

        String Data = "Hey!";
        SecretKey key = SecretKey.generate();
        SymmetricHub symmetricHub = new SymmetricHub(key);

        // Encrypt Data and Get Encrypted Data In Byte Array
        byte[] Encrypted = symmetricHub.encrypt(Data.getBytes());

        // Get Encrypted Data As Base64 Encoding
        byte[] EncryptedBase64 = symmetricHub.getCipherDataAsBase64();

        // Decrypt Data and Get Decrypted Data In Byte Array
        byte[] PlainText = symmetricHub.decrypt(Encrypted);

        byte[] SymmetricKey = key.getKeyAsBase64();

        System.out.println("Key: " + new String(SymmetricKey));
        System.out.println("Encrypted Data: " + new String(EncryptedBase64));
        System.out.println("Decrypted Data: " + new String(PlainText));

    }

    public static void AsymmetricHub() throws Exception {

        String Data = "Hello";

        KeyPair SenderKeyPair = KeyPair.generate();

        AsymmetricHub asymmetricHub = new AsymmetricHub(SenderKeyPair.getPrivateKey(), SenderKeyPair.getPublicKey());

        // Encrypt Data and Get Encrypted Data In Byte Array
        byte[] Encrypted = asymmetricHub.encrypt(Data.getBytes());

        // Get Encrypted Data As Base64 Encoding
        byte[] EncryptedBase64 = asymmetricHub.getCipherDataAsBase64();

        // Decrypt Data and Get Decrypted Data In Byte Array
        byte[] PlainText = asymmetricHub.decrypt(Encrypted);

        System.out.println("Encrypted Data: " + new String(EncryptedBase64));
        System.out.println("Public Key: " + new String(SenderKeyPair.getPublicKeyAsBase64()));
        System.out.println("Private Key: " + new String(SenderKeyPair.getPrivateKeyAsBase64()));
        System.out.println("Decrypted Data: " + new String(PlainText));

    }

    public static void Hybrid() throws Exception {

        String Data = "Hey!";

        // Generate Keys
        KeyPair SenderKeyPair = KeyPair.generate();
        KeyPair ReceiverKeyPair = KeyPair.generate();

        SecretKey key = SecretKey.generate();

        // Key Details
        System.out.println("Sender Private Key: " + new String(SenderKeyPair.getPrivateKeyAsBase64()));
        System.out.println("Sender Public Key: " + new String(SenderKeyPair.getPublicKeyAsBase64()));

        System.out.println("Receiver Private Key: " + new String(ReceiverKeyPair.getPrivateKeyAsBase64()));
        System.out.println("Receiver Public Key: " + new String(ReceiverKeyPair.getPublicKeyAsBase64()));

        System.out.println("Symmetric Key: " + new String(key.getKeyAsBase64()));

        // Encrypt Data With Symmetric Key 
        SymmetricHub symmetricHub_encrypt = new SymmetricHub(key);
        byte[] EncryptedData = symmetricHub_encrypt.encrypt(Data.getBytes());

        // Encrypt Symmetric Key With Key Pair [Sender Private Key + Receiver Public Key]
        AsymmetricHub asymmetricHub_encrypt = new AsymmetricHub(SenderKeyPair.getPrivateKey(), ReceiverKeyPair.getPublicKey());
        byte[] EncryptedKey = asymmetricHub_encrypt.encrypt(key.getBytes());

        System.out.println("Encrypted Data: " + new String(symmetricHub_encrypt.getCipherDataAsBase64()));
        System.out.println("Encrypted Symmetric Key: " + new String(symmetricHub_encrypt.getCipherDataAsBase64()));

        // Decrypt Symmetric Key With Key Pair [Receiver Private Key + Sender Public Key]
        AsymmetricHub asymmetricHub_decrypt = new AsymmetricHub(ReceiverKeyPair.getPrivateKey(), SenderKeyPair.getPublicKey());
        byte[] DecryptedKey = asymmetricHub_decrypt.decrypt(EncryptedKey);

        // Decrypt Data With Symmetric Key
        SymmetricHub symmetricHub_decrypt = new SymmetricHub(DecryptedKey);
        byte[] DecryptedData = symmetricHub_decrypt.decrypt(EncryptedData);

        System.out.println("Decrypted Data: " + new String(DecryptedData));

    }

}
