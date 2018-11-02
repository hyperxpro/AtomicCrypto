package examples;

import com.aayushatharva.atomiccrypto.cryptography.AsymmetricHub;
import com.aayushatharva.atomiccrypto.cryptography.SymmetricHub;
import com.aayushatharva.atomiccrypto.keys.KeyPair;
import com.aayushatharva.atomiccrypto.keys.SecretKey;
import java.security.Security;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Aayush Atharva
 * @timestamp Nov 2, 2018 2:55:52 PM
 */
public class Asymmetric_Symmetric_Cryptography {

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        Symmetric();
        Asymmetric();
        Hybrid();
    }

    public static void Asymmetric() {
        try {
            
            String Data = "Hey!";
            
            // Generate Keys
            KeyPair SenderKeyPair = KeyPair.generate();
            KeyPair ReceiverKeyPair = KeyPair.generate();

            AsymmetricHub SenderBox = new AsymmetricHub(SenderKeyPair.getPrivateKey(), ReceiverKeyPair.getPublicKey());
            AsymmetricHub ReceiverBox = new AsymmetricHub(ReceiverKeyPair.getPrivateKey(), SenderKeyPair.getPublicKey());

            byte[] Encrypted = SenderBox.encrypt(Data.getBytes("UTF-8"));
            byte[] PlainText = ReceiverBox.decrypt(Encrypted);

            System.out.println("Sender Private Key: " + SenderKeyPair.getPrivateKeyAsBase64());
            System.out.println("Sender Public Key: " + SenderKeyPair.getPublicKeyAsBase64());
            System.out.println("Receiver Private Key: " + ReceiverKeyPair.getPrivateKeyAsBase64());
            System.out.println("Receiver Private Key: " + ReceiverKeyPair.getPublicKeyAsBase64());
            System.out.println("Encrypted Data: " + SenderBox.getCipherTextAsBase64());
            System.out.println("Decrypted Data: " + new String(PlainText, "UTF-8"));
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void Symmetric() {
        try {
            String Data = "Hey!";
            SecretKey key = SecretKey.generate();
            SymmetricHub box = new SymmetricHub(key);
            // Encrypt
            byte[] Encrypted = box.encrypt(Data.getBytes("UTF-8"));
            // Decrypt
            byte[] PlainText = box.decrypt(Encrypted);
            String EncryptedData = box.getCipherTextAsBase64();
            System.out.println("Key: " + key.getKeyAsBase64());
            System.out.println("Encrypted Data: " + EncryptedData);
            System.out.println("Decrypted Data: " + new String(PlainText, "UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void Hybrid() {
        try {
            
            String Data = "Hey!";
            // Generate Keys
            KeyPair SenderKeyPair = KeyPair.generate();
            KeyPair ReceiverKeyPair = KeyPair.generate();

            System.out.println("Sender Private Key: " + SenderKeyPair.getPrivateKeyAsBase64());
            System.out.println("Sender Public Key: " + SenderKeyPair.getPublicKeyAsBase64());
            System.out.println("Receiver Private Key: " + ReceiverKeyPair.getPrivateKeyAsBase64());
            System.out.println("Receiver Public Key: " + ReceiverKeyPair.getPublicKeyAsBase64());

            SecretKey key = SecretKey.generate();
            HybridCryptography hybridCryptography = new HybridCryptography(SenderKeyPair, ReceiverKeyPair, key.getBytes(), Data.getBytes());
            hybridCryptography.Encrypt();

            String EncryptedKey = Base64.getEncoder().encodeToString(hybridCryptography.getEncryptedSymmetricKey());
            String SymmetricKey = Base64.getEncoder().encodeToString(key.getBytes());

            System.out.println("Symmetric Key: " + SymmetricKey);
            System.out.println("Encrypted Key: " + EncryptedKey);
            System.out.println("Encrypted Data: " + Base64.getEncoder().encodeToString(hybridCryptography.getEncryptedData()));

            HybridCryptography hybridCryptographyDecrypt = new HybridCryptography(SenderKeyPair, ReceiverKeyPair, hybridCryptography.getEncryptedSymmetricKey(), hybridCryptography.getEncryptedData());
            hybridCryptographyDecrypt.Decrypt();

            System.out.println("Sender Public Key: " + SenderKeyPair.getPublicKeyAsBase64());
            System.out.println("Receiver Private Key: " + ReceiverKeyPair.getPrivateKeyAsBase64());
            System.out.println("Encrypted Data: " + new String(hybridCryptography.getData()));
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
