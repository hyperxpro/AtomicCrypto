package Testing;


import com.aayushatharva.atomiccrypto.cryptography.AsymmetricHub;
import com.aayushatharva.atomiccrypto.keys.KeyPair;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 *
 * @author Aayush Atharva
 * @timestamp 23-Jan-2019 18:30:05 PM
 */
public class Main {

    public static void main(String[] args) throws Exception {
        
        Security.addProvider(new BouncyCastleProvider());

        KeyPair pair1 = KeyPair.generate();
        KeyPair pair2 = KeyPair.generate();

        AsymmetricHub SenderBox = new AsymmetricHub(pair1.getPrivateKey(), pair2.getPublicKey());
        AsymmetricHub ReceiverBox = new AsymmetricHub(pair2.getPrivateKey(), pair1.getPublicKey());

        byte[] Encrypted = SenderBox.encrypt("Hey!".getBytes("UTF-8"));
        byte[] PlainText = ReceiverBox.decrypt(Encrypted);
        
        System.out.println(new String(SenderBox.getCipherDataAsBase64()));

    }

}
