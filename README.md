# AtomicCrypto
Java Library To Provide Cryptographic Functions

## Algorithms
AtomicCrypto uses NSA Suite B Cryptography. This means it uses AES-256-GCM to encrypt data and for asymmetric cryptography it uses ECDH with curve P-256 as default key agreement.

## Requirements
You need to [Install Bouncy Castle as a JCE provider](http://www.bouncycastle.org/wiki/display/JA1/Provider+Installation). <br />
You need the [Java Crypto Unlimited Strength Policy files](https://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html).

## Usage
### Box (Asymmetric Cryptography)
```Java
KeyPair pair1 = KeyPair.generate();
KeyPair pair2 = KeyPair.generate();

AsymmetricHub SenderBox = new AsymmetricHub(SenderKeyPair.getPrivateKey(), ReceiverKeyPair.getPublicKey());
AsymmetricHub ReceiverBox = new AsymmetricHub(ReceiverKeyPair.getPrivateKey(), SenderKeyPair.getPublicKey());

byte[] Encrypted = SenderBox.encrypt("Hey!".getBytes("UTF-8"));
byte[] PlainText = ReceiverBox.decrypt(Encrypted);
```

### Secret Box (Symmetric Cryptography)
```Java
SecretKey key = SecretKey.generate();
SymmetricHub box = new SymmetricHub(key);
         
byte[] Encrypted = box.encrypt("Hey!".getBytes("UTF-8"));
byte[] PlainText = box.decrypt(Encrypted);	
```
