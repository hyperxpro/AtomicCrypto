# AtomicCrypto
Java Library To Provide Cryptographic Functions

[![Build Status](https://travis-ci.com/hyperxpro/AtomicCrypto.svg?branch=master)](https://travis-ci.com/hyperxpro/AtomicCrypto)


## Algorithms
AtomicCrypto uses NSA Suite B Cryptography. This means it uses AES-256-GCM to encrypt data and for asymmetric cryptography it uses ECDH with curve P-256 as default key agreement.

## Requirements
You need to [Install Bouncy Castle as a JCE provider](http://www.bouncycastle.org/wiki/display/JA1/Provider+Installation). <br />
You need the [Java Crypto Unlimited Strength Policy files](https://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html).

## How To Use AtomicCrypto In Project
### Maven
```Java
<dependency>
  <groupId>com.aayushatharva</groupId>
  <artifactId>AtomicCrypto</artifactId>
  <version>1.2.1.0</version>
</dependency>
```

### Gradle Groovy DSL
```Java
implementation 'com.aayushatharva:AtomicCrypto:1.2.1.0'
```

## Usage
### Asymmetric Cryptography
```Java
KeyPair SenderKeyPair = KeyPair.generate();
KeyPair ReceiverKeyPair = KeyPair.generate();

AsymmetricHub SenderBox = new AsymmetricHub(SenderKeyPair.getPrivateKey(), ReceiverKeyPair.getPublicKey());
AsymmetricHub ReceiverBox = new AsymmetricHub(ReceiverKeyPair.getPrivateKey(), SenderKeyPair.getPublicKey());

byte[] Encrypted = SenderBox.encrypt("Hey!".getBytes("UTF-8"));
byte[] PlainText = ReceiverBox.decrypt(Encrypted);
```

### Symmetric Cryptography
```Java
SecretKey key = SecretKey.generate();
SymmetricHub box = new SymmetricHub(key);
         
byte[] Encrypted = box.encrypt("Hey!".getBytes("UTF-8"));
byte[] PlainText = box.decrypt(Encrypted);	
```
