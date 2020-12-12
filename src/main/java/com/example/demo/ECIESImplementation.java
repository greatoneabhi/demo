package com.example.demo;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

public class ECIESImplementation {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        System.out.println("ECIES Implementation");
        Security.addProvider(new BouncyCastleProvider());

        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(ecSpec);

        KeyPair keyPairU = keyPairGenerator.generateKeyPair();
        ECPrivateKey privateKeyU = (ECPrivateKey) keyPairU.getPrivate();
        ECPublicKey publicKeyU = (ECPublicKey) keyPairU.getPublic();

        KeyPair keyPairV = keyPairGenerator.generateKeyPair();
        ECPrivateKey privateKeyV = (ECPrivateKey) keyPairV.getPrivate();
        ECPublicKey publicKeyV = (ECPublicKey) keyPairV.getPublic();

        System.out.println("Private key U: "+privateKeyU.getEncoded().toString());
        System.out.println("Public Key U: "+publicKeyU.toString());

        System.out.println("Private key V: "+privateKeyU.getEncoded().toString());
        System.out.println("Public Key V: "+publicKeyU.toString());

        KeyAgreement ecdhU = KeyAgreement.getInstance("ECDH");
        ecdhU.init(privateKeyU);
        ecdhU.doPhase(publicKeyV, true);

        KeyAgreement ecdhV = KeyAgreement.getInstance("ECDH");
        ecdhV.init(privateKeyV);
        ecdhV.doPhase(publicKeyU, true);

        System.out.println("Secret computed by U: 0x" + (new BigInteger(1, ecdhU.generateSecret())
                .toString(16).toUpperCase()));
        System.out.println("Secret computed by V: 0x" + (new BigInteger(1, ecdhV.generateSecret())
                .toString(16).toUpperCase()));

        encryptionAndDecryption();

    }

    public static void encryptionAndDecryption() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        ecKeyGen.initialize(new ECGenParameterSpec("secp256r1"));

        KeyPair ecKeyPair = ecKeyGen.generateKeyPair();

        Cipher iesCipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        Cipher iesDecipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        iesCipher.init(Cipher.ENCRYPT_MODE, ecKeyPair.getPublic());

        String message = "Hello World";

        byte[] ciphertext = iesCipher.doFinal(message.getBytes());
        System.out.println(Hex.toHexString(ciphertext));

        iesDecipher.init(Cipher.DECRYPT_MODE, ecKeyPair.getPrivate(), iesCipher.getParameters());
        byte[] plaintext = iesDecipher.doFinal(ciphertext);

        System.out.println(new String(plaintext));
    }
}
