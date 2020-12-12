package com.example.demo;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class ECIESImplementation {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        System.out.println("ECIES Implementation");

        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(ecSpec);

        KeyPair keyPairU = keyPairGenerator.generateKeyPair();
        PrivateKey privateKeyU = keyPairU.getPrivate();
        PublicKey publicKeyU = keyPairU.getPublic();

        KeyPair keyPairV = keyPairGenerator.generateKeyPair();
        PrivateKey privateKeyV = keyPairV.getPrivate();
        PublicKey publicKeyV = keyPairV.getPublic();

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

    }
}
