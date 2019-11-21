package com.company;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

public class Main {

    public static void main(String[] args) throws Exception {
        Claus claus = new Claus();
        String msg = "Soy un cuenta cuentos";
        KeyPair key = claus.randomGenerate(1024);

        byte[] b1 = msg.getBytes("UTF-8");

        byte[] encryptTxt1 = claus.encryptData(b1, key.getPublic());
        byte[] dencryptTxt1 = claus.decryptData(encryptTxt1, key.getPrivate());
        System.out.println(new String(dencryptTxt1));


        KeyStore keyStore = claus.loadKeyStore("/out/artifacts/Wrapped/keystore_AlejandroP.jks","123456");

        System.out.println(keyStore.getType());
        System.out.println(keyStore.size());

        Enumeration<String>aliasesEnumeration = keyStore.aliases();

        while (aliasesEnumeration.hasMoreElements()){
            System.out.println(aliasesEnumeration.nextElement());
        }
        System.out.println(keyStore.getCertificate("mykey"));
        System.out.println(keyStore.getKey("mykey","123456".toCharArray()).getAlgorithm());


        SecretKey secretKey = Claus.keygenKeyGeneration(256);
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);

        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection("123456".toCharArray());

        keyStore.setEntry("secretKeyAlias", skEntry, protectionParameter);

        try (FileOutputStream fileOutputStream = new FileOutputStream("/out/artifacts/Wrapped/keystore_AlejandroP.jks")) {
            keyStore.store(fileOutputStream, "123456".toCharArray());
        }
        System.out.println(keyStore.getEntry("secretKeyAlias", protectionParameter));


        FileInputStream fileInputStream = new FileInputStream("/out/artifacts/Wrapped/apereiraf73.cer");

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Collection collection = certificateFactory.generateCertificates(fileInputStream);

        Iterator i = collection.iterator();
        while (i.hasNext()) {
            Certificate cer = (Certificate)i.next();
            System.out.println(cer);
        }


        PrivateKey privateKey = key.getPrivate();
        byte[] byData = "datos".getBytes();
        byte[] sign = Claus.signData(byData,privateKey);
        System.out.println(new String(sign));


        PublicKey publicKey = key.getPublic();

        boolean verified = Claus.validateSignature(byData,sign,publicKey);

        System.out.println(verified);





        KeyPair clausW = claus.randomGenerate(1024);

        PublicKey pubKey = clausW.getPublic();
        PrivateKey privateKey2 = clausW.getPrivate();
        byte[][] clauWrappedEncript = Claus.encryptWrappedData(byData,pubKey);
        byte[]  clauWrappedDecript = Claus.decryptWrappedData(clauWrappedEncript,privateKey2);

        System.out.println(new String(clauWrappedDecript));


    }
}
