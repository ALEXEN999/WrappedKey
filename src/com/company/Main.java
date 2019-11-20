package com.company;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.PublicKey;

public class Main {

    public static void main(String[] args) throws Exception {
        Claus claus = new Claus();
        String msg = "Soy un cuenta cuentos";
        KeyPair key = claus.randomGenerate(1024);

        byte[] b1 = msg.getBytes("UTF-8");

        byte[] encryptTxt1 = claus.encryptData(b1, key.getPublic());
        byte[] dencryptTxt1 = claus.decryptData(encryptTxt1, key.getPrivate());
        System.out.println(new String(dencryptTxt1));


        claus.loadKeyStore("/home/dam2a/KeyStore.ks","123456");
        System.out.println(claus.loadKeyStore("/home/dam2a/KeyStore.ks","123456"));
    }
}
