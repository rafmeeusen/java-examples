package net.meeusen.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class RSAexception {

    public static void main(String[] args) {

        Cipher      myCipher = null; 
        KeyPairGenerator  kpg = null;
        PrivateKey  privateKeyMy = null; 

        System.out.println("Test: Let RSA generate a bad padding exception. ");

        try {
            kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            KeyPair     kp           = kpg.genKeyPair();
            privateKeyMy = kp.getPrivate();

            //Cipher      myCipher     = Cipher.getInstance("RSA/ECB/NoPadding");
            myCipher     = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            myCipher.init(Cipher.DECRYPT_MODE, privateKeyMy);            
        } catch ( Exception e ) {
            System.out.println("NOT the goal of this test. Unexpected exception with message: " + e.getMessage());
            e.printStackTrace();
        }

        try {
            myCipher.doFinal(new byte[128]);
        }
        catch ( BadPaddingException e ) {
            System.out.println("BadPaddingException. Message: " + e.getMessage());
            System.out.println("stack trace: ");
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            System.out.println("IllegalBlockSizeException. Message: " + e.getMessage());
            System.out.println("stack trace: ");
            e.printStackTrace();
        }

    }

}
