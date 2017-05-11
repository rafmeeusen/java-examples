package net.meeusen.crypto;

import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.meeusen.util.ByteString;

public class TestCrypto {

    public TestCrypto() {
        // TODO Auto-generated constructor stub
    }

    private static boolean testString(String ss) {

        // System.out.println("testing "+ss);
        Cipher c = null;
        try {
            c = Cipher.getInstance(ss);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // e.printStackTrace();
            System.out.println(ss + " was NOK!!!");
            return false;
        }
        System.out.println(ss + " was OK, " + c.getProvider());
        return true;

    }

    public static void main(String[] args) throws Exception {

        System.out.println("test");

        // String basepath = System.getProperty("java.home");
        // File cacertfile = new File (basepath+"/lib/security/cacerts");
        // if ( ! cacertfile.exists()) {
        // throw new Exception("mmm");
        // }
        // KeyStore systemTrustStore =
        // KeyStore.getInstance(KeyStore.getDefaultType());
        // systemTrustStore.load(new FileInputStream(cacertfile),
        // "changeit".toCharArray());
        // String firstEntryAlias = systemTrustStore.aliases().nextElement();
        // //System.out.println("alias:" + firstEntryAlias);
        // Certificate mycert1 =
        // systemTrustStore.getCertificate(firstEntryAlias);

        // AlgorithmParameters ap = AlgorithmParameters.getInstance("AES");

        // AlgorithmParameterGenerator apg =
        // AlgorithmParameterGenerator.getInstance("AES");
        // apg.generateParameters();

        // AlgorithmParameterSpec paramSpec = null;
        //
        // ap.init(paramSpec);

        //
        String provider = "SunJCE";
        String cipheralgo = "AES/GCM/NoPadding";
        // byte[] aeskey256bits = new byte[]
        // {00,01,02,03,04,05,06,07,0x8,0x9,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,00,01,02,03,04,05,06,07,0x8,0x9,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
        byte[] aeskey256bits = new byte[] { 00, 01, 02, 03, 04, 05, 06, 07, 0x8, 0x9, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F };
        byte[] plaintext = "AaBb012 This is a test plaintext...".getBytes();
        byte[] iv = new byte[] { 00, 01, 02, 03, 04, 05, 06, 07, 0x8, 0x9, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

        System.out.println("key length: " + aeskey256bits.length * 8);

        Cipher encryptor = Cipher.getInstance(cipheralgo, provider);
        Cipher decryptor = Cipher.getInstance(cipheralgo, provider);
        SecretKeySpec secretKeySpec = new SecretKeySpec(aeskey256bits, "AES");
        //IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        System.out.println("keygen algo: " + kg.getAlgorithm());
        SecretKey generatedkey = kg.generateKey();

        Key keyInUse = generatedkey;
        System.out.println("generated key algo:" + generatedkey.getAlgorithm());
        
        System.out.println(new ByteString(plaintext));
        //
        //encryptor.init(Cipher.ENCRYPT_MODE, keyInUse, ivParameterSpec);
        encryptor.init(Cipher.ENCRYPT_MODE, keyInUse);
        AlgorithmParameters params = encryptor.getParameters();
        byte[] ciphertext = encryptor.doFinal(plaintext);

        System.out.println("ciphertext:");
        System.out.println(new ByteString(ciphertext));

        decryptor.init(Cipher.DECRYPT_MODE, keyInUse, params);
        byte[] emptyarray=new byte[0];
        byte[] decryption = decryptor.doFinal(emptyarray);
        System.out.println("decrypted text:");
        System.out.println(new ByteString(decryption));

        // Provider[] provs = Security.getProviders();
        // for ( Provider p:provs) {
        // System.out.println("=======Provider: " + p + "==============");
        // Set<Provider.Service> slist = p.getServices();
        // for ( Provider.Service s:slist ) {
        // System.out.println(" service: "+s);
        // }
        // }

        // String test1="AES";
        //
        // testString("AES");
        // testString("DES");
        // testString("DESede");
        //
        //
        //
        // testString("AES/CBC/nopadding");
        // testString("AES/ECB/nopadding");
        // testString("AES/CTR/nopadding");
        //
        // testString(" ");
        //
        //
        // testString("AES/CTR/PKCS5Padding");
        //
        // testString("AES/CBC/PKCS5Padding");
        // testString("AES/ECB/PKCS5Padding");
        //
        // testString("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        // testString("RSA/ECB/PKCS1Padding");
        //
        //
        //
        // //NOK
        // testString("1DES");
        // testString("3DES");

    }

}
