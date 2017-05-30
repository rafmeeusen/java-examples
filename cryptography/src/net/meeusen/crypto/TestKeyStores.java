package net.meeusen.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.util.Random;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import net.meeusen.util.ByteString;

public class TestKeyStores {

    private static String pwd_entry = "our test entry password";
    private static SecretKey testSecKey = null;
    private static Certificate testCert = null;

    static void doTest(KeyStore ks) throws Exception {

        System.out.println("Start of test for KeyStore type " + ks.getType() + " of provider " + ks.getProvider());
        ks.load(null, null);
        trySetKeyEntry(ks, getOurTestSecretKey());
        trySetCertEntry(ks, getOurTestCertificate());
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Testing capabilities of different keystore types");

        KeyStore[] keyStoresToTest = new KeyStore[] { KeyStore.getInstance("jceks"), KeyStore.getInstance("jks"),
                KeyStore.getInstance("PKCS12"), };

        for (KeyStore ks : keyStoresToTest) {
            doTest(ks);
        }

    }

    private static void trySetKeyEntry(KeyStore ourks, Key ourkey) {
        String message = "Storing " + ourkey.getClass() + " in " + ourks.getType() + " ";
        System.out.print(message);
        try {
            String alias = getRandomAlias();
            ourks.setKeyEntry(alias, ourkey, pwd_entry.toCharArray(), null);
            System.out.println("SUCCEEDED for alias " + alias);
        } catch (Exception e) {
            System.out.println("FAILED. " + e.getMessage());
        }
    }

    private static void trySetCertEntry(KeyStore ourks, Certificate c) {
        String message = "Storing " + c.getClass() + " in " + ourks.getType() + " ";
        System.out.print(message);
        try {
            String alias = getRandomAlias();
            ourks.setCertificateEntry(alias, c);
            System.out.println("SUCCEEDED for alias " + alias);
        } catch (Exception e) {
            System.out.println("FAILED. " + e.getMessage());
        }
    }

    private static String getRandomAlias() {
        Random rng = new Random();
        byte[] ranbytes = new byte[8];
        rng.nextBytes(ranbytes);
        return new ByteString(ranbytes).toHexString();
    }

    private static SecretKey getOurTestSecretKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        if (testSecKey == null) {
            testSecKey = KeyGenerator.getInstance("AES").generateKey();
        }
        return testSecKey;
    }

    private static Certificate getOurTestCertificate() throws Exception {
        if (testCert == null) {
            String basepath = System.getProperty("java.home");
            File cacertfile = new File(basepath + "/lib/security/cacerts");
            if (!cacertfile.exists()) {
                throw new Exception("mmm");
            }
            KeyStore systemTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            systemTrustStore.load(new FileInputStream(cacertfile), "changeit".toCharArray());
            String firstEntryAlias = systemTrustStore.aliases().nextElement();
            testCert = systemTrustStore.getCertificate(firstEntryAlias);
        }
        return testCert;
    }

}
