package net.meeusen.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.SecretKeyEntry;
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

    public static void main(String[] args) throws Exception {
        System.out.println("Testing capabilities of different keystore types");

        System.out.println("Default type keystore: " + KeyStore.getDefaultType()); 
        KeyStore ks_jceks = KeyStore.getInstance("jceks"); 
        KeyStore ks_jks = KeyStore.getInstance("jks");
        KeyStore ks_pkcs12 = KeyStore.getInstance("PKCS12"); 

        ks_jks.load(null,null);
        ks_jceks.load(null,null);
        ks_pkcs12.load(null,null);  


        //System.out.println( "Secret key used here:"+ Helpers.bytes2HexString(getOurTestSecretKey().getEncoded()) );
        System.out.println("Trying setKeyEntry() with SecretKey for each type:"); 
        trySetKeyEntry(ks_jks, getOurTestSecretKey());
        trySetKeyEntry(ks_jceks, getOurTestSecretKey());
        trySetKeyEntry(ks_pkcs12, getOurTestSecretKey());
        ////////////////////////////////////////////
        System.out.println("Trying setCertificateEntry() for each type:"); 
        trySetCertEntry(ks_jks, getOurTestCertificate()); 
        trySetCertEntry(ks_jceks, getOurTestCertificate());
        trySetCertEntry(ks_pkcs12, getOurTestCertificate());
        //////////////////////////////////////////////        

        //ks_jks.store(new FileOutputStream("ks_jks.ks"), null);
        ks_jks.store(new FileOutputStream("ks_jceks.ks"), null);
        //ks_jks.store(new FileOutputStream("ks_pkcs12.ks"), null);
        
        
        System.out.println("certificate used:");
        System.out.println(getOurTestCertificate());
        
//        KeyStore.SecretKeyEntry mysk = new KeyStore.SecretKeyEntry(getOurTestSecretKey());
//        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection("blablabla123".toCharArray()); 
//        ks_jceks.setEntry("seckey1", mysk, protParam);

//        System.out.println("size: "+ks_jks.size());
//        ks_jceks.store(new FileOutputStream(new File("test.jks")), "".toCharArray());
//
//        KeyStore.SecretKeyEntry entryout = (SecretKeyEntry) ks_jceks.getEntry("seckey1", protParam);
//        SecretKey keyout = entryout.getSecretKey(); 
//        System.out.println(keyout.getAlgorithm());
//        System.out.println(keyout.getFormat());
//        byte[] keybytes = keyout.getEncoded();
//        System.out.println( Helpers.bytes2HexString(keybytes));
    }


    private static void trySetKeyEntry(KeyStore ourks, Key ourkey) {
        String message = "Storing " + ourkey.getClass() + " in " + ourks.getType() + " ";
        System.out.print(message);
        try {		
            String alias = getRandomAlias(); 
            ourks.setKeyEntry(alias, ourkey, pwd_entry.toCharArray(), null);
            System.out.println("SUCCEEDED for alias "+alias);
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
            System.out.println("SUCCEEDED for alias "+alias);
        } catch (Exception e) {
            System.out.println("FAILED. "+ e.getMessage()); 
        }
    }

    private static String getRandomAlias() {
        Random rng = new Random(); 
        byte[] ranbytes = new byte[8]; 
        rng.nextBytes(ranbytes);
        return new ByteString(ranbytes).toHexString();
    }

    private static SecretKey getOurTestSecretKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        if ( testSecKey == null ) {
            testSecKey = KeyGenerator.getInstance("AES").generateKey();
        }
        return testSecKey; 
    }

    private static Certificate getOurTestCertificate() throws Exception {
        if ( testCert == null ) {
            String basepath = System.getProperty("java.home");      
            File cacertfile = new File (basepath+"/lib/security/cacerts"); 
            if ( ! cacertfile.exists()) {
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
