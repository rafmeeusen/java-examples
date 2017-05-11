package net.meeusen.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class TestCiphers {

    private String transformation;

    public TestCiphers(String transformation) {
        this.transformation = transformation;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
        TestCiphers[] tests = new TestCiphers[] { new TestCiphers("AEs/ECB/NoPadding"),
                new TestCiphers("AES/GCM/NoPadding"), new TestCiphers("AES/CTR/NoPadding"), new TestCiphers("AES/CTR/PKCS5Padding"),};

        for (TestCiphers t : tests) {
            System.out.println("Testing " + t.transformation);
            t.runTest();
            System.out.println("End of " + t.transformation);
            System.out.println("- - - - - - - - - - - - -");
        }

    }

    private void runTest() throws NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipherUnderTest = null;
        System.out.print("Instantiating Cihper ");
        try {
            cipherUnderTest = Cipher.getInstance(transformation);
            System.out.println("succeeded.");

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.out.println("failed. Exiting test.");
            return;
        }

        String algo = cipherUnderTest.getAlgorithm();
        System.out.println("Algorithm: " + algo);
        System.out.println("Provider: " + cipherUnderTest.getProvider());
        System.out.println("Block size: " + cipherUnderTest.getBlockSize());
        
        int maxkeylen = Cipher.getMaxAllowedKeyLength(algo);
        System.out.println("max key len for " + algo + ": " + maxkeylen);
        
        // create random key bytes of size 256. 
        byte[] symkey = new byte[256/8]; 
        new SecureRandom().nextBytes(symkey);
        SecretKeySpec k = new SecretKeySpec(symkey, "AES");
        //System.out.println("key: "+ Helpers.bytes2HexString(symkey));       
        //System.out.println("format of our key: " + k.getFormat());
        
        cipherUnderTest.init(Cipher.ENCRYPT_MODE, k);
        int inputSizes[] = new int[] {0,1,15,16,17}; 
        for ( int insize: inputSizes) {
            System.out.println("getOutputSize(" + insize + ") returns " + cipherUnderTest.getOutputSize(insize) );
        }
        
        // try encrypt 8 bytes
        System.out.print("Encrypting 8 bytes of PT ");
        try {
            byte[] ct = cipherUnderTest.doFinal(new byte[]{1,2,3,4,5,6,7,8});
            System.out.println(" succeeded, and returned " + ct.length + " bytes.");
            
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println(" failed with " + e.getClass().getSimpleName());
        }
        
        System.out.println("getParameters: "+cipherUnderTest.getParameters()); 

    }

}
