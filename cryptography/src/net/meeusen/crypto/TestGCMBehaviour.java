package net.meeusen.crypto;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Random;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.meeusen.util.ByteString;

public class TestGCMBehaviour {


    public static void main(String[] args) throws Exception {
        System.out.println("Testing some GCM aspects.");

        System.out.println("static getMaxAllowedKeyLength on GCM: "+ Cipher.getMaxAllowedKeyLength("AES/GCM/NoPadding"));
        System.out.println("static getMaxAllowedKeyLength on CCM: "+ Cipher.getMaxAllowedKeyLength("AES/CCM/NoPadding"));


        TestGCMBehaviour testInstance = new TestGCMBehaviour(); 

        Cipher gcmcipher = Cipher.getInstance("AES/GCM/NoPadding");
        System.out.println("getAlgorithm: "+ gcmcipher.getAlgorithm());
        System.out.println("getExemptionMechanism: "+ gcmcipher.getExemptionMechanism());


        byte[] aeskey128bits = new byte[] {00,01,02,03,04,05,06,07,0x8,0x9,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
        SecretKeySpec secretKeySpec = new SecretKeySpec(aeskey128bits, "AES");
        System.out.println("format of our key: " + secretKeySpec.getFormat());

        testInstance.testAuthTagSize(gcmcipher, secretKeySpec);
        testInstance.testRandomBlockSizes(gcmcipher, secretKeySpec);
        testInstance.testFailedAuthentication(gcmcipher,secretKeySpec); 
        testInstance.testShortCipherTextDecryption(gcmcipher,secretKeySpec);

    }

    private void testShortCipherTextDecryption(Cipher cipherToUse, SecretKeySpec keyToUse) throws InvalidKeyException, InvalidParameterSpecException, InvalidAlgorithmParameterException {
        System.out.println("testing doFinal result on very short ciphertext, shorter than tag length");

        AlgorithmParameters params = cipherToUse.getParameters();
        cipherToUse.init(Cipher.DECRYPT_MODE, keyToUse, params);



        for ( int size : new int[]{0, 3,10,15,16,17})
            try {
                System.out.println("SIZE: "+size);
                cipherToUse.doFinal(new byte[size]);
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                System.out.println("exception: " + e.getMessage());
                e.printStackTrace();
            }

    }

    private void testFailedAuthentication(Cipher cipherToUse, SecretKey keyToUse) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidParameterSpecException {
        cipherToUse.init(Cipher.ENCRYPT_MODE, keyToUse);
        AlgorithmParameters params = cipherToUse.getParameters();
        //        System.out.println("params: " + params);

        GCMParameterSpec ivspec = params.getParameterSpec(javax.crypto.spec.GCMParameterSpec.class);
        //javax.crypto.spec.GCMParameterSpec
        System.out.println("ivspec getTLen (tag len I geuss): " + ivspec.getTLen());
        byte[] iv = ivspec.getIV(); 

        System.out.println("ivspec getIv: " + new ByteString(iv));
        System.out.println("iv nr bits: " + iv.length*8);

        byte[] plaintext = new byte[]{1,2,3,4,5,6} ; 
        byte[] ciphertext = cipherToUse.doFinal(plaintext);
        byte[] modifiedCipherText = ciphertext.clone(); 
        modifiedCipherText[modifiedCipherText.length-3] += 1; 
        System.out.println("showing that cipher is using authenticated encryption.");

        System.out.println("decrypt in one go.");
        cipherToUse.init(Cipher.DECRYPT_MODE, keyToUse, params);
        boolean hadExpectedException = false; 
        try {
            cipherToUse.doFinal(modifiedCipherText);
        } catch(AEADBadTagException e) {
            hadExpectedException = true; 
        }
        if ( ! hadExpectedException) {
            System.out.println("Mmmmm. DID NOT EXPECT THIS DECRYPTION TO WORK, BUT IT WORKED. ");
        } else {
            System.out.println("OK. Got bad tag exception.");
        }

        System.out.println("decrypt byte per byte.");
        cipherToUse.init(Cipher.DECRYPT_MODE, keyToUse, params);
        for ( byte b:modifiedCipherText) {
            byte[] oneByteArray = new byte[]{b};
            cipherToUse.update(oneByteArray);
        }
        hadExpectedException = false;
        try {
            cipherToUse.doFinal();
        } catch(AEADBadTagException e) {
            hadExpectedException = true; 
        }
        if ( ! hadExpectedException) {
            System.out.println("Mmmmm. DID NOT EXPECT THIS DECRYPTION TO WORK, BUT IT WORKED. ");
        } else {
            System.out.println("OK. Got bad tag exception.");
        }
    }

    private void testRandomBlockSizes(Cipher cipherToUse, SecretKey keyToUse) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        System.out.println();
        System.out.println("encrypting random data, random lengths, showing the cipher does buffering on some update calls, and ciphertext can be size 0.");
        int total_pt_len=0;
        int total_ct_len=0;
        Random rng = new Random(); 
        cipherToUse.init(Cipher.ENCRYPT_MODE, keyToUse);
        for ( int i=0; i<10; i++) {
            int nrbytes =0;
            while (nrbytes==0) {
                nrbytes = rng.nextInt(32);    
            }             
            byte[] pt = new byte[nrbytes]; 
            rng.nextBytes(pt);
            System.out.println("pt" + i +" : " + new ByteString(pt) + ", len=" + pt.length);
            int expectedlen = cipherToUse.getOutputSize(pt.length);
            byte[] ct = cipherToUse.update(pt);
            if ( ct.length <= expectedlen ) {
                System.out.println("ct" + i +" : " + new ByteString(ct) + ", len=" + ct.length);
                if (ct.length < expectedlen) {
                    System.out.println("Mmm. OK but overestimated by " + (expectedlen - ct.length) );
                }
            } else {
                System.out.println("Error!! " + expectedlen + " cannot hold " + ct.length );
            }
            total_pt_len+=pt.length;
            total_ct_len+=ct.length;
        }
        byte[] lastct = cipherToUse.doFinal();
        int lastctlen = lastct==null?0:lastct.length; 
        System.out.println("lastct: " + new ByteString(lastct) + ", len=" + lastctlen);
        total_ct_len+=lastctlen;

        System.out.println("total len of PT: " + total_pt_len);
        System.out.println("total len of CT: " + total_ct_len);
        System.out.println("delta total len: " + (total_ct_len - total_pt_len) );

    }

    public void testAuthTagSize(Cipher cipherToUse, SecretKey keyToUse) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        System.out.println();
        System.out.println("encrypting some different sizes of short data, showing that it's a stream cipher not a block cipher");

        byte[][] plaintexts = new byte[][] {
            new byte[]{1,2,3}, 
            new byte[]{1}, 
            new byte[]{1,2,3,4,5,6},
        };

        byte[][] ciphertexts = new byte[plaintexts.length][]; 

        for ( int i=0; i< plaintexts.length; i++ ) {
            cipherToUse.init(Cipher.ENCRYPT_MODE, keyToUse);
            ciphertexts[i] = cipherToUse.doFinal(plaintexts[i]);
            System.out.println("pt: " + i + new ByteString(plaintexts[i]) + ", len=" + plaintexts[i].length);
            System.out.println("ct: " + i +new ByteString(ciphertexts[i]) + ", len=" + ciphertexts[i].length);
            System.out.println("delta len: " + (ciphertexts[i].length - plaintexts[i].length) );
        }
    }

}
