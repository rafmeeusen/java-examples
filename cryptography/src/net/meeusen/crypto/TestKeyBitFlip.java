package net.meeusen.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class TestKeyBitFlip {



    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("simple test to flip bit in a key");
        
        Cipher ecbcipher = Cipher.getInstance("AES/ECB/NoPadding");
        byte[] aeskey128bits = new byte[] {00,01,02,03,04,05,06,07,0x8,0x9,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
        byte[] aeskey128bit_flippedbit = new byte[] {80,01,02,03,04,05,06,07,0x8,0x9,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
        byte[] plaintext32bytes = "abcdefghijklmnopqrstuvwxyz012345".getBytes();  
        System.out.println("plaintext: "+bytes2HexString(plaintext32bytes));

        SecretKeySpec secretKeySpec_rightkey = new SecretKeySpec(aeskey128bits, "AES");
        SecretKeySpec secretKeySpec_wrongkey = new SecretKeySpec(aeskey128bit_flippedbit, "AES");
        
        System.out.println("encrypt");
        ecbcipher.init(Cipher.ENCRYPT_MODE, secretKeySpec_rightkey);
        byte[] ciphertext = ecbcipher.doFinal(plaintext32bytes);        
        System.out.println("ciphertext: "+bytes2HexString(ciphertext));
        
        System.out.println("decrypt with right key");
        ecbcipher.init(Cipher.DECRYPT_MODE,  secretKeySpec_rightkey);
        byte[] decrypted1 = ecbcipher.doFinal(ciphertext);
        System.out.println("decrypted1: "+bytes2HexString(decrypted1));
        
        System.out.println("decrypt with wrong key");
        ecbcipher.init(Cipher.DECRYPT_MODE,  secretKeySpec_wrongkey);
        byte[] decrypted2 = ecbcipher.doFinal(ciphertext);
        System.out.println("decrypted2: "+bytes2HexString(decrypted2));
        
    }

    
    public static String bytes2HexString(byte[] thebytes) {
        StringBuffer sb = new StringBuffer(""); 
        for ( byte b : thebytes ) { 
            String oneByteString =String.format("%02x", b);  
            sb.append( oneByteString  ) ; 
        }
        return sb.toString();
    }
}
