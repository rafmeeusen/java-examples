package net.meeusen.crypto;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;



public class AesTest {

	
    private static final byte[]      IV                        = hexStringToByteArray("ABABABABABABABABABABABABABABABAB");
    private static final byte[]      AES_KEY                   = hexStringToByteArray("100F0E0D0C0B0A090807060504030201");
    private static String            TEST_PAYLOAD              = "Hello World!!!!!Hello World!!!!!";
	private static String fixedpayload; 
	private static byte[] fixedcleartext; 
	
	public static void main(String[] args) {

		System.out.println("just a simple AES enc/dec test");
		
		
        // build looooong payload
        String payload = TEST_PAYLOAD;
        for (int i = 0; i < 30; i++) {
            payload += TEST_PAYLOAD;
        }

        System.out.println("--------------------------------------------------------------------- ");
        System.out.println("Payload used in this test: " + payload.length() + " characters in string: ");
        System.out.println(payload);
        System.out.println("--------------------------------------------------------------------- ");
        fixedpayload = payload; 
        
        fixedcleartext = encodeUTF(fixedpayload);
		
		System.out.println("input: " + Arrays.toString(fixedcleartext)); 
		
		try {
			Cipher myaescipher = Cipher.getInstance("AES/CBC/NoPadding"); 
			SecretKeySpec secretKeySpec = new SecretKeySpec(AES_KEY, "AES");
			myaescipher.init(Cipher.ENCRYPT_MODE, secretKeySpec); 			
			IvParameterSpec iv = new IvParameterSpec(IV); 

			//AlgorithmParameters k = null;
			myaescipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv); 
			
			byte[] output = myaescipher.doFinal(fixedcleartext);
			System.out.println("output: " + Arrays.toString(output)); 
			
			
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error. Algo not supported. "); 
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			System.out.println("Error. Padding not supported. "); 
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.out.println("Error. Key error. "); 
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		
		System.out.println("End of test. "); 
		
	}


    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(
                s.charAt(i + 1), 16));
        }
        return data;
    }

    
    private static byte[] encodeUTF(String s) {
        try {
            return s.getBytes("UTF-8");
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }
}
