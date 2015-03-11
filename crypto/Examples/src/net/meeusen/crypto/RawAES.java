package net.meeusen.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import net.meeusen.util.ByteString;

public class RawAES {

	public static ByteString aesEncrypt(ByteString key, ByteString in) {

		byte[] keyBytes = key.getBytes();
		byte[] inBytes = in.getBytes();
		byte[] outBytes = null;
		
		try {
			SecretKeySpec aesKeySpec = new SecretKeySpec(keyBytes, "AES");
			Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
			c.init(Cipher.ENCRYPT_MODE, aesKeySpec);
			outBytes = c.doFinal(inBytes);
		} catch (Exception e) {
			System.out.println("Exception raised in aesEncrypt()");
			e.printStackTrace();
			System.exit(0);
		}
	    return(new ByteString(outBytes));
	}
	
	public static ByteString aesDecrypt(ByteString key, ByteString in) {

		byte[] keyBytes = key.getBytes();
		byte[] inBytes = in.getBytes();
		byte[] outBytes = null;
		
		try {
			SecretKeySpec aesKeySpec = new SecretKeySpec(keyBytes, "AES");
			Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
			c.init(Cipher.DECRYPT_MODE, aesKeySpec);
			outBytes = c.doFinal(inBytes);
		} catch (Exception e) {
			System.out.println("Exception raised in aesDecrypt()");
			e.printStackTrace();
			System.exit(0);
		}
	    return(new ByteString(outBytes));
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
	    		
		ByteString testClearText1 = ByteString.zero(16);
		ByteString testKey1 = new ByteString("00800000 00000000 00000000 00000000");
		ByteString testExpectedCipherText1 = new ByteString("807d678fff1f56fa92de3381904842f2");
		ByteString testCipherText1 = aesEncrypt(testKey1, testClearText1);
		
		System.out.println("Test 1:");
		System.out.println("  Key:    " + testKey1.toHexString());
		System.out.println("  Clear:  " + testClearText1.toHexString());
		System.out.println("  Cipher: " + testCipherText1.toHexString());
		System.out.println("  Expect: " + testExpectedCipherText1.toHexString());
		System.out.println(" Succeeded: " + testCipherText1.equal(testExpectedCipherText1));
		
		ByteString testClearText2 = new ByteString("00112233445566778899aabbccddeeff");
		ByteString testKey2 = new ByteString("000102030405060708090a0b0c0d0e0f1011121314151617");
		ByteString testExpectedCipherText2 = new ByteString("dda97ca4864cdfe06eaf70a0ec0d7191");
		ByteString testCipherText2 = aesEncrypt(testKey2, testClearText2);
		
		System.out.println("Test 2:");
		System.out.println("  Key:    " + testKey2.toHexString());
		System.out.println("  Clear:  " + testClearText2.toHexString());
		System.out.println("  Cipher: " + testCipherText2.toHexString());
		System.out.println("  Expect: " + testExpectedCipherText2.toHexString());
		System.out.println(" Succeeded: " + testCipherText2.equal(testExpectedCipherText2));
		
		
	}
}
