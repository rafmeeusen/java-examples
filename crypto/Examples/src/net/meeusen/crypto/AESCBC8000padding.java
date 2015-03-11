package net.meeusen.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.meeusen.util.ByteString;

public class AESCBC8000padding {

	public static ByteString aesCBCEncrypt(ByteString key, ByteString iv, ByteString in) {
		byte[] keyBytes = key.getBytes();
		byte[] ivBytes = iv.getBytes();
		byte[] inBytes = in.forcedPadded8000().getBytes();
		byte[] outBytes = null;

		try {
			SecretKeySpec aesKeySpec = new SecretKeySpec(keyBytes, "AES");
			Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
			c.init(Cipher.ENCRYPT_MODE, aesKeySpec, new IvParameterSpec(ivBytes));
			outBytes = c.doFinal(inBytes);
		} catch (Exception e) {
			System.out.println("Exception raised in aesCBCEncrypt()");
			e.printStackTrace();
			System.exit(0);
		}
	    return(new ByteString(outBytes));
	}
	
	public static ByteString aesCBCDecrypt(ByteString key, ByteString iv, ByteString in) {
		byte[] keyBytes = key.getBytes();
		byte[] ivBytes = iv.getBytes();
		byte[] inBytes = in.getBytes();
		byte[] outBytes = null;

		try {
			SecretKeySpec aesKeySpec = new SecretKeySpec(keyBytes, "AES");
			Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
			c.init(Cipher.DECRYPT_MODE, aesKeySpec, new IvParameterSpec(ivBytes));
			outBytes = c.doFinal(inBytes);
		} catch (Exception e) {
			System.out.println("Exception raised in aesCBCEncrypt()");
			e.printStackTrace();
			System.exit(0);
		}
	    return(new ByteString(outBytes));
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}
}
