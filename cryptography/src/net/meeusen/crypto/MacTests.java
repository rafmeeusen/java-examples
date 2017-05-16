package net.meeusen.crypto;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import net.meeusen.util.ByteString;


public class MacTests {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
	    
		testOne();

	}



    private static void testOne() throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException {
        final int maxkeybytes = 24; 
		String message_p1 = "this is my "; 
		String message_p2 = "message!"; 

		System.out.println("playing around with hmac");
		System.out.println("hmac seems to work with any length of key");
		System.out.println("message: " + message_p1 + message_p2);
		System.out.println("message len: " + (message_p1.length() + message_p2.length()) );
		
		byte[] keybytes = new byte[maxkeybytes];
		new Random().nextBytes(keybytes);

		Mac hm = Mac.getInstance("HmacSHA1");
		for ( int keylen_bytes=1; keylen_bytes<maxkeybytes; keylen_bytes++) {
			byte[] keybytes_sub = Arrays.copyOfRange(keybytes, 0, keylen_bytes); 
			Key k = new SecretKeySpec(keybytes_sub, "THIS_DOESNT_MATTER");
			hm.init(k);
			hm.update(message_p1.getBytes());
			hm.update(message_p2.getBytes()); 
			byte[] mac = hm.doFinal();	
			System.out.println("key: " + new ByteString(keybytes_sub).toHexString());
			System.out.println("hmac: " + new ByteString(mac).toHexString());			
		}
		
		
//		byte[] keybytes16 = new byte[16]; 
//		byte[] keybytes37 = new byte[37]; 		
		
		//Key longkey = new SecretKeySpec(keybytes37, "AES"); 
		
			
		
		
//		hm.init(longkey);
//		hm.update("my message part 1".getBytes());
//		hm.update("part II of my msgtxt".getBytes());
//		byte[] mac2 = hm.doFinal();		
//		System.out.println("mac with short key: " + new ByteString(mac2).toHexString());
    }

}
