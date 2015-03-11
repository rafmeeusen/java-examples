package net.meeusen.crypto.examples;

import java.math.BigInteger;

public class Message {

	private byte[] pk;
	private byte[] ct;
	private byte[] mac;
	
	Message( byte[] publicKey, byte[] cipherText, byte[] macTag  ) throws Exception {
		
		if ( publicKey.length != 65 ) throw new Exception ("Error. Expected publicKey of length 65"); 
		pk = publicKey.clone();
		ct = cipherText.clone();
		mac = macTag.clone();
	}

	public byte[] getMac() {
		return mac;
	}

	public byte[] getCt() {
		return ct;
	}

	public byte[] getPk() {
		return pk;
	}

	public BigInteger getPkX() {
		// returns BigInt based on 33 bytes, always leading 0 byte to make sure it's +
		byte[] temp = new byte[33]; 
		temp[0] = 0;
		System.arraycopy(pk, 1, temp, 1, 32);
		return new BigInteger(temp);
	}
	
	public BigInteger getPkY() {
		// returns BigInt based on 33 bytes, always leading 0 byte to make sure it's +
		byte[] temp = new byte[33]; 
		temp[0] = 0;
		System.arraycopy(pk, 1+32, temp, 1, 32);		
		return new BigInteger(temp);	
	}		
	
}
