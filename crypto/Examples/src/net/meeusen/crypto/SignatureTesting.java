package net.meeusen.crypto;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;

import net.meeusen.util.ByteString;


class SigTest {
	private KeyPair kp;  
	private String algo;
	private byte[] sigresult; 


	public KeyPair getKp() {
		return kp;
	}
	public String getAlgo() {
		return algo;
	}
	public byte[] getSigResult() {
		return sigresult; 
	}

	public SigTest(KeyPair kp, String algo) {
		super();
		this.kp = kp;
		this.algo = algo;
	}


	public void test() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {

		byte[] data = "data to be signed".getBytes(); 

		Signature s = Signature.getInstance(this.algo, "BC");
		s.initSign(this.kp.getPrivate());
		s.update(data);
		sigresult = s.sign(); 

		tstsign(s, new byte[32]); 
		tstsign(s, new byte[1]); 
		tstsign(s, new byte[65]); 
		tstsign(s, new byte[64]); 
		tstsign(s, new byte[2]); 
		tstsign(s, new byte[47]); 

		// verify first signature
		s.initVerify(this.kp.getPublic());
		s.update(data);  
		boolean result = s.verify(sigresult);
		if ( !result ) {
			System.out.println("Mmmm. failed to verify signature on test data. ");
		}

	}

	private static void tstsign(Signature s, byte[] data) {

		try {
			s.update(data);
			s.sign();
			// System.out.println("sign OK");

		} catch(Exception e) {
			System.out.println("sign failed when trying sign with data len " + data.length);
			//e.printStackTrace();
		}

	}

}

public class SignatureTesting {

	/**
	 * @param args
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchProviderException 
	 */
	public static void main ( String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {

		System.out.println("Some signature experimenting"); 

		KeyPairGenerator kpg_dsa = KeyPairGenerator.getInstance("DSA");
		KeyPairGenerator kpg_rsa = KeyPairGenerator.getInstance("RSA");
		KeyPairGenerator kpg_ec = KeyPairGenerator.getInstance("EC");

		KeyPair kp_dsa = kpg_dsa.generateKeyPair(); 
		KeyPair kp_rsa = kpg_rsa.generateKeyPair(); 
		KeyPair kp_ec = kpg_ec.generateKeyPair(); 


		SigTest[] tests = new SigTest[] {
				new SigTest(kp_dsa, "SHA1withDSA"),
				new SigTest(kp_rsa, "SHA1withRSA"),
				new SigTest(kp_ec, "NONEwithECDSA"),
				new SigTest(kp_ec, "SHA1withECDSA"),
				new SigTest(kp_ec, "SHA256withECDSA"),
		}; 

		for ( SigTest t: tests) { 
			System.out.println("Testing " + t.getAlgo() + ": ");  
			t.test();			
			System.out.println("signature on test data: " + new ByteString(t.getSigResult()).toHexString());
		}

	} 

}

