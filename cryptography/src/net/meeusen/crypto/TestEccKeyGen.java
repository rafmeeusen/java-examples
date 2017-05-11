package net.meeusen.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.ECGenParameterSpec;

public class TestEccKeyGen {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
		ECGenParameterSpec kpgparams = new ECGenParameterSpec("secp256r1") ; 
		System.out.println("test that we can init BC EC kpg with " + kpgparams.getName());			
		kpg.initialize(kpgparams);
		System.out.println("ok");

	}

}
