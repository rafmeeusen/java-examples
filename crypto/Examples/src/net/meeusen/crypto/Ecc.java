package net.meeusen.crypto;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import net.meeusen.util.ByteString;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;


public class Ecc {

	private static BigInteger prk2bi (byte[] keybytes) {
		// raw priv-key bytes 2 big-int conversion ; just adding 0 prefix to force positive value
		int nrbytes = keybytes.length; 
		byte[] tmp = new byte[1+nrbytes];
		System.arraycopy(keybytes, 0, tmp, 1, nrbytes);
		return new BigInteger(tmp); 
	}
	
	private static BigInteger puk2bi (byte[] keybytes, boolean isYCoord) throws Exception {
		// raw pub-key bytes 2 big-int conversion for the X-coord.
		// assuming 04 is first byte, followed by x and y bytes
		int nrbytes_twocoord = keybytes.length - 1 ; 
		if ( (nrbytes_twocoord % 2) != 0 ) throw new Exception ("This function must be called with odd number of bytes. ");
		int nrbytes_onecoord = nrbytes_twocoord/2; 		
		int startidx = 1;
		if (isYCoord) startidx+= nrbytes_onecoord; 		
		byte[] tmp = new byte[1+nrbytes_onecoord];
		System.arraycopy(keybytes, startidx, tmp, 1, nrbytes_onecoord);
		return new BigInteger(tmp); 
	}
	
	private static BigInteger pukx2bi (byte[] keybytes) throws Exception {
		return puk2bi(keybytes, false); 
	}
	
	private static BigInteger puky2bi (byte[] keybytes) throws Exception {
		return puk2bi(keybytes, true); 
	}
	
	public static void main(String[] args) throws Exception {
		System.out.println("Ecc example code.");
		
		MyDomain dom256 = new MyDomain("secp256r1");
		System.out.println(dom256);
		SecureRandom rng = new SecureRandom(); 
		
		// generate 2 keypairs
		int nrkeypairs = 2; 
		
		int keysize = 256; // nr bits for above curve
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
		//kpg.initialize(keysize); 
		AlgorithmParameterSpec ecc_algo_params = new ECGenParameterSpec(dom256.getCurveName()) ; 
		kpg.initialize(ecc_algo_params);
		
		System.out.println("KeyPairGenerator algo: " + kpg.getAlgorithm());
		
		PublicKey ecpuk[] = new PublicKey[nrkeypairs];
		PrivateKey ecprk[] = new PrivateKey[nrkeypairs];
		
		for ( int i=0; i<nrkeypairs; i++) {
			KeyPair tmp =  kpg.generateKeyPair();
			ecpuk[i] = tmp.getPublic(); 
			ecprk[i] = tmp.getPrivate() ; 
		}
		
		// convert keys to byte[] and BigInteger
		byte[][] ecpukbytesencoded = new byte[nrkeypairs][]; 
		byte[][] ecprkbytesencoded = new byte[nrkeypairs][]; 
		byte[][] ecpukbytes = new byte[nrkeypairs][]; 
		byte[][] ecprkbytes = new byte[nrkeypairs][];
		BigInteger[] ecprk_bi = new BigInteger[nrkeypairs];
		BigInteger[] ecpukx_bi = new BigInteger[nrkeypairs];
		BigInteger[] ecpuky_bi = new BigInteger[nrkeypairs];
		
		int actualprklen = 1 + keysize/8; // 256-bit => 32 bytes + 1 to always start with 0 (prevents bigint to become negative)
		int actualpuklen = 1 + 2* (keysize/8);
		for ( int i=0; i<nrkeypairs; i++  ) {
			ecpukbytesencoded[i] = ecpuk[i].getEncoded(); 
			ecpukbytes[i] = Arrays.copyOfRange(ecpukbytesencoded[i], ecpukbytesencoded[i].length-actualpuklen, ecpukbytesencoded[i].length);
			
			ecpukx_bi[i] = pukx2bi(ecpukbytes[i]); 
			ecpuky_bi[i] = puky2bi(ecpukbytes[i]); 
			
			ecprkbytesencoded[i] = ecprk[i].getEncoded();
			int offset_privkey_asn1_octetstring = 34; // TODO: proper ASN1 parsing
			if ( ecprkbytesencoded[i][offset_privkey_asn1_octetstring] != 0x04 ) throw new Exception("Oops this handcrafted asn1 parsing fails");
			int privkey_len = ecprkbytesencoded[i][offset_privkey_asn1_octetstring+1]; 
			if ( privkey_len != 0x20 ) throw new Exception("Oops this handcrafted asn1 parsing fails");

			ecprkbytes[i] = Arrays.copyOfRange(ecprkbytesencoded[i], ecprkbytesencoded[i].length-actualprklen, ecprkbytesencoded[i].length);
			//ecprkbytes[i][0] = 0; 
			ecprk_bi[i] = prk2bi(ecprkbytes[i]) ; // new BigInteger(ecprkbytes[i]); 
		}
		
		// print key info		
		for ( int i=0; i<nrkeypairs; i++  ) {
			System.out.println("key pair " + (i+1));
			System.out.println(" algorithm: " + ecpuk[i].getAlgorithm() + "/ format PuK:" + ecpuk[i].getFormat() + "/ format PrK:" + ecprk[i].getFormat());			
			System.out.println("  PuK bytes " + new ByteString(ecpukbytesencoded[i]).toHexString() );
			System.out.println("      of which raw key bytes (04-prefix): " + new ByteString(ecpukbytes[i]).toHexString() );
			System.out.println("  PrK bytes " + new ByteString(ecprkbytesencoded[i]).toHexString() );
			System.out.println("      of which raw key bytes: " + new ByteString(ecprkbytes[i]).toHexString() );
		}
		
		// sign something
		String message = new String("Test message."); 
		Signature signer = Signature.getInstance("SHA1withECDSA"); 		
		signer.initSign(ecprk[0]);
		signer.update(message.getBytes());
		byte[] signature = signer.sign(); 
		System.out.println("Signature: ");
		System.out.println("    message: " + message);
		System.out.println("    signature: " + new ByteString(signature).toHexString()) ;
				
		// verify signature: 
		Signature verifier = Signature.getInstance("SHA1withECDSA"); 
		verifier.initVerify(ecpuk[0]);
		verifier.update(message.getBytes());
		System.out.println("    verification result: " + verifier.verify(signature) ) ; 
		
		// reconstruct key objects from asn1 byte[] (which contains curve info) 
//		ECPrivateKeyParameters prkspec_a = (ECPrivateKeyParameters) PrivateKeyFactory.createKey(ecprkbytesencoded[0]) ; 
		
		// reconstruct key objects from raw bytes (BigInts, but that's similar), knowing which curve we are on.
		System.out.println("reconstructing key from the raw bytes");
		KeyFactory keymaker = KeyFactory.getInstance("EC");//KeyFactory keymaker = KeyFactory.getInstance("EC", "BC");
		java.security.spec.ECPoint pubkeypoint = new java.security.spec.ECPoint( ecpukx_bi[0], ecpuky_bi[0] );  
		java.security.spec.ECPrivateKeySpec privkeyspec = new java.security.spec.ECPrivateKeySpec(ecprk_bi[0], dom256.getEcParamSpec()); // ECPrivateKeySpec(BigInteger s, ECParameterSpec params)
		java.security.spec.ECPublicKeySpec pubkeyspec = new java.security.spec.ECPublicKeySpec(pubkeypoint, dom256.getEcParamSpec()); // ECPrivateKeySpec(BigInteger s, ECParameterSpec params)
		PrivateKey prk_regenerated = keymaker.generatePrivate(privkeyspec); 
		PublicKey puk_regenerated = keymaker.generatePublic(pubkeyspec); 

		System.out.println(" algorithm: " + puk_regenerated.getAlgorithm() + "/ format PuK:" + puk_regenerated.getFormat() + "/ format PrK:" + prk_regenerated.getFormat());			
		System.out.println("  PuK bytes " + new ByteString(puk_regenerated.getEncoded()).toHexString() );
		System.out.println("  PrK bytes " + new ByteString(prk_regenerated.getEncoded()).toHexString() );

		// verify signature again: 
		verifier.initVerify(puk_regenerated);
		verifier.update(message.getBytes());
		System.out.println("    verification result: " + verifier.verify(signature) ) ; 
		
		// test some lesser used methods on the providers
		
		String[] provs2test = new String[] {"SunEC", "BC"};
		for ( String prov: provs2test ) {
			signer = Signature.getInstance("SHA1withECDSA",prov);
			System.out.println("playing with algo parameters for provider " + signer.getProvider());
			try {
				AlgorithmParameters ap = signer.getParameters(); 
				System.out.println("Signature getParameters: " + ap);
			} catch(Exception e) {
				System.out.println("Signature getParameters exception: " + e.getClass());
			}			
			try {
				signer.setParameter(null);
				System.out.println("Signature setparameter(null) no exception");
			} catch (Exception e) {
				System.out.println("Signature setParameter exception: " + e.getClass());
			}
			
			kpg = KeyPairGenerator.getInstance("EC", prov);
			ECGenParameterSpec kpgparams = new ECGenParameterSpec(dom256.getCurveName()) ; 
			System.out.println("test that we can init kpg with " + kpgparams.getName());			
			kpg.initialize(kpgparams);
			System.out.println("ok");
		}
		
	}
	
	
	
}
