package net.meeusen.crypto.examples;


import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;

import net.meeusen.util.ByteString;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.agreement.*;
import org.bouncycastle.crypto.macs.*;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.*;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.math.ec.*;
import org.bouncycastle.math.ec.ECCurve.*;


@SuppressWarnings("restriction")
public class TestMain {

	static final int MODE_INVALID = 0;
	static final int MODE_GENENERATE_KP = 1;
	static final int MODE_DECRYPT = 2; 
	static final int MODE_ENCRYPT = 3;

	static final byte[] keydevparam = new ByteString("deadbeef").getBytes(); 	// P1 = key deriv param. DEADBEEF
	static final byte[] macencodingparam = new ByteString("cafebabe").getBytes(); // mac calculation string
	static final int macKeyLen = 20; //nr of bytes of the MAC key
	static final int macLen = 20; // nr of bytes of the MAC

	static X9ECParameters nist256params = NISTNamedCurves.getByName("P-256");	
	static ECDomainParameters mydomain = new ECDomainParameters(nist256params.getCurve(), nist256params.getG(), nist256params.getN() ); 	
	static int keySizeBytes = nist256params.getCurve().getFieldSize()/8; 
	
	// my key material:
	static ByteString my_privatekey_bs = new ByteString("6c385b1dad4cf9b4d5273c52ad27fa6d42998ec7c7d5a1563a313f8121813914");
	static ByteString my_puk_bs = new ByteString("04188be2de168b8ef385203cf3cb304bb094f28ead4a9f117d594a295681c930977aee3dbe80acf3bb5bf6a614151516d8dcc2b01887e3fd27d39e035329b44311");
	
	// their key material: 
	static ByteString their_puk_bs = new ByteString("04C2AE613D2018105DC47013885D4A6B398BA1B1F12542EB6B5333D5437B2B65E36294E95E5F4CAA330A19C4A691CB7068EB9DAA65E48C3C9FA0A94EE787B159DE");
	static byte[] their_puk_x = takePuKXbytes(their_puk_bs.getBytes());   
	static byte[] their_puk_y = takePuKYbytes(their_puk_bs.getBytes()); 

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		ByteString paramstring=null;
		AsymmetricCipherKeyPair keypair=null;
		
		System.out.println("Test start.");
		System.out.println("ECC domain info: ");
		printOurDomainParams();
		System.out.println();		

		CmdArgs parsedArgs = parseArgs (args); 
		//System.out.println("param:" + parameter);

		switch (parsedArgs.mode) {
		case MODE_GENENERATE_KP:
			System.out.println("Generating key pair ...");
			keypair = genKeyPair(); 
			try {
				byte[] pubkeyx = stripLeadingZero ( pubKeyXFromACKP (keypair) , keySizeBytes);
				byte[] pubkeyy = stripLeadingZero ( pubKeyYFromACKP (keypair) , keySizeBytes) ; 
				byte[] privkey = stripLeadingZero ( privKeyFromACKP (keypair) , keySizeBytes) ;  

				String hexstringx = new ByteString (pubkeyx).toHexString(); 
				String hexstringy = new ByteString (pubkeyy).toHexString(); 

				System.out.println ("private key : " +  new ByteString (privkey).toHexString()  );
				System.out.println ("public key x: " + hexstringx  );
				System.out.println ("public key y: " + hexstringy  );
				System.out.println ("public key  : " + "04" + hexstringx + hexstringy);
			} catch (Exception e1) {
				e1.printStackTrace();
			} 
			break;
		case MODE_DECRYPT:
			// input = MSG_PUK || MSG_CT || MSG_TAG
			//           65    ||  ??    ||   20   bytes
			System.out.println("Decrypting message");
			paramstring = new ByteString (parsedArgs.param.toString()); 
			int nrbytes = paramstring.length(); 
			ByteString msg_puk = paramstring.substring(0, 65);
			ByteString msg_ct = paramstring.substring(65, nrbytes-macLen-65);
			ByteString msg_tag = paramstring.substring(nrbytes-macLen, macLen);

			System.out.println("PUK: "+msg_puk.toHexString());
			System.out.println("CT : "+msg_ct.toHexString());
			System.out.println("TAG: "+msg_tag.toHexString());

			Message msg;

			try {
				msg = new Message ( msg_puk.getBytes(), msg_ct.getBytes(), msg_tag.getBytes() );
				int msglen = msg.getCt().length;
				int nrKeyBytes = msglen + macKeyLen ; // need key bytes for CT + key bytes for MAC-key

				// DH + keystream generation
				byte[] sharedsecret = doDH (new BigInteger(my_privatekey_bs.getBytes()), msg.getPkX(), msg.getPkY()); 
				System.out.println("shared secret: " + new ByteString(sharedsecret).toHexString() );							
				byte[] keystream = genKeyStream ( keydevparam, sharedsecret, nrKeyBytes );
				byte[] decryptionkey = new ByteString(keystream).substring(0, msglen).getBytes();
				byte[] mackey = new ByteString(keystream).substring(msglen, macKeyLen).getBytes();
				System.out.println("key: "+ new ByteString(keystream).toHexString());

				// VERIFY MAC
				byte[] calculatedMac = calcMac (mackey, msg.getCt(), macencodingparam) ; 
				// strip off first 'maclen' bytes: 
				boolean macOK = Arrays.equals(msg.getMac(), calculatedMac);
				if (macOK) {
					// decrypt
					byte[] plaintext = new byte[msglen];
					xor ( msg.getCt(), 0, decryptionkey, 0, plaintext, 0, msglen); 
					System.out.println("pt-ascii: " + new String(plaintext) );
					System.out.println("pt-hex  : " + new ByteString(plaintext).toHexString());
				} else {
					System.out.println("INVALID MESSAGE. NOT DECRYPTING.");
				}

			} catch (Exception e) {
				e.printStackTrace();
			}

			break;
		case MODE_ENCRYPT:
			System.out.println("Encrypting message");
			byte[] plaintext = parsedArgs.param.getBytes();
			int msglen = plaintext.length;
			int nrKeyBytes = msglen + macKeyLen ; // need key bytes for CT + key bytes for MAC-key
			
			// generate ephem key pair
			try {
				keypair = genKeyPair(); 
				byte[] ephemPrivKey = privKeyFromACKP (keypair) ;

				// DH with enc_puk and ephem_priv
				// bigint objects.
				BigInteger pukx = new BigInteger( addLeadingZero(their_puk_x) ); 
				BigInteger puky = new BigInteger( addLeadingZero(their_puk_y) ); 
				BigInteger prk = new BigInteger( addLeadingZero(ephemPrivKey) ); 
				byte[] sharedsecret = doDH (prk, pukx, puky); 
				System.out.println("shared secret: " + new ByteString(sharedsecret).toHexString() );			
				byte[] keystream = genKeyStream ( keydevparam, sharedsecret, nrKeyBytes );
				byte[] encryptionkey = new ByteString(keystream).substring(0, msglen).getBytes();
				byte[] mackey = new ByteString(keystream).substring(msglen, macKeyLen).getBytes();
				System.out.println("key: "+ new ByteString(keystream).toHexString());				
				
				// encrypt
				byte[] ct = new byte[msglen]; 
				xor (plaintext, 0, encryptionkey, 0, ct, 0, msglen); 
				
				// generate mac
				byte[] tag = calcMac (mackey, ct, macencodingparam) ; 
 				
				byte[] ephemPubKeyX = stripLeadingZero ( pubKeyXFromACKP (keypair) , keySizeBytes);
				byte[] ephemPubKeyY = stripLeadingZero ( pubKeyYFromACKP (keypair) , keySizeBytes) ; 
				ByteString ephpk1 = new ByteString ("04"); 
				ByteString ephpk2 = new ByteString (ephemPubKeyX); 
				ByteString ephpk3 = new ByteString (ephemPubKeyY); 
				byte[] ephemPubKey = ByteString.concat(ephpk1, ephpk2, ephpk3).getBytes();  
				Message encmsg = new Message(ephemPubKey, ct, tag);
				System.out.println ("Ephem public key: " + new ByteString(encmsg.getPk()).toHexString() );
				System.out.println ("Cipher text: " + new ByteString(encmsg.getCt()).toHexString() );
				System.out.println ("Tag: " + new ByteString(encmsg.getMac()).toHexString() );
				
			} catch (Exception e) {
				e.printStackTrace();
			}
			
			break;

		default: 
			System.out.println("ERROR in params. Usages: " );
			System.out.println("--- gen");
			System.out.println("--- dec + hex string (e.g. aa bb cc dd ee ff...11223344)");
			System.out.println("--- enc + \"my message as one parameter\"");

		}

		System.out.println("Test end.");
	}
	
	private static byte[] addLeadingZero(byte[] inbytes) {
		byte[] outbytes = new byte[inbytes.length+1]; 
		outbytes[0] = 0; 
		System.arraycopy(inbytes, 0, outbytes, 1, inbytes.length);
		return outbytes;
	}

	private static byte[] takePuKXbytes(byte[] inbytes) {
		byte[] xbytes = new byte[keySizeBytes];
		System.arraycopy(inbytes, 1, xbytes, 0, keySizeBytes);
		return xbytes;
	}

	private static byte[] takePuKYbytes(byte[] inbytes) {
		byte[] ybytes = new byte[keySizeBytes];
		System.arraycopy(inbytes, 1+keySizeBytes, ybytes, 0, keySizeBytes);
		return ybytes;
	}

	
	private static byte[] stripLeadingZero(byte[] inputbytes, int expectednrbytes) throws Exception {
		byte [] outputbytes=null; 
		// strip off potential leading 00 	
		if      ( inputbytes.length == expectednrbytes )    outputbytes = inputbytes;
		else if ( inputbytes.length == expectednrbytes+1 )  outputbytes = Arrays.copyOfRange(inputbytes, 1, expectednrbytes+1);
		else throw new Exception("byte array has unexpected length of " + inputbytes.length);
		return outputbytes;
	}

	private static byte[] privKeyFromACKP(AsymmetricCipherKeyPair keypair) {
		ECPrivateKeyParameters privkeyparam = (ECPrivateKeyParameters)keypair.getPrivate();		
		return privkeyparam.getD().toByteArray();
	}

	private static byte[] pubKeyXFromACKP(AsymmetricCipherKeyPair keypair) {
		ECPublicKeyParameters pubkeyparam = (ECPublicKeyParameters)keypair.getPublic();
		return pubkeyparam.getQ().getX().toBigInteger().toByteArray();
	}

	private static byte[] pubKeyYFromACKP(AsymmetricCipherKeyPair keypair) {
		ECPublicKeyParameters pubkeyparam = (ECPublicKeyParameters)keypair.getPublic();
		return pubkeyparam.getQ().getY().toBigInteger().toByteArray();
	}

	private static AsymmetricCipherKeyPair genKeyPair() {
		ECKeyPairGenerator g = new ECKeyPairGenerator() ;
		KeyGenerationParameters kgp = new ECKeyGenerationParameters(mydomain, new SecureRandom()); 
		g.init(kgp); 
		return g.generateKeyPair();
	}

	private static byte[] calcMac(byte[] mackey, byte[] ct, byte[] encparam ) {
		HMac maccer = new HMac(new SHA256Digest());
		byte[] macbytes = new byte[maccer.getMacSize()];
		CipherParameters ciphpar = new KeyParameter(mackey) ; 

		maccer.init(ciphpar);
		maccer.update(ct, 0, ct.length);
		maccer.update(encparam, 0, encparam.length);		
		maccer.doFinal(macbytes, 0);

		// restrict to maclen bytes: 
		macbytes = new ByteString(macbytes).substring(0, macLen).getBytes();
		
		return macbytes; 
	}

	/**
	 * generate nrKeyBytes of keystream
	 * */
	private static byte[] genKeyStream(byte[] keydevparam, byte[] sharedsecret, int nrKeyBytes) {
		byte[] keystream = new byte[nrKeyBytes]; 

		Digest sha256dig = new SHA256Digest();
		KDF2BytesGenerator kdf = new KDF2BytesGenerator( sha256dig );
		DerivationParameters derivparams = new KDFParameters( sharedsecret, keydevparam );
		kdf.init(derivparams); 	
		kdf.generateBytes(keystream, 0, nrKeyBytes);

		return keystream;
	}

	/*
	 * ECDH cofactor agreement
	 * */
	private static byte[] doDH(BigInteger privkey, BigInteger pubkeyx, BigInteger pubkeyy) throws Exception {
		final int sharedsecretsize = 32;
		byte[] sharedsecret ; 

		BasicAgreement ourdh = new ECDHCBasicAgreement();
		CipherParameters myprivkey = new ECPrivateKeyParameters(privkey, mydomain);
		// init with priv key
		ourdh.init(myprivkey);
		// do DH with pub key
		ECFieldElement ephemPukX = new ECFieldElement.Fp( ((ECCurve.Fp)mydomain.getCurve()).getQ() , pubkeyx );
		ECFieldElement ephemPukY = new ECFieldElement.Fp( ((ECCurve.Fp)mydomain.getCurve()).getQ() , pubkeyy );
		ECCurve ourcurve = mydomain.getCurve();
		ECPoint pubkeypoint = new ECPoint.Fp(ourcurve, ephemPukX,ephemPukY);
		CipherParameters pubkeyparam = new ECPublicKeyParameters(pubkeypoint, mydomain);	
		sharedsecret = ourdh.calculateAgreement(pubkeyparam).toByteArray();

		// strip off potential leading 00 (because byte array from negative BigInt has leading 00)	
		sharedsecret = stripLeadingZero (sharedsecret, sharedsecretsize); 

		return sharedsecret;
	}


	/**
	 * concat strings[] except strings[0]
	 * */
	private static String concatArgs ( String[] args ) { 		
		StringBuffer concatenation = new StringBuffer(); 		
		for ( int i=1; i<args.length; i++) {
			concatenation.append(args[i]); 
		}		
		return concatenation.toString();
	}

	private static CmdArgs parseArgs(String[] args) {	
		int nrargs = args.length; 		
		CmdArgs parsedArgs = new CmdArgs();
		parsedArgs.mode = MODE_INVALID;

		try {
			if ( nrargs == 0 ) throw new Exception();
			String cmd = args[0];
			parsedArgs.param = null; 
			if ( cmd.matches("gen") ) {
				if ( nrargs != 1 ) throw new Exception(); 
				parsedArgs.mode = MODE_GENENERATE_KP; 
			} else if ( cmd.matches("dec")) {
				parsedArgs.param  = concatArgs(args);
				if ( parsedArgs.param .length() %2 != 0 ) throw new Exception("EXCEPTION MESSAGE: number of hex digits must be even") ;
				parsedArgs.mode = MODE_DECRYPT; 
			} else if ( cmd.matches("enc")) {
				if ( nrargs != 2 ) throw new Exception(); 
				parsedArgs.param  = concatArgs(args);				
				parsedArgs.mode = MODE_ENCRYPT;
			}			
		} catch (Exception e) {
			System.out.println(e.getMessage());
			parsedArgs.mode = MODE_INVALID; 
		}		
		return parsedArgs;
	}

	/**
	 * print domain params: p, a, b, gx, gy
	 * */
	private static void printOurDomainParams() {
		ECCurve.Fp curve = (Fp) mydomain.getCurve();

		String a = new ByteString ( curve.getA().toBigInteger() ).toHexString();
		String b = new ByteString ( curve.getB().toBigInteger() ).toHexString();
		String p = new ByteString (curve.getQ()).toHexString();
		String gx = new ByteString ( mydomain.getG().getX().toBigInteger() ).toHexString();
		String gy = new ByteString ( mydomain.getG().getY().toBigInteger() ).toHexString();

		System.out.println("a: " + a); 
		System.out.println("b: " + b); 
		System.out.println("p: " + p); 
		System.out.println("gx: " + gx); 
		System.out.println("gy: " + gy); 

	}

	private static void xor(byte[] leftBuff, int leftOffset, 
			byte[] rightBuff, int rightOffset,
			byte[] xorBuff, int xorOffset,
			int length) {
		leftOffset += length;
		rightOffset += length;
		xorOffset += length;
		while(length > 0) {
			leftOffset--;
			rightOffset--;
			xorOffset--;
			length--;
			xorBuff[xorOffset] = (byte) (leftBuff[leftOffset] ^ rightBuff[rightOffset]);
		}
	}



}
