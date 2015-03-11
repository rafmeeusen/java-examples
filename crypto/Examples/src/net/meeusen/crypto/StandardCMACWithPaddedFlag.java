package net.meeusen.crypto;


import net.meeusen.crypto.RawAES;
import net.meeusen.util.ByteString;

public class StandardCMACWithPaddedFlag {

	private static ByteString R128 = new ByteString("00000000 00000000 00000000 00000087");
	
	public static void subkeyGeneration(ByteString k, ByteString k1, ByteString k2) {
		ByteString l = RawAES.aesEncrypt(k, ByteString.zero(16));
		ByteString tempK1;
		ByteString tempK2;
		
		ByteString lShl1 = l.shiftLeft1Bit();
		
		if (l.mostSignificantBit() == 0) {
			tempK1 = lShl1;
		} else {
			tempK1 = lShl1.xor(R128);
		}
		
		ByteString k1Shl1 = tempK1.shiftLeft1Bit();
		
		if (tempK1.mostSignificantBit() == 0) {
			tempK2 = k1Shl1;
		} else {
			tempK2 = k1Shl1.xor(R128);
		}
		
		k1.setBytes(tempK1.getBytes());
		k2.setBytes(tempK2.getBytes());
	}
	
	public static ByteString cmacPadToLength(ByteString m, int length) {
		if (m.length() < length) {
			return(ByteString.concat(m, ByteString.concat(new ByteString("80"), ByteString.zero(length-m.length()-1))));
		} else {
			return(m);
		}
	}
	
	public static ByteString macGeneration(ByteString k, ByteString m, boolean padded) {
		ByteString t;
		
		ByteString k1 = new ByteString();
		ByteString k2 = new ByteString();
		int n; // number of blocks
		
		subkeyGeneration(k, k1, k2);
		
		if (m.length() == 0) {
			n = 1;
		} else {
			n = (int)(Math.ceil(m.length() / 16.0));
		}
		
		ByteString c = ByteString.zero(16);
		
		for (int i = 0 ; i < n-1 ; i++) {
			ByteString mCurrent = m.substring(i*16, 16);
			c = RawAES.aesEncrypt(k, mCurrent.xor(c));
		}

		int lengthMLast = m.length()-(n-1)*16;
		ByteString mLast = m.substring((n-1)*16, lengthMLast);
		
		if (lengthMLast != 16) {
			System.out.println("Error: invalid message length: " + lengthMLast + " in CMAC with Padded flag");
			System.exit(1);
		}

		if (!padded) {
			t = RawAES.aesEncrypt(k, mLast.xor(c).xor(k1));
		} else {
			t = RawAES.aesEncrypt(k, mLast.xor(c).xor(k2));
		}
		return(t);
	}

	public static void abu() {
		
		
		ByteString k = new ByteString("f3 f9 37 76 98 70 7b 68 8e af 84 ab e3 9e 37 91");
		ByteString aMes = new ByteString("01 0a cf 38 d6 de ad be ef fe ed");
		
		ByteString k1 = new ByteString();
		ByteString k2 = new ByteString();
		
		
		System.out.println(cmacPadToLength(aMes, 32).toHexString());
		System.out.println(macGeneration(k, cmacPadToLength(aMes, 32), true).toHexString());


		System.out.println("Key: " + k.toHexString());
		subkeyGeneration(k, k1, k2);
		
		System.out.println("K1: " + k1.toHexString());
		System.out.println("K2: " + k2.toHexString());
		
		System.out.println("Mes: " + aMes.toHexString());

		ByteString aMesPadded = cmacPadToLength(aMes,32);
		
		System.out.println("Mes padded: " + aMesPadded.toHexString());
		ByteString m1 = aMesPadded.slice(0,15);
		ByteString m2 = aMesPadded.slice(16, 31);
		
		System.out.println("Block 1: " + m1.toHexString());
		System.out.println("Block 2: " + m2.toHexString());
		
		ByteString b1 = RawAES.aesEncrypt(k, m1);
		
		System.out.println("Block 1 encryption: " + b1.toHexString() + " = E(" + k.toHexString() +","+m1.toHexString()+")");
		
		ByteString m2prime = m2.xor(k2).xor(b1);
		System.out.println("Block 2 XOR K2 XOR Block 1 encrypted: " + m2prime.toHexString());
		System.out.println("Block 2 XOR K2: " + m2.xor(k2).toHexString());
		System.out.println("Block 2 XOR Block 1 encrypted: " + m2.xor(b1).toHexString());
		
		ByteString b2 = RawAES.aesEncrypt(k, m2prime);
		
		System.out.println("Block 2 encryption: " + b2.toHexString() + " = E(" + k.toHexString() +","+m2prime.toHexString()+")");
		
	}
	
	
	public static void main(String[] args) {
		
		// Test case out of standard SP_800-38B document
		//D.1 AES-128
		//For Examples 1–4 below, the block cipher is the AES algorithm with the following 128 bit key:
		//    K 2b7e1516 28aed2a6 abf71588 09cf4f3c.
		// Subkey Generation
		//    CIPHK(0128) 7df76b0c 1ab899b3 3e42f047 b91b546f
		//    K1 fbeed618 35713366 7c85e08f 7236a8de
		//    K2 f7ddac30 6ae266cc f90bc11e e46d513b
				
		ByteString kTest1 = new ByteString("2b7e1516 28aed2a6 abf71588 09cf4f3c");
		ByteString k1Test1 = new ByteString();
		ByteString k2Test1 = new ByteString();
		
		subkeyGeneration(kTest1, k1Test1, k2Test1);

		System.out.println("Test 1: ");
		System.out.println("  k:  " + kTest1.toHexString());
		System.out.println("  k1: " + k1Test1.toHexString());
		System.out.println("  k2: " + k2Test1.toHexString());
		System.out.println("  k1 ok: " 
				+ k1Test1.equal(new ByteString("fbeed618 35713366 7c85e08f 7236a8de")));
		System.out.println("  k2 ok: " 
				+ k2Test1.equal(new ByteString("f7ddac30 6ae266cc f90bc11e e46d513b")));

		// Example 1: Mlen = 0
		ByteString mesA = new ByteString("80000000 00000000 00000000 00000000");
		ByteString expectedCMACMesA = new ByteString("bb1d6929 e9593728 7fa37d12 9b756746");
		
		// Example 2: Mlen = 128
		ByteString mesB = new ByteString("6bc1bee2 2e409f96 e93d7e11 7393172a");
		ByteString expectedCMACMesB = new ByteString("070a16b4 6b4d4144 f79bdd9d d04a287c");

		// Example 3: Mlen = 320
		ByteString mesC = new ByteString("6bc1bee2 2e409f96 e93d7e11 7393172a"
				+ "ae2d8a57 1e03ac9c 9eb76fac 45af8e51"
				+ "30c81c46 a35ce411 80000000 00000000");
		ByteString expectedCMACMesC = new ByteString("dfa66747 de9ae630 30ca3261 1497c827");

		// Example 4: Mlen = 512
		ByteString mesD = new ByteString("6bc1bee2 2e409f96 e93d7e11 7393172a"
				+ "ae2d8a57 1e03ac9c 9eb76fac 45af8e51"
				+ "30c81c46 a35ce411 e5fbc119 1a0a52ef"
				+ "f69f2445 df4f9b17 ad2b417b e66c3710");
		ByteString expectedCMACMesD = new ByteString("51f0bebf 7e3b9d92 fc497417 79363cfe");

		ByteString cmacMesA = macGeneration(kTest1, mesA, true);
		System.out.println("CMAC Mes A: " + cmacMesA.toHexString());
		System.out.println("  Succeeded: " + (cmacMesA.equal(expectedCMACMesA)));
		
		ByteString cmacMesB = macGeneration(kTest1, mesB, false);
		System.out.println("CMAC Mes B: " + cmacMesB.toHexString());
		System.out.println("  Succeeded: " + (cmacMesB.equal(expectedCMACMesB)));

		ByteString cmacMesC = macGeneration(kTest1, mesC, true);
		System.out.println("CMAC Mes C: " + cmacMesC.toHexString());
		System.out.println("  Succeeded: " + (cmacMesC.equal(expectedCMACMesC)));

		ByteString cmacMesD = macGeneration(kTest1, mesD, false);
		System.out.println("CMAC Mes D: " + cmacMesD.toHexString());
		System.out.println("  Succeeded: " + (cmacMesD.equal(expectedCMACMesD)));
		
		ByteString PmesA = new ByteString(new byte[0]);
		ByteString PmesB = new ByteString("6bc1bee2 2e409f96 e93d7e11 7393172a");
		ByteString PmesC = new ByteString("6bc1bee2 2e409f96 e93d7e11 7393172a"
				+ "ae2d8a57 1e03ac9c 9eb76fac 45af8e51"
				+ "30c81c46 a35ce411");
		ByteString PmesD = new ByteString("6bc1bee2 2e409f96 e93d7e11 7393172a"
				+ "ae2d8a57 1e03ac9c 9eb76fac 45af8e51"
				+ "30c81c46 a35ce411 e5fbc119 1a0a52ef"
				+ "f69f2445 df4f9b17 ad2b417b e66c3710");

		System.out.println(cmacPadToLength(PmesA, 16).toHexString());
		System.out.println(cmacPadToLength(PmesB, 16).toHexString());
		System.out.println(cmacPadToLength(PmesC, 48).toHexString());
		System.out.println(cmacPadToLength(PmesD, 64).toHexString());
		
		ByteString aKey = new ByteString("f3 f9 37 76 98 70 7b 68 8e af 84 ab e3 9e 37 91");
		ByteString aMes = new ByteString("01 0a cf 38 d6 de ad be ef fe ed");
		System.out.println(cmacPadToLength(aMes, 32).toHexString());
		System.out.println(macGeneration(aKey, cmacPadToLength(aMes, 32), true).toHexString());
		System.out.println(macGeneration(aKey, cmacPadToLength(aMes, 32), false).toHexString());
		
		abu();
		
	}
}
