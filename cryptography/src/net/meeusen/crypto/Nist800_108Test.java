package net.meeusen.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KDFCounterParameters;

import net.meeusen.util.ByteString;


/**
 * Implement test for NIST 800-108 key derivation. 
 * Based on AES-CMAC PRF.
 * Doing counter Mode KDF. 
 * */
public class Nist800_108Test {

    /* r : An integer, smaller or equal to 32, whose value is the length of the
    binary representation of the counter i when i is an input in counter
    mode or (optionally) in feedback mode and double-pipeline
    iteration mode of each iteration of the PRF. */     
    private int r; 

    public Nist800_108Test(int rValue) {
        this.r = rValue; 
    }

    public static void main(String[] args) {

        System.out.println("Testing KDF for all-zero bits key, 256 bits.");
        int nrInputKeyBytes = 256/8; 
        byte[] inputKey = new byte[nrInputKeyBytes]; 

        int myRValue = 16;
        Nist800_108Test mytest = new Nist800_108Test(myRValue); 
        String label = "CRYPTO STORAGE HW Crypto Derived key SYMR";
        String context = "CRYPTO STORAGE HW Crypto key derived from SHK SYMR";

        int outputSize = 256/8; // note MUST match 0x0100 while hardcoded below
        byte[] derivedKey = mytest.deriveKey(inputKey, label, context, outputSize);
        System.out.println(new ByteString(derivedKey));

    }

    /**
     * Do a KDF.
     * 
     * @param inputKey: byte[] with key bits
     * @param label: String used as label in KDF
     * @param context: String used as context in KDF
     * @param outputSize: number of key bytes to derive 
     * 
     * @returns Derived key
     * */
    private byte[] deriveKey(byte[] inputKey, String label, String context, int outputSize) {

        BlockCipher underlyingCipher = new AESEngine();
        Mac aesCbcMac = new CMac(underlyingCipher);
        KDFCounterBytesGenerator mygen = new KDFCounterBytesGenerator(aesCbcMac);

        ByteString labelBytes = new ByteString( label.getBytes() ); 
        ByteString zeroByte = new ByteString("00");  
        ByteString contextBytes = new ByteString( context.getBytes() );
        ByteString encodedLength = new ByteString("0100"); // note: must match outputSize, currently hardcoded.

        /* NIST spec: K(i) := PRF (KI, [i]2 || Label || 0x00 || Context || [L]2)
         * where [i]2 is added by BC KDFCounterBytesGenerator class. */ 
        byte[] fixedInputData = ByteString.concat(new ByteString[]{labelBytes, zeroByte, contextBytes, encodedLength}).getBytes();

        /* Using constructor case 1, counter at beginning of fixedInputData */
        byte[] partOfFixedInputDataBeforeCounter = null; 
        byte[] partOfFixedInputDataAfterCounter = fixedInputData;
        DerivationParameters myparams = new KDFCounterParameters(inputKey, partOfFixedInputDataBeforeCounter, partOfFixedInputDataAfterCounter, r);
        mygen.init(myparams);

        byte[] derivedKey = new byte[outputSize];
        int offset=0;
        mygen.generateBytes(derivedKey, offset, derivedKey.length);

        return derivedKey;
    }


}
