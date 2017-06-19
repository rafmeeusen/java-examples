package net.meeusen.crypto;

import java.util.Arrays;

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
 * 
 * KDF spec: http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf
 * underlying PRF: AES-CMAC, see http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
 * */
public class Nist800_108Test {

    public byte[] getInputkey() {
        return inputkey;
    }

    public byte[] getFixedInDataBefore() {
        return fixedInDataBefore;
    }

    public byte[] getFixedInDataAfter() {
        return fixedInDataAfter;
    }

    final static int bitsPerByte = 8; 

    public static void main(String[] args) throws Exception {

        /**
         * Test vectors from KDFCTR_gen.txt in CounterMode.zip,
         * found on http://csrc.nist.gov/groups/STM/cavp/key-derivation.html#testing
         * 
         * */
        Nist800_108Test someNistTestVectors[] = new Nist800_108Test[] {
                /* 0 */ new Nist800_108Test(Prf.CMAC_AES128, CtrLocation.BEFORE_FIXED, RLen.R_8_BITS, 128, "dff1e50ac0b69dc40f1051d46c2b069c", null, "c16e6e02c5a3dcc8d78b9ac1306877761310455b4e41469951d9e6c2245a064b33fd8c3b01203a7824485bf0a64060c4648b707d2607935699316ea5", "8be8f0869b3c0ba97b71863d1b9f7813"),
                /* 1 */ new Nist800_108Test(Prf.CMAC_AES128, CtrLocation.BEFORE_FIXED, RLen.R_8_BITS, 128, "e4d94da336fada7c0ee4a9591dd0327a", null, "538fefb2eeb7c50c84bf603a7beddff4bba049f0052c45f13c56e9ae5944eb22d677f280e5a29c588cf40c7c57f7767aad3d595069fb40d02c01f866", "268a1d44ba5a5b1a28b9a611c76671f7"),
                /* 2 */ new Nist800_108Test(Prf.CMAC_AES128, CtrLocation.BEFORE_FIXED, RLen.R_16_BITS, 128, "30ec5f6fa1def33cff008178c4454211", null, "c95e7b1d4f2570259abfc05bb00730f0284c3bb9a61d07259848a1cb57c81d8a6c3382c500bf801dfc8f70726b082cf4c3fa34386c1e7bf0e5471438", "00018fff9574994f5c4457f461c7a67e"),
                /* 3 */ new Nist800_108Test(Prf.CMAC_AES128, CtrLocation.BEFORE_FIXED, RLen.R_24_BITS, 128, "ca1cf43e5ccd512cc719a2f9de41734c", null, "e3884ac963196f02ddd09fc04c20c88b60faa775b5ef6feb1faf8c5e098b5210e2b4e45d62cc0bf907fd68022ee7b15631b5c8daf903d99642c5b831", "1cb2b12326cc5ec1eba248167f0efd58"),
                /* 4 */ new Nist800_108Test(Prf.CMAC_AES128, CtrLocation.BEFORE_FIXED, RLen.R_24_BITS, 320, "26fa0e32e7e08f9b157ebae9f579710f", null, "ceab805efbe0c50a8aef62e59d95e7a54daa74ed86aa9b1ae8abf68b985b5af4b0ee150e83e6c063b59c7bf813ede9826af149237aed85b415898fa8", "f1d9138afcc3db6001eb54c4da567a5db3659fc0ed48e664a0408946bcee0742127c17cabf348c7a"),
                /* 5 */ new Nist800_108Test(Prf.CMAC_AES128, CtrLocation.BEFORE_FIXED, RLen.R_32_BITS, 128, "c10b152e8c97b77e18704e0f0bd38305", null, "98cd4cbbbebe15d17dc86e6dbad800a2dcbd64f7c7ad0e78e9cf94ffdba89d03e97eadf6c4f7b806caf52aa38f09d0eb71d71f497bcc6906b48d36c4", "26faf61908ad9ee881b8305c221db53f"),
                /* 6 */ new Nist800_108Test(Prf.CMAC_AES128, CtrLocation.AFTER_FIXED, RLen.R_8_BITS, 128, "e61a51e1633e7d0de704dcebbd8f962f", "5eef88f8cb188e63e08e23c957ee424a3345da88400c567548b57693931a847501f8e1bce1c37a09ef8c6e2ad553dd0f603b52cc6d4e4cbb76eb6c8f", null, "63a5647d0fe69d21fc420b1a8ce34cc1"),
                /* 7 */ new Nist800_108Test(Prf.CMAC_AES192, CtrLocation.BEFORE_FIXED, RLen.R_8_BITS, 128, "53d1705caab7b06886e2dbb53eea349aa7419a034e2d92b9", null, "b120f7ce30235784664deae3c40723ca0539b4521b9aece43501366cc5df1d9ea163c602702d0974665277c8a7f6a057733d66f928eb7548cf43e374", "eae32661a323f6d06d0116bb739bd76a"),
                /* 8 */ new Nist800_108Test(Prf.CMAC_AES192, CtrLocation.BEFORE_FIXED, RLen.R_24_BITS, 128, "f7c1e0682a12f1f17d23dc8af5c463b8aa28f87ed82fad22", null, "890ec4966a8ac3fd635bd264a4c726c87341611c6e282766b7ffe621080d0c00ac9cf8e2784a80166303505f820b2a309e9c3a463d2e3fd4814e3af5", "a71b0cbe30331fdbb63f8d51249ae50b"),
                /* 9 */ new Nist800_108Test(Prf.CMAC_AES256, CtrLocation.BEFORE_FIXED, RLen.R_8_BITS, 128, "aeb7201d055f754212b3e497bd0b25789a49e51da9f363df414a0f80e6f4e42c", null, "11ec30761780d4c44acb1f26ca1eb770f87c0e74505e15b7e456b019ce0c38103c4d14afa1de71d340db51410596627512cf199fffa20ef8c5f4841e", "2a9e2fe078bd4f5d3076d14d46f39fb2"),
                /*10 */ new Nist800_108Test(Prf.CMAC_AES256, CtrLocation.BEFORE_FIXED, RLen.R_16_BITS, 128, "4df60800bf8e2f6055c5ad6be43ee3deb54e2a445bc88a576e111b9f7f66756f", null, "962adcaf12764c87dad298dbd9ae234b1ff37fed24baee0649562d466a80c0dcf0a65f04fe5b477fd00db6767199fa4d1b26c68158c8e656e740ab4d", "eca99d4894cdda31fe355b82059a845c"),
                /*11 */ new Nist800_108Test(Prf.CMAC_AES256, CtrLocation.AFTER_FIXED, RLen.R_32_BITS, 320, "a487f6ae25608d71b98bd7f7973fa68871b91fb59f703a2e4684d3b98c4309fe", "b353d8e8558b52023882646d9271e245ea5c3684806d726858227dbae641385f4dd122907abb9005f59584f7bf859e0f19a99f52b2f15fffbed3499f", null, "9820f408e23d1c05638e36540e18832659691471bf215e68f535d66e6b482362902fcdda1818a01f"),                
                /*12 */ new Nist800_108Test(Prf.CMAC_AES128, CtrLocation.MIDDLE_FIXED, RLen.R_8_BITS, 128, "b6e04abd1651f8794d4326f4c684e631", "93612f7256c46a3d856d3e951e32dbf15fe11159d0b389ad38d603850fee6d18d22031435ed36ee20da76745fbea4b10fe1e", "99322aae605a5f01e32b", "dcb1db87a68762c6b3354779fa590bef"),
                /*13*/ new Nist800_108Test(Prf.CMAC_AES128, CtrLocation.MIDDLE_FIXED, RLen.R_32_BITS, 128, "90e33a1e76adedcabd2214326be71abf", "3d2f38c571575807eecd0ec9e3fd860fb605f0b17139ce01904abba7ae688a50e620341787f69f00b872343f42b18c979f6f", "8885034123cb45e27440", "9e2156cd13e079c1e6c6379f9a55f433"),                
        };

        System.out.println("Running " + someNistTestVectors.length + " NIST test vectors.");
        int testCounter = 0; 
        for ( Nist800_108Test t : someNistTestVectors ) {
            System.out.print(testCounter + ":" + t + ": ");
            boolean hasPassed = t.checkTestVector();                 
            if ( ! hasPassed ) {
                System.out.println("ERROR.");    
            } else {
                System.out.println("OK.");
            }
            testCounter++;  
        }
        System.out.println("DONE running NIST test vectors.");

    }

    public enum Prf {
        CMAC_AES128, CMAC_AES256, CMAC_AES192, ;
        public String toString() {
            switch (this) {
            case CMAC_AES128: return "CMAC_AES128"; 
            case CMAC_AES192: return "CMAC_AES192"; 
            case CMAC_AES256: return "CMAC_AES256"; 
            default: throw new IllegalArgumentException(); 

            }
        }
    }

    public enum CtrLocation {         
        BEFORE_FIXED, MIDDLE_FIXED, AFTER_FIXED;   
        public String toString() {
            switch (this) {
            case BEFORE_FIXED: return "BEFORE_FIXED"; 
            case MIDDLE_FIXED: return "MIDDLE_FIXED"; 
            case AFTER_FIXED: return "AFTER_FIXED"; 
            default: throw new IllegalArgumentException(); 

            }
        }
    }

    public enum RLen {
        R_8_BITS, R_16_BITS, R_24_BITS, R_32_BITS ;
        public String toString() {
            switch (this) {           
            case R_8_BITS: return "R_8_BITS"; 
            case R_16_BITS: return "R_16_BITS"; 
            case R_24_BITS: return "R_24_BITS"; 
            case R_32_BITS: return "R_32_BITS"; 
            default: throw new IllegalArgumentException(); 
            }
        }
    }


    private Prf prf;
    private CtrLocation ctrloc;

    /* r : An integer, smaller or equal to 32, whose value is the length of the
    binary representation of the counter i when i is an input in counter
    mode or (optionally) in feedback mode and double-pipeline
    iteration mode of each iteration of the PRF. */     
    private RLen rValue;

    private int L_outputbits;
    private byte[] inputkey;
    private byte[] fixedInDataBefore;
    private byte[] fixedInDataAfter;
    private byte[] calculatedOutput;
    private byte[] expectedOutput;

    /**
     * Constructor with byte[].  
     * @throws Exception 
     * */
    public Nist800_108Test(Prf prf, CtrLocation ctrloc, RLen rEnum, int nrOutputBits, byte[] argKi,
            byte[] argFixedinputBefore, byte[] argFixedinputAfter, byte[] argKo) throws Exception {

        this.prf = prf;
        this.ctrloc = ctrloc;
        this.rValue = rEnum;        
        this.L_outputbits = nrOutputBits;

        if ( argKi == null ) throw new Exception ("Error. Need input key.");        
        this.inputkey = argKi.clone(); 

        switch(this.ctrloc) {
        case BEFORE_FIXED:
            if ( argFixedinputBefore != null ) throw new Exception("Error. No fixed data before counter in BEFORE_FIXED.");            
            if ( argFixedinputAfter == null ) throw new Exception("Error. Need fixed data after counter in BEFORE_FIXED."); 
            break;
        case MIDDLE_FIXED:
            if ( argFixedinputBefore == null ) throw new Exception("Error. Need fixed data before counter in MIDDLE_FIXED.."); 
            if ( argFixedinputAfter == null ) throw new Exception("Error. Need fixed data after counter in MIDDLE_FIXED."); 
            break;
        case AFTER_FIXED:
            if ( argFixedinputBefore == null ) throw new Exception("Error. Need fixed data before counter in AFTER_FIXED.."); 
            if ( argFixedinputAfter != null ) throw new Exception("Error. No fixed data after counter in AFTER_FIXED.");             
            break;
        }

        if ( argFixedinputBefore != null ) this.fixedInDataBefore = argFixedinputBefore.clone(); 
        if ( argFixedinputAfter != null ) this.fixedInDataAfter = argFixedinputAfter.clone();        
        if ( argKo != null ) {
            this.expectedOutput = argKo.clone();
            // some checks
            int nrOutputBytes = this.L_outputbits/bitsPerByte;         
            if ( nrOutputBytes != this.expectedOutput.length ) {
                throw new Error("Error, L value must be equal to given output key size.");
            }            
        }
    }

    /**
     * Constructor with String instead of byte[].
     * @throws Exception 
     * */
    public Nist800_108Test(Prf prf, CtrLocation ctrloc, RLen rEnum, int nrOutputBits, String ki,
            String fixedinputBefore, String fixedinputAfter, String ko) throws Exception {
        this(prf,ctrloc, rEnum, nrOutputBits, new ByteString(ki).getBytes(),  new ByteString(fixedinputBefore).getBytes(), new ByteString(fixedinputAfter).getBytes(),  new ByteString(ko).getBytes());
    }

    /**
     * summarize some KDF params in a string
     * */
    public String toString() {
        return this.prf.toString() +" "+ this.ctrloc +" "+ this.rValue;
    }

    public void calculateOuput() {
        int inKeyLenBits = this.inputkey.length*bitsPerByte;
        switch (this.prf) {
        case CMAC_AES128: if (inKeyLenBits!=128) throw new Error(); break;
        case CMAC_AES192: if (inKeyLenBits!=192) throw new Error(); break;
        case CMAC_AES256:if (inKeyLenBits!=256) throw new Error(); break;
        }

        int rbits=0;
        switch(this.rValue) {
        case R_8_BITS: rbits=8;break;
        case R_16_BITS: rbits=16;break;
        case R_24_BITS: rbits=24;break;
        case R_32_BITS: rbits=32;break;        
        }

        DerivationParameters myparams =null;
        switch(this.ctrloc) {
        /**
         * Different constructors depending on concatenation strategy:   
         * http://javadox.com/org.bouncycastle/bcprov-jdk15on/1.51/org/bouncycastle/crypto/params/KDFCounterParameters.html 
         * */
        case BEFORE_FIXED:
            if ( this.fixedInDataAfter == null ) {
                throw new Error("Should not be possible, counter BEFORE_FIXED but not data after counter.");
            }
            myparams = new KDFCounterParameters(this.inputkey, null, this.fixedInDataAfter, rbits);
            break;
        case MIDDLE_FIXED:
            myparams = new KDFCounterParameters(this.inputkey, this.fixedInDataBefore,this.fixedInDataAfter,  rbits);
            break;
        case AFTER_FIXED:
            if ( this.fixedInDataBefore == null ) {
                throw new Error("Should not be possible, counter AFTER_FIXED but not data before counter.");
            }
            myparams = new KDFCounterParameters(this.inputkey, this.fixedInDataBefore,null,  rbits);
            break;
        }

        BlockCipher underlyingCipher = new AESEngine();
        Mac aesCbcMac = new CMac(underlyingCipher);
        KDFCounterBytesGenerator mygen = new KDFCounterBytesGenerator(aesCbcMac);
        mygen.init(myparams);
        this.calculatedOutput = new byte[this.L_outputbits/bitsPerByte];
        int offset=0;
        mygen.generateBytes(calculatedOutput, offset, calculatedOutput.length);
    }

    /**
     * Do a KDF, and compare with expected output.
     * */
    boolean checkTestVector() {
        calculateOuput();        
        return Arrays.equals(this.calculatedOutput, this.expectedOutput);
    }

    public byte[] getCalculatedOutput() {
        return calculatedOutput;
    }

    public byte[] getExpectedOutput() {
        return expectedOutput;
    }
}
