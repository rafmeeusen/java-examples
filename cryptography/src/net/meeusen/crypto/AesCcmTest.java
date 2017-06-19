package net.meeusen.crypto;

import java.util.Arrays;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import net.meeusen.util.ByteString;


/**
 * Wrappers around BC AES-CCM, with easy API to validate NIST test vectors for AES-CCM.  * 
 * */
public class AesCcmTest {

    public byte[] getCalculatedOutput() {
        return calculatedOutput;
    }

    public byte[] getPayLoad() {
        return payLoad;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    private CCMBlockCipher ccmCipher;
    private KeyParameter keyParameter;
    private int TlenBytes; 
    private byte[] key;
    private byte[] nonce;
    private byte[] Adata;
    private byte[] payLoad;
    private byte[] cipherText;
    private TestType type;

    // following can be either payload or ciphertext depending on test type.    
    private byte[] calculatedOutput; 

    public String toString() {
        return this.type.toString() + " Tlen:" + TlenBytes + " KeyLen:" + key.length + " Nlen: " + nonce.length
                + " Alen: " + Adata.length + " Plen:" + payLoad.length;
    }

    /**
     * Constructor with (hex) String arguments
     * @throws Exception 
     * */
    public AesCcmTest(TestType type, int argTlenBytes, String Key, String Nonce, String argAdata, String argPayload,
            String argCipherText) throws Exception {
        this(type, argTlenBytes, new ByteString(Key).getBytes(), new ByteString(Nonce).getBytes(),
                new ByteString(argAdata).getBytes(), new ByteString(argPayload).getBytes(),
                new ByteString(argCipherText).getBytes());
    }

    /**
     * Constructor with byte[] arguments
     * @throws Exception 
     * */
    public AesCcmTest(TestType argTestType, int argTlenBytes, byte[] Key, byte[] Nonce, byte[] argAdata, byte[] argPayload,
            byte[] argCipherText) throws Exception {

        switch ( argTestType ) {
        case ENCRYPT:
            // need payload to encrypt something
            if ( argPayload == null ) throw new Exception ("Cannot encrypt without payload.");             
            break;
        case DECRYPT:
            // need CT to decrypt something
            if ( argCipherText == null ) throw new Exception ("Cannot decrypt without ciphertext."); 
            break;
        default:
            throw new Exception("not allowed");
        }

        this.type = argTestType;
        this.ccmCipher = new CCMBlockCipher(new AESEngine());
        this.keyParameter = new KeyParameter(Key);
        this.TlenBytes = argTlenBytes;
        this.key = Key.clone();
        this.nonce = Nonce.clone();

        // some of these are optional: 
        if ( argAdata != null ) this.Adata = argAdata.clone();
        if ( argPayload != null ) this.payLoad = argPayload.clone();
        if ( argCipherText != null ) this.cipherText = argCipherText.clone();
    }

    /**
     * encrypt or decrypt depending on test type. 
     * store result in instance variable calculatedOutput
     * result is NOT interpreted, not compared to any expected output...
     * @throws Exception 
     * */
    public void doCalculate() throws Exception{
        boolean isEncryption;
        byte[] testInput=null;
        //byte[] testOutput=null;

        switch ( this.type ) {
        case ENCRYPT:
            isEncryption = true;
            testInput = this.payLoad;
            break;
        case DECRYPT:
            isEncryption = false;
            testInput = this.cipherText;
            break;
        default:
            throw new Exception("not allowed");
        }

        /** Java docs:
         * http://javadox.com/org.bouncycastle/bcprov-jdk15on/1.51/org/bouncycastle/crypto/modes/CCMBlockCipher.html 
         * http://javadox.com/org.bouncycastle/bcprov-jdk15on/1.51/org/bouncycastle/crypto/params/AEADParameters.html
         */

        // init
        int TlenBits = this.TlenBytes * 8;
        ccmCipher.init(isEncryption, new AEADParameters(this.keyParameter, TlenBits, this.nonce, this.Adata));

        // process
        int inputOffset = 0;
        int outputOffset = 0;
        int expectedOutputSize = this.ccmCipher.getOutputSize(testInput.length); 
        this.calculatedOutput = new byte[expectedOutputSize]; 
        int nrProcessBytes = this.ccmCipher.processPacket(testInput, inputOffset, testInput.length, this.calculatedOutput,
                outputOffset);

        if ( nrProcessBytes != expectedOutputSize ) {
            throw new Exception("unexpected internal error or misunderstanding...");
        }

        // strange, when I do another doFinal, there is data coming out, not
        // expected, and not sure what this data means...
        // byte[] finalOutput = new byte[ccmCipher.getOutputSize(0)];
        // int nrOutputBytes =ccmCipher.doFinal(finalOutput, 0);
        // if ( nrOutputBytes != finalOutput.length) {
        // throw new Error("this should not happen.");
        // }
    }

    /**
     * calculate AND compare with expected output
     * */
    public boolean checkTestVector() throws Exception  {

        this.doCalculate();

        byte[] expectedOutput=null;
        switch ( this.type ) {
        case ENCRYPT:
            expectedOutput = this.cipherText; 
            break;
        case DECRYPT:
            expectedOutput = this.payLoad;
            break;
        default:
            throw new Exception("not allowed");
        }

        return Arrays.equals(this.calculatedOutput, expectedOutput);
    }

    /**
     * Check some CCM test vectors NIST.
     * */
    public static void main(String[] args) throws Exception {
        /**
         * 
         * http://csrc.nist.gov/groups/STM/cavp/block-cipher-modes.html#test-
         * vectors explained in :
         * http://csrc.nist.gov/groups/STM/cavp/documents/mac/CCMVS.pdf (ccmvs =
         * ccm validation system)
         * 
         * summary of test vector types: DVPT : Decryption-Verification Process
         * Test VADT : variable associated data test VNT : variable nonce test
         * VPT : variable playload test VTT : variable tag test
         */
        AesCcmTest someNistAesCcmTestVectors[] = new AesCcmTest[] {
                // from VPT256.rsp NIST file:
                /* 0 */ new AesCcmTest(TestType.ENCRYPT, 16,
                        "7da6ef35ad594a09cb74daf27e50a6b30d6b4160cf0de41ee32bbf2a208b911d",
                        "98a32d7fe606583e2906420297",
                        "217d130408a738e6a833931e69f8696960c817407301560bbe5fbd92361488b4",
                        "b0053d1f490809794250d856062d0aaa92",
                        "a6341ee3d60eb34a8a8bc2806d50dd57a3f628ee49a8c2005c7d07d354bf80994d"),
                /* 1 */ new AesCcmTest(TestType.ENCRYPT, 16,
                        "c6c14c655e52c8a4c7e8d54e974d698e1f21ee3ba717a0adfa6136d02668c476",
                        "291e91b19de518cd7806de44f6",
                        "b4f8326944a45d95f91887c2a6ac36b60eea5edef84c1c358146a666b6878335", "",
                        "ca482c674b599046cc7d7ee0d00eec1e"),
                /* 2 */ new AesCcmTest(TestType.ENCRYPT, 16,
                        "cc49d4a397887cb57bc92c8a8c26a7aac205c653ef4011c1f48390ad35f5df14",
                        "6df8c5c28d1728975a0b766cd7",
                        "080f82469505118842e5fa70df5323de175a37609904ee5e76288f94ca84b3c5", "1a",
                        "a5f24e87a11a95374d4c190945bf08ef2f"),
                /* 3 */ new AesCcmTest(TestType.ENCRYPT, 16,
                        "62b82637e567ad27c3066d533ed76e314522ac5c53851a8c958ce6c64b82ffd0",
                        "5bc2896d8b81999546f88232ab",
                        "fffb40b0d18cb23018aac109bf62d849adca42629d8a9ad1299b83fe274f9a63", "87294078",
                        "2bc22735ab21dfdcfe95bd83592fb6b4168d9a23"),

                // from VNT256.rsp:
                /* 4 */ new AesCcmTest(TestType.ENCRYPT, 16, "553521a765ab0c3fd203654e9916330e189bdf951feee9b44b10da208fee7acf",
                        "aaa23f101647d8", "a355d4c611812e5f9258d7188b3df8851477094ffc2af2cf0c8670db903fbbe0",
                        "644eb34b9a126e437b5e015eea141ca1a88020f2d5d6cc2c",
                        "27ed90668174ebf8241a3c74b35e1246b6617e4123578f153bdb67062a13ef4e986f5bb3d0bb4307"),
                /* 5 */ new AesCcmTest(TestType.ENCRYPT, 16,
                        "4a75ff2f66dae2935403cce27e829ad8be98185c73f8bc61d3ce950a83007e11",
                        "ef284d1ddf35d1d23de6a2f84b",
                        "0b90b3a087b9a4d3267bc57c470695ef7cf658353f2f680ee00ccc32c2ba0bdc",
                        "bf35ddbad5e059169468ae8537f00ec790cc038b9ed0a5d7",
                        "b702ad593b4169fd7011f0288e4e62620543095186b32c122389523b5ccc33c6b41b139108a99442"),

                // from VADT128.rsp:
                /* 6 */ new AesCcmTest(TestType.ENCRYPT, 16, "d24a3d3dde8c84830280cb87abad0bb3", "f1100035bb24a8d26004e0e24b",
                        "", "7c86135ed9c2a515aaae0e9a208133897269220f30870006",
                        "1faeb0ee2ca2cd52f0aa3966578344f24e69b742c4ab37ab1123301219c70599b7c373ad4b3ad67b"),
                /* 7 */ new AesCcmTest(TestType.ENCRYPT, 16, "5a33980e71e7d67fd6cf171454dc96e5",
                        "33ae68ebb8010c6b3da6b9cb29",
                        "eca622a37570df619e10ebb18bebadb2f2b49c4d2b2ff715873bb672e30fc0ff",
                        "a34dfa24847c365291ce1b54bcf8d9a75d861e5133cc3a74",
                        "7a60fa7ee8859e283cce378fb6b95522ab8b70efcdb0265f7c4b4fa597666b86dd1353e400f28864"),

                // from VTT192.rsp:
                /* 8 */ new AesCcmTest(TestType.ENCRYPT, 4, "11fd45743d946e6d37341fec49947e8c70482494a8f07fcc",
                        "c6aeebcb146cfafaae66f78aab",
                        "7dc8c52144a7cb65b3e5a846e8fd7eae37bf6996c299b56e49144ebf43a1770f",
                        "ee7e6075ba52846de5d6254959a18affc4faf59c8ef63489",
                        "137d9da59baf5cbfd46620c5f298fc766de10ac68e774edf1f2c5bad"),
                /* 9 */ new AesCcmTest(TestType.ENCRYPT, 14, "d2d4482ea8e98c1cf309671895a16610152ce283434bca38",
                        "6ee177d48f59bd37045ec03731",
                        "d4cd69b26ea43596278b8caec441fedcf0d729d4e0c27ed1332f48871c96e958",
                        "e4abe343f98a2df09413c3defb85b56a6d34dba305dcce46",
                        "7e8f27726c042d73aa6ebf43217395202e0af071eacf53790065601bb59972c35b580852e684"),

                // from DVPT256.rsp:
                /* 10 */ new AesCcmTest(TestType.DECRYPT, 4, "af063639e66c284083c5cf72b70d8bc277f5978e80d9322d99f2fdc718cda569",
                        "a544218dadd3c1", "", "d3d5424e20fbec43ae495353ed830271515ab104f8860c98",
                        "64a1341679972dc5869fcf69b19d5c5ea50aa0b5e985f5b722aa8d59"),
                /* 11 */ new AesCcmTest(TestType.DECRYPT, 4,
                        "a4bc10b1a62c96d459fbaf3a5aa3face7313bb9e1253e696f96a7a8e36801088",
                        "a544218dadd3c10583db49cf39",
                        "3c0e2815d37d844f7ac240ba9d6e3a0b2a86f706e885959e09a1005e024f6907", "", "866d4227"),
                /* 12 */ new AesCcmTest(TestType.DECRYPT, 16,
                        "314a202f836f9f257e22d8c11757832ae5131d357a72df88f3eff0ffcee0da4e",
                        "a544218dadd3c10583db49cf39",
                        "3c0e2815d37d844f7ac240ba9d6e3a0b2a86f706e885959e09a1005e024f6907",
                        "e8de970f6ee8e80ede933581b5bcf4d837e2b72baa8b00c3",
                        "8d34cdca37ce77be68f65baf3382e31efa693e63f914a781367f30f2eaad8c063ca50795acd90203"),
        };

        System.out.println("Running " + someNistAesCcmTestVectors.length + " NIST test vectors.");
        int testCounter = 0;
        for (AesCcmTest t : someNistAesCcmTestVectors) {
            System.out.print(testCounter + ":" + t + ": ");
            boolean hasPassed = t.checkTestVector();
            if (!hasPassed) {
                System.out.println("ERROR.");
            } else {
                System.out.println("OK.");
            }
            testCounter++;
        }
        System.out.println("DONE running NIST test vectors.");


    }

    public enum TestType {
        ENCRYPT, DECRYPT;
        public String toString() {
            switch (this) {
            case ENCRYPT:
                return "ENCRYPT";
            case DECRYPT:
                return "DECRYPT";
            default:
                throw new IllegalArgumentException();

            }
        }
    }

}
