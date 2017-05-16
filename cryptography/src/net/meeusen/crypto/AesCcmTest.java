package net.meeusen.crypto;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import net.meeusen.util.ByteString;

public class AesCcmTest {

    private byte[] key; 
    private byte[] nonce;
    private int macsize;

    public AesCcmTest(byte[] key, byte[] nonce, int macsize) {
        this.key = key;
        this.nonce=nonce;
        this.macsize=macsize;
    }

    public static void main(String[] args) throws IllegalStateException, InvalidCipherTextException {
        // key: coming from KDF in MacTests, for Ki=0x00..0
        byte[] key = new ByteString("623148bda6dc345cb1a74b97c9c93d910a54d91a7125d59e4ba51a7a98c7dfbc").getBytes();
        
        int macsize = 16*8;

        // f0 e0 4a e6 9a cd 6e 06 cd 9f 1d 33 f3 6c ab 3c c7 35 65 69 61 9d f5 a5 8d 1a d9 9d 5d a3 96 20 62 af 63 7e d1 e5 f4 9c 90 d4 82 c8 d5 17 c5 e3 75 52 7e 0c a1 4e 0b 51

        ByteString generatedTzKey = new ByteString("f0 e0 4a e6 9a cd 6e 06 cd 9f 1d 33 f3 6c ab 3c c7 35 65 69 61 9d f5 a5 8d 1a d9 9d 5d a3 96 20 62 af 63 7e d1 e5 f4 9c 90 d4 82 c8 d5 17 c5 e3 75 52 7e 0c a1 4e 0b 51");
        System.out.println("len of tz key: " + generatedTzKey.length());
        
        // suppose nonce is first: 
//        ByteString nonce = generatedTzKey.slice(0, 7);
//        ByteString actualct = generatedTzKey.slice(8, 39);
//        ByteString tag = generatedTzKey.slice(40, 55);

        // if nonce is last: 
        
        ByteString actualct = generatedTzKey.slice(0, 31);
        ByteString tag = generatedTzKey.slice(32, 47);
        ByteString nonce = generatedTzKey.slice(48, 55);
        
        ByteString ct_with_tag = generatedTzKey.slice(0,47);
        
        byte[] cipherText = new ByteString("23bb343a1859bfba393acffc655ce60ba4b149a73c38b26482953dd1ad75ee27").getBytes();
        //byte[] nonce = new ByteString ("0102030405060708").getBytes();

        new AesCcmTest(key, nonce.getBytes(), macsize).runDecrypt(ct_with_tag.getBytes());

    }

    private void runDecrypt(byte[] cipherText) throws IllegalStateException, InvalidCipherTextException {
        System.out.println("Implementing AES-CCM");
        System.out.println("key: " + new ByteString(key));

        
        CCMBlockCipher ccm = new CCMBlockCipher(new AESEngine());
        KeyParameter keyParam = new KeyParameter(key);        
        
        boolean isEncryption = false;
        ccm.init(isEncryption, new AEADParameters(keyParam, macsize, nonce, null));
        
        int offset=0;
        byte[] plaintext = ccm.processPacket(cipherText, offset, cipherText.length);
        System.out.println(new ByteString(plaintext));
        //ccm.doFinal(cipherText, paramInt);

    }

}
