package net.meeusen.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

public class CipherGetOuputSizeBehavior {

    public void run()
            throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {

        String provider = "SunJCE";
        String cipheralgo = "AES/CBC/PKCS5Padding";
        System.out.println("testing getOutputSize() on Cipher " + cipheralgo + " from " + provider);

        byte[] iv = new byte[] { 00, 01, 02, 03, 04, 05, 06, 07, 0x8, 0x9, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
        Cipher encryptor = Cipher.getInstance(cipheralgo, provider);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        SecretKey generatedkey = kg.generateKey();
        Key keyInUse = generatedkey;

        int inputlen = 8;
        int outputlen_minusbytes = 6;

        byte[] inputbuffer = new byte[inputlen];
        encryptor.init(Cipher.ENCRYPT_MODE, keyInUse, ivParameterSpec);
        int getOSresult = encryptor.getOutputSize(inputbuffer.length);
        System.out.println("getOuputSize() result: " + getOSresult);

        byte[] outputbuffer = new byte[getOSresult - outputlen_minusbytes];
        System.out.println("actual output buffer size in update call: " + outputbuffer.length);
        encryptor.update(inputbuffer, 0, inputlen, outputbuffer);
        System.out.println(" seemed to work");

    }

    public static void main(String[] args)
            throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
        new CipherGetOuputSizeBehavior().run();
    }

}
