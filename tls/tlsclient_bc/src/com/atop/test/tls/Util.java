package com.atop.test.tls;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.tls.Certificate;

public class Util {
  public static PrivateKey loadKey(String keyFile, PrintStream dbg)
  throws FileNotFoundException, IOException, NoSuchAlgorithmException,
  InvalidKeySpecException
  {
    InputStream  bis         = null;
    File         privKeyFile = new File(keyFile);

    bis                 = new BufferedInputStream( new FileInputStream(privKeyFile) );
    byte[] privKeyBytes = new byte[(int)privKeyFile.length()];
    bis.read(privKeyBytes);
    bis.close();
    PrivateKey      privKey = null;

    EncodedKeySpec  ks      = new PKCS8EncodedKeySpec(privKeyBytes);

    try {
      privKey = Util.decodePrivateKey(ks, "RSA", dbg);
    }
    catch ( Exception e ) {
      e.printStackTrace();
      dbg.println("Could not load key from PKCS8 store as RSA, trying EC");
      privKey = Util.decodePrivateKey(ks, "EC", dbg);
    }
    return privKey;
  }

  public static Certificate loadCertificates(
    String fileName) throws FileNotFoundException,
  CertificateException, IOException
  {
    FileInputStream  certificateStream =
      new FileInputStream(fileName);

    try {
      CertificateFactory  cf = CertificateFactory.getInstance("X.509");

      // uugh, first parse into a JCE certificate, then encode into DER and parse into BC certificate

      java.security.cert.Certificate          tempCert  = cf.generateCertificate(certificateStream);
      ASN1Primitive                           asn1      = ASN1Sequence.fromByteArray( tempCert.getEncoded() );
      org.bouncycastle.asn1.x509.Certificate  tempCert2 = org.bouncycastle.asn1.x509.Certificate.getInstance(
        asn1);
      System.out.println( tempCert2.getIssuer() );
      return new Certificate(new org.bouncycastle.asn1.x509.Certificate[] { tempCert2 });

// return Certificate.parse( new ByteArrayInputStream( tempCert.getEncoded() ) );
    } finally {
      certificateStream.close();
    }
  }

  public static PrivateKey decodePrivateKey(EncodedKeySpec ks, String algorithm, PrintStream dbg)
  throws NoSuchAlgorithmException, InvalidKeySpecException
  {
    dbg.println( "Loading PKCS8 key in format " + ks.getFormat() );
    KeyFactory  keyFactory = KeyFactory.getInstance(algorithm);
    PrivateKey  privKey    = (PrivateKey)keyFactory.generatePrivate(ks);
    return privKey;
  }
}
