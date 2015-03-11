package net.meeusen.net.example;

import java.io.IOException;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.DefaultTlsSignerCredentials;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TlsContext;
import org.bouncycastle.crypto.tls.TlsServerProtocol;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

public class TlsServerBc {
  static {
    /**
     * Try to add bouncycastle provider. This avoids having to edit
     * java.security. It will silently fail if bouncycastle is not available on
     * the classpath.
     */
    try {
      Class     provClass = Class
                            .forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
      Provider  prov      = (Provider)provClass.newInstance();
      Security.addProvider(prov);
    }
    catch ( Throwable e ) {
      // System.err.println("Could not load bouncycastle provider");
    }
  }

  private static SecureRandom  secureRandom = new SecureRandom();
  private static final int     SERVER_PORT  = 8748;
  private static PrivateKey    privateKey   = null;
  private static Certificate   bcCert       = null;
  private static String        keyFile      = "C:\\cygwin\\home\\RafMe\\tls_server\\keystores\\localhost_rsa.key";
  private static String        certFile     = "C:\\cygwin\\home\\RafMe\\tls_server\\keystores\\localhost_rsa.cer";

  // new Certificate(
  // new org.bouncycastle.asn1.x509.Certificate[] { new
  // X509V3CertificateStrategy()
  // .selfSignedCertificateHolder(keyPair).toASN1Structure() });

  private static TlsSignerCredentials tlsSignerCredentials(TlsContext context)
  throws IOException
  {
    return new DefaultTlsSignerCredentials( context, bcCert,
                                            PrivateKeyFactory.createKey( privateKey.getEncoded() ) );
  }

  public static void main(String[] args) throws IOException,
  NoSuchAlgorithmException, InvalidKeySpecException, CertificateException
  {
    privateKey = Util.loadKey(keyFile, System.out);
    bcCert     = Util.loadCertificates(certFile);
    ServerSocket  serverSocket = new ServerSocket(SERVER_PORT);
    try {
      while ( true ) {
        Socket             socket            = serverSocket.accept();

        TlsServerProtocol  tlsServerProtocol = new TlsServerProtocol(
          socket.getInputStream(), socket.getOutputStream(), secureRandom);

        DefaultTlsServer  tlsServer = new DefaultTlsServer() {
          protected TlsSignerCredentials getRSASignerCredentials()
          throws IOException
          {
            return tlsSignerCredentials(context);
          }

// protected ProtocolVersion getMaximumVersion()
// {
// return ProtocolVersion.TLSv12;
// }
        };

        tlsServerProtocol.accept(tlsServer);
        new PrintStream( tlsServerProtocol.getOutputStream() )
        .println("Hello TLS");
      }
    } finally {
      if ( serverSocket != null ) {
        serverSocket.close();
      }
    }
  }
}
