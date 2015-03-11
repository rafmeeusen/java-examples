package net.meeusen.net.example;


import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.math.BigInteger;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import net.meeusen.util.ByteString;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;


public class TlsClientBc {

	private static Certificate getClientCert() {
		Certificate cert=null;
		try {

			cert = Util.loadCertificates("C:\\cygwin\\home\\RafMe\\tls_server\\keystores\\client_ec.cer"); 

			//InputStream is = new FileInputStream(new File("C:\\cygwin\\home\\RafMe\\tls_server\\keystores\\client_ec.cer")); 
			//cert = Certificate.parse(is);
		} catch (IOException e) {									
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} 
		return cert; 
	}

	private static AsymmetricKeyParameter getClientPrivKey() throws IOException {
		AsymmetricKeyParameter privateKey = null;

		try {
			Reader rdr = new FileReader(new File("C:\\cygwin\\home\\RafMe\\tls_server\\keystores\\client_ec.key"));
			PemReader pemReader = new PemReader(rdr);

			PemObject pem = null;

			BigInteger d = null; 
			ECDomainParameters dom = null;

			while ( pemReader.ready() ) {
				pem = pemReader.readPemObject();
				byte[] pembytes = pem.getContent();
				String type = pem.getType(); 
				System.out.println(type);
				if ( type.equals("EC PARAMETERS")) {
					System.out.println(new ByteString(pembytes).toHexString());

					ECNamedCurveParameterSpec curveparams= ECNamedCurveTable.getParameterSpec("P-256");

					ECCurve curve = curveparams.getCurve();
					ECPoint g = curveparams.getG();
					BigInteger order = curveparams.getN();
					dom = new ECDomainParameters(curve, g, order);
				} else if (type.equals("EC PRIVATE KEY")) {
					System.out.println(new ByteString(pembytes).toHexString());
					byte[] keybytes = new byte[32];
					int keystartidx = 7;
					System.arraycopy(pembytes, keystartidx, keybytes, 0, 32);
					d = new BigInteger(keybytes);
				} else {
					System.out.println("error in getClientPrivKey() ");
					pemReader.close();
					throw new IOException("unexpected pem object"); 
				}


			}

			pemReader.close();
			rdr.close();
			privateKey = new ECPrivateKeyParameters(d, dom);  
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} 

		return privateKey;
	}


	public static void main(String[] args) throws IOException, NoSuchAlgorithmException
	{
		System.out.println("Testing tls handshake client auth method(s)");

		String server_ip = "localhost"; 
		int server_port = 8748; 
		Socket sock = new Socket(server_ip, server_port); 
		System.out.println( sock.getInetAddress());

		TlsClientProtocol tls = new TlsClientProtocol(sock.getInputStream(), sock.getOutputStream(), SecureRandom.getInstance("SHA1PRNG"));

		DefaultTlsClient client = new DefaultTlsClient() {

			public int[] getCipherSuites() {
				//CipherSuite TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA    = { 0xC0, 0x04 }
				/*
				 * 0xC0,0x04	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA	Y	[RFC4492]
0xC0,0x05	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
0xC0,0x25	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256

				 * */
				// Audi: ECDH-ECDSA-AES128-SHA256 
				return new int []{0xc025};
			}

			public TlsAuthentication getAuthentication() throws IOException {
				return new TlsAuthentication() {

					public void notifyServerCertificate(Certificate serverCertificate) throws IOException {
						System.out.println("notify:");
						org.bouncycastle.asn1.x509.Certificate[] certs = serverCertificate.getCertificateList(); 
						System.out.println("chain len: "+certs.length);
						System.out.println(certs[0].getSubject());
						System.out.println(certs[0].getStartDate() + " - " + certs[0].getEndDate());

					}
					public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException  {
						short[] certtypes = certificateRequest.getCertificateTypes();
						for ( int i=0; i<certtypes.length; i++) {
							System.out.print(certtypes[i]+ " ");
						}
						System.out.println(); 	

						TlsCredentials cred = new MyTlsAgreementCredentials(getClientCert(), getClientPrivKey());  
						//						TlsCredentials cred = new TlsAgreementCredentials() {
						//							public Certificate getCertificate() {
						//								System.out.println("call to TlsAgreementCredentials.getCertificate");
						//									return getClientCert(); 
						//							}
						//
						//							@Override
						//							public byte[] generateAgreement(
						//									AsymmetricKeyParameter peerPublicKey)
						//									throws IOException {
						//								System.out.println("call to TlsAgreementCredentials.generateAgreement");
						//								System.out.println(peerPublicKey.getClass());
						//								ECPublicKeyParameters params = (ECPublicKeyParameters)peerPublicKey;
						//								ECPoint publickeypoint = params.getQ(); 
						//								BigInteger x_coord_bi = publickeypoint.getXCoord().toBigInteger();
						//								System.out.println(x_coord_bi); 
						//								
						//								return null;
						//							}
						//						};
						return cred; 
						//return tlsSignerCredentials(context);
					}
					//					@Override
					//					public TlsCredentials getClientCredentials(
					//							CertificateRequest arg0) throws IOException {
					//						// TODO Auto-generated method stub
					//						return null;
					//					}
				};
			}

		}; 


		tls.connect(client);

		InputStream is = tls.getInputStream(); 
		OutputStream os = tls.getOutputStream(); 



		BufferedWriter wr = new BufferedWriter(new OutputStreamWriter(os));  
		BufferedReader rd = new BufferedReader(new InputStreamReader(is));          

		//wr.write("GET HTTP/1.1\r\n");


		//		BufferedInputStream bis = new BufferedInputStream(is);
		//		System.out.println(bis.available());		
		String string;
		rd.ready();
		while ((string = rd.readLine()) != null) {
			System.out.println(string);
			System.out.flush();
		}

		//wr.close();
		//rd.close();

		sock.close();
		//      TlsServerProtocol  tlsServerProtocol = new TlsServerProtocol(
		//              socket.getInputStream(), socket.getOutputStream(), secureRandom);


	}
}
/*
 * 

  Socket socket = new Socket(<server IP>, SERVER_PORT);
TlsClientProtocol tlsClientProtocol = new TlsClientProtocol(    
    socket.getInputStream(), socket.getOutputStream());
tlsClientProtocol.connect(new DefaultTlsClient() {          
    public TlsAuthentication getAuthentication() throws IOException {
        return new ServerOnlyTlsAuthentication() {                  
            public void notifyServerCertificate(Certificate serverCertificate) throws IOException {
                validateCertificate(serverCertificate);
            }
        };
    }
});
String message = new BufferedReader(
    new InputStreamReader(tlsClientProtocol.getInputStream())).readLine();

 * 
 * 
 * 
 * */
