package net.meeusen.net.example.https;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

/**
 * This reference software application or driver is provided as a way of example only, to show conceptually how a specific function or
 * group of related functions can be used. In itself, it does not constitute a blueprint for how to design and implement a commercial/
 * production application with all due considerations to defensive programming, reliability, performance, efficiency, security and/or
 * any other relevant concern.
 *
 * In no event shall Telit be liable to any party for direct, indirect, special, exemplary, incidental, or consequential damages arising
 * out of - or in connection with - the use, inability to use, or non-fitness for a particular purpose of this software, its documentation,
 * or any derivatives thereof, even if Telit has been advised of the possibility of such damage.
 *
 * Telit specifically disclaims any express or implied warranty, including, but not limited to, any implied warranty of merchantability,
 * fitness for a particular purpose, and non-infringement. The entire risk as to the quality and performance of this software is with the
 * recipient. Except when otherwise stated in writing, this software is provided on an "as is" basis, and Telit has no obligation to provide
 * maintenance, support, updates, enhancements, or modifications.
 *
 * @author Telit Automotive Solutions
 *
 */

public class testHttps2 {
	private static final String  FILENAMEBASE = "/app/ksfile_";
	private static String        separator    = "===============================================";
	private static Key           SomeAESKey   = new SecretKeySpec(new byte[] { 'a', 't', 'o', 'p', '_',
			'a', 'e', 's', '_',
			'k', 'e', 'y', '0', '0', '0', '1' },
			"AES");
	private static String  ServerCertFile;
	private static String  printProviders;
	private static String  wrongUrlForFirstConnection;
	private static String  openConnectionBeforeKeyStoreLoad;
	private static String  connectBeforeKeyStoreLoad;
	private static String  LoadTrustoreFileIfExists;

	public static void main(String[] args)
	{
		final Properties prop = new Properties();
		InputStream input = null;
		try {
			input = new FileInputStream("/home/raf/Downloads/magweg/example_https_test/appdata/connectSsl.cfg");
			// load a properties file
			prop.load(input);
			// get the property value and print it out
			ServerCertFile=prop.getProperty("ServerCertFile");
			printProviders=prop.getProperty("printProviders");
			wrongUrlForFirstConnection=prop.getProperty("wrongUrlForFirstConnection");
			openConnectionBeforeKeyStoreLoad=prop.getProperty("openConnectionBeforeKeyStoreLoad");
			connectBeforeKeyStoreLoad=prop.getProperty("connectBeforeKeyStoreLoad");
			LoadTrustoreFileIfExists=prop.getProperty("LoadTrustoreFileIfExists");
			System.out.println("ServerCertFile                   = " + ServerCertFile);
			System.out.println("printProviders                   = " + printProviders);
			System.out.println("wrongUrlForFirstConnection       = " + wrongUrlForFirstConnection);
			System.out.println("openConnectionBeforeKeyStoreLoad = " + openConnectionBeforeKeyStoreLoad);
			System.out.println("connectBeforeKeyStoreLoad        = " + connectBeforeKeyStoreLoad);
			System.out.println("LoadTrustoreFileIfExists         = " + LoadTrustoreFileIfExists);
		}
		catch (final IOException ex) {
			ex.printStackTrace();
		}
		finally {
			if (input != null) {
				try {
					input.close();
				}
				catch (final IOException e) {
					e.printStackTrace();
				}
			}
		}    
		System.out.println("-------------------------------------------------");
		System.out.println("  Starting security example  ");
		System.out.println("-------------------------------------------------");

		if(printProviders.equals("yes")){
			System.out.println(separator);
			System.out.println("PRINTING PROVIDER OVERVIEW: ");
			HashSet  availableKeyStoreTypes = new HashSet();
			printProviders(availableKeyStoreTypes);
			System.out.println(separator + "\n");
		}

		System.out.println(separator);
		System.out.println("KEYSTORE EXAMPLE: ");
		System.out.println("Inspecting the created files should show whether keys are encrypted or not. ");
		System.out.println("");
		keyStoreTypeExample("JKS", ServerCertFile);
		System.out.println(separator + "\n");

		System.out.println("Bye bye");
		System.out.println("-------------------------------------------------");

		// Never ended loop, in order to not exit from JVM
		while ( true ) {
			try {
				Thread.sleep(1000);
			}
			catch ( InterruptedException e ) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	private static void  printProviders(Set foundKeyStores)
	{
		Provider  p[] = Security.getProviders();

		System.out.println("Found " + p.length + " security providers: ");
		for ( int i = 0; i < p.length; i++ ) {
			Enumeration  keysinprovider = p[i].keys();
			System.out.println( "Name: " + p[i].getName() );
			System.out.println( "    Version: " + p[i].getVersion() );
			System.out.println( "    Info: " + p[i].getInfo() );
			System.out.println("    Properties (key / value): ");
			for (; keysinprovider.hasMoreElements(); ) {
				String  key   = (String)keysinprovider.nextElement();
				String  value = p[i].getProperty(key);
				if ( key.startsWith("KeyStore") ) {
					String  kstype = key.substring( "KeyStore.".length() );
					foundKeyStores.add(kstype);
				}
				System.out.println("        " + key + " / " + value);
			}
		}
	}

	private static int getInputStreamLength(InputStream is) throws IOException
	{
		byte  buf[] = new byte[64 * 1024];
		int   count = 0;

		while ( true ) {
			int  sz = is.read(buf);
			if ( sz < 0 ) {
				break;
			}
			count += sz;
		}
		return count;
	}

	/* loop example code over available keystore types */
	private static void keyStoreTypeExample(String  kstype, String ServerCertFile)
	{
		System.out.println("KeyStore type: " + kstype);

		// HttpsURLConnection handling before to load KeyStore with Certificate
		HttpsURLConnection  con = null;
		try{

			// !!! Fill URL of Secured Server
			if(wrongUrlForFirstConnection.equals("yes")){
				new URL("https://" + "wrongurl.com" + ":" + "5555");
			}
			else{
			}
			URL url = new URL("https://" + "atop.telit.com" + ":" + "8543");
			// !!! Fill URL of Secured Server

			if(openConnectionBeforeKeyStoreLoad.equals("yes")){
				// just open HttpsURLConnection and close it
				con = (HttpsURLConnection)url.openConnection();
				con.getInputStream().close();
			}
			if(connectBeforeKeyStoreLoad.equals("yes")){
				// open HttpsURLConnection, try to use it and close it
				con = (HttpsURLConnection)url.openConnection();
				con.setHostnameVerifier(new HostnameVerifier(){public boolean verify(String hostname, SSLSession session) { return true;}});
				System.out.println("got " + getInputStreamLength( con.getInputStream() ) + " bytes from server");
				System.out.println( "cert type: " + con.getServerCertificates()[0].getClass().toString() );
				System.out.println( "cert : " + con.getServerCertificates()[0].toString() );
				con.getInputStream().close();
			}
		}
		catch(MalformedURLException e){
			e.printStackTrace();
		}
		catch(IOException e){
			e.printStackTrace();
		}

		try {
			// KeyStore handling:
			KeyStore  truststore = KeyStore.getInstance(kstype);
			File  trustStoreFile = new File(FILENAMEBASE + kstype);
			System.out.println("+ + + + +");
			System.out.println( "Running example for " + kstype + " on file " + trustStoreFile.getName() );

			// If KeyStore already exists or not
			if ( trustStoreFile.exists() ) {
				System.out.println( trustStoreFile.getName() + " already exists");
				if(LoadTrustoreFileIfExists.equals("yes")){
					// Loading keystore
					FileInputStream  fis = new FileInputStream(trustStoreFile);
					truststore.load( fis, "changeit".toCharArray() );
					fis.close();
				}
			}
			else {
				// create empty keystore
				System.out.println( trustStoreFile.getName() + " doesn't exist, create an empty keystore");
				truststore.load(null, null);
			}


			// Certificate handling: Opening & loading certificate file
			FileInputStream     certIs = new FileInputStream(ServerCertFile);
			CertificateFactory  cf     = CertificateFactory.getInstance("X.509");
			System.out.println( "Certificate Factory provider is " + cf.getProvider() );
			Certificate  cert = cf.generateCertificate(certIs);
			certIs.close();

			// Adding certificate into keystore
			System.out.println("Keystore contains " + truststore.size() + " certificates");
			truststore.setCertificateEntry(ServerCertFile, cert);
			System.out.println("Added certificate " + ServerCertFile + " into keystore");
			System.out.println("Keystore contains " + truststore.size() + " certificates");

			System.out.println("+ + + + +");
			System.out.println("");

			// save truststore
			FileOutputStream  fos = new FileOutputStream(trustStoreFile);
			truststore.store( fos, "changeit".toCharArray() );
			fos.close();

			// set truststore as JVM default KeyStore
			System.setProperty("javax.net.ssl.trustStore", FILENAMEBASE + kstype);
			System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
		}
		catch ( FileNotFoundException e1 ) {
			e1.printStackTrace();
		}
		catch ( KeyStoreException e ) {
			e.printStackTrace();
		}
		catch ( NoSuchAlgorithmException e ) {
			e.printStackTrace();
		}
		catch ( CertificateException e ) {
			e.printStackTrace();
		}
		catch ( IOException e ) {
			e.printStackTrace();
		}

		// HttpsURLConnection handling after KeyStore with Certificate (bad or right) was loaded
		try{
			// !!! Fill URL of Secured Server
			URL url = new URL("https://" + "atop.telit.com" + ":" + "8543");
			// !!! Fill URL of Secured Server

			con = (HttpsURLConnection)url.openConnection();

			// Try to connect and get Server Certicates a first time
			con.setHostnameVerifier(new HostnameVerifier() { public boolean verify(String hostname, SSLSession session) { return true; } });
			System.out.println("got " + getInputStreamLength( con.getInputStream() ) + " bytes from server");
			System.out.println( "cert type: " + con.getServerCertificates()[0].getClass().toString() );
			System.out.println( "cert : " + con.getServerCertificates()[0].toString() );			
			con.getInputStream().close();

			// Try to connect and get Server Certicates a second time after having close the first HttpsURLConnection
			con = (HttpsURLConnection)url.openConnection();
			con.setHostnameVerifier(new HostnameVerifier() { public boolean verify(String hostname, SSLSession session) { return true; } });
			System.out.println("got " + getInputStreamLength( con.getInputStream() ) + " bytes from server");
			System.out.println( "cert type: " + con.getServerCertificates()[0].getClass().toString() );
			System.out.println( "cert : " + con.getServerCertificates()[0].toString() );
			con.getInputStream().close();
		}
		catch(MalformedURLException e){
			e.printStackTrace();
		}
		catch(IOException e){
			e.printStackTrace();
		}
	}
}
