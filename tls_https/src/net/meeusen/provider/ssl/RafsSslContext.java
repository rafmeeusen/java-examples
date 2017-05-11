package net.meeusen.provider.ssl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

public class RafsSslContext extends SSLContextSpi {

	public RafsSslContext() {
		System.out.println("constructor called.");
	}

	@Override
	protected SSLEngine engineCreateSSLEngine() {

		System.out.println("engineCreateSSLEngine.");
		return null;
	}

	@Override
	protected SSLEngine engineCreateSSLEngine(String arg0, int arg1) {
		System.out.println("engineCreateSSLEngine with args");
		return null;
	}

	@Override
	protected SSLSessionContext engineGetClientSessionContext() {
		System.out.println("engineGetClientSessionContext ");
		return null;
	}

	@Override
	protected SSLSessionContext engineGetServerSessionContext() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected SSLServerSocketFactory engineGetServerSocketFactory() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected SSLSocketFactory engineGetSocketFactory() {
		System.out.println("engineGetSocketFactory ");
		return null;
	}

	@Override
	protected void engineInit(KeyManager[] arg0, TrustManager[] arg1, SecureRandom arg2) throws KeyManagementException {
		System.out.println("engineInit ");
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		//System.setProperty("javax.net.debug", "ssl");
		System.out.println("just some tests on this class.");
		
		System.out.println("keystore prop: "+ System.getProperty("javax.net.ssl.keyStore")); 
		System.out.println("truststore prop: "+ System.getProperty("javax.net.ssl.trustStore"));
		//Security.addProvider(new RafsSslProvider()); 
		//Security.insertProviderAt(new RafsSslProvider(), 0); 

		//String providerstring = "SunJSSE";
		//String providerstring = "rafs"; 
		//SSLContext ourcontext = SSLContext.getInstance("TLSv1.2", providerstring);

		//HttpsConnection; 
		//SSLSessionContext oursessioncontext = ourcontext.getClientSessionContext();

		//Security.setProperty("ssl.SocketFactory.provider", "com.raf.test");
		Security.setProperty("ssl.SocketFactory.provider","sun.security.ssl.SSLSocketFactoryImpl");
		System.out.println("property: "+Security.getProperty("ssl.SocketFactory.provider") ); 

		
		
//		SSLContext def_ctx = SSLContext.getDefault(); 
//		System.out.println("default ctx: "+def_ctx);
//		SSLSocketFactory def_sf = def_ctx.getSocketFactory();
//		System.out.println("default sf: "+def_sf);
//
//		SSLEngine myengine = def_ctx.createSSLEngine(); 
//		System.out.println(myengine);
//		System.out.println("engine class: "+myengine.getClass());

		String https_url = "https://www.google.com/";
		SSLSocketFactory myfac = new RafsSecureSockFac(); 
		URL url = new URL(https_url);
		HttpsURLConnection con = (HttpsURLConnection)url.openConnection();
		//con.setSSLSocketFactory(myfac);
		
		SSLSocketFactory socfacinuse = con.getSSLSocketFactory(); 
		
		System.out.println("about to connect, con.getSSLSocketFactory()="+socfacinuse);		
		
		try {
			con.connect(); 
			InputStream ins = con.getInputStream();
		} catch (Exception e) {
			e.printStackTrace();
		}
//InputStreamReader isr = new InputStreamReader(ins); 
//BufferedReader in = new BufferedReader(isr); 
//System.out.println("line: " + in.readLine());
		
		
//		InputStream is = con.getInputStream();
//		int firstbyte = is.read(); 
//
//		System.out.println("first byte: "+firstbyte);

		//System.out.println("cipher suite: "+con.getCipherSuite());

//		Certificate[] certs = con.getServerCertificates(); 
//		System.out.println("server cert type: "+ certs[0].getType());
//
//		SSLSocketFactory sf = con.getSSLSocketFactory(); 
//		System.out.println("ssl socket factory class: "+ sf.getClass());
//		con.disconnect();
		
		System.out.println("");
		System.out.println("now repeat the thing");
		HttpsURLConnection con2 = (HttpsURLConnection)url.openConnection();
		//con2.setSSLSocketFactory(myfac);
		System.out.println("about to connect2");
		con2.connect(); 
//		InputStream ins2 = con2.getInputStream();
//InputStreamReader isr2 = new InputStreamReader(ins2); 
//BufferedReader in2 = new BufferedReader(isr2); 
//System.out.println("line: " + in2.readLine());

		System.out.println("end of main");
	}

}
