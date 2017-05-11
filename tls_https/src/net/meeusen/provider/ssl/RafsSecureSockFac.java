package net.meeusen.provider.ssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;


public class RafsSecureSockFac extends SSLSocketFactory {

	public RafsSecureSockFac()  {
		System.out.println("RafsSecureSockFac constructor");
	}

	
	
	@Override
	public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
		System.out.println("createSocket0");
		
//		System.out.println("given sock: " + s);
//		System.out.println("given sock class: " + s.getClass());
//		SSLSocket newsock = null; 
//		try {
//			SSLSocketFactory sf = HttpsURLConnection.getDefaultSSLSocketFactory();
//			newsock = (SSLSocket) sf.createSocket(host, port);
//		} catch (Exception e) {
//			System.out.println("oho.");
//		}
//		System.out.println("new sock class: " + newsock.getClass());
//		SSLSession ses = newsock.getSession(); 
//		SSLSessionContext sescontext = ses.getSessionContext(); 
//		
//		System.out.println("new sock session: " + ses);
//		System.out.println("new sock session ctx: " + sescontext);
//		System.out.println("new sock is connected? " + newsock.isConnected());
		return new RafsSslSocket(host, port);
	}

	@Override
	public String[] getDefaultCipherSuites() {
		System.out.println("getDefaultCipherSuites");
		return null;
	}

	@Override
	public String[] getSupportedCipherSuites() {
		System.out.println("getSupportedCipherSuites");
		return null;
	}

	@Override
	public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
		System.out.println("createSocket1");
		
		Socket s=null; 

		return  s;
		
	}

	@Override
	public Socket createSocket(InetAddress host, int port) throws IOException {
		System.out.println("createSocket2");
		return null;
	}

	@Override
	public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
			throws IOException, UnknownHostException {
		System.out.println("createSocket3");
		return null;
	}

	@Override
	public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
			throws IOException {
		System.out.println("createSocket4");
		return null;
	}

}
