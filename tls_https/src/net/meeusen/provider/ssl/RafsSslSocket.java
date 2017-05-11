package net.meeusen.provider.ssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class RafsSslSocket extends SSLSocket {

	public RafsSslSocket() {
		super(); 
		System.out.println("RafsSslSocket0");		
	}

	private SSLSocket wrappedsock = null; 

	public RafsSslSocket(String host, int port) throws IOException, UnknownHostException {
		super(host, port);
		System.out.println("RafsSslSocket1 host "+host +" port "+port);

		SSLSocketFactory sf = HttpsURLConnection.getDefaultSSLSocketFactory();
		wrappedsock = (SSLSocket) sf.createSocket(host, port);
		//return newsock;
	}

	public RafsSslSocket(InetAddress address, int port) throws IOException {
		super(address, port);
		System.out.println("RafsSslSocket2");
	}

	public RafsSslSocket(String host, int port, InetAddress clientAddress, int clientPort)
			throws IOException, UnknownHostException {
		super(host, port, clientAddress, clientPort);
		System.out.println("RafsSslSocket3");
	}

	public RafsSslSocket(InetAddress address, int port, InetAddress clientAddress, int clientPort) throws IOException {
		super(address, port, clientAddress, clientPort);
		System.out.println("RafsSslSocket4");
	}

	@Override
	public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
		System.out.println("addHandshakeCompletedListener " + listener);
		wrappedsock.addHandshakeCompletedListener(listener);

	}

	@Override
	public boolean getEnableSessionCreation() {
		System.out.println("getEnableSessionCreation");
		return false;
	}

	@Override
	public String[] getEnabledCipherSuites() {
		System.out.println("getEnabledCipherSuites from wrappedsock..");


		String[] suites = wrappedsock.getEnabledCipherSuites(); 
		//		for ( String suite:suites) {
		//		System.out.println("suite "+ suite);
		//	}

		return suites;
	}

	@Override
	public String[] getEnabledProtocols() {
		System.out.println("getEnabledProtocols from wrappedsock..");

		String[] protocols =	wrappedsock.getEnabledProtocols();
		//		for ( String suite:protocols) {
		//		System.out.println("prot "+ suite);
		//	}
		return protocols;  

	}

	@Override
	public boolean getNeedClientAuth() {
		System.out.println("getNeedClientAuth. from wrap" );
		boolean result=false;
		try {
			result = wrappedsock.getNeedClientAuth();
			System.out.println("wrap need client auth: "+ result);
			
		}catch (Exception e) {
			System.out.println("oho. exception "+e);
		}
		return result;  
	}

	@Override
	public SSLSession getSession() {
		System.out.println("getSession from wrap");
		return wrappedsock.getSession();
	}

	@Override
	public String[] getSupportedCipherSuites() {
		System.out.println("getSupportedCipherSuites");
		return null;
	}

	@Override
	public String[] getSupportedProtocols() {
		System.out.println("getSupportedProtocols");
		return null;
	}

	@Override
	public boolean getUseClientMode() {
		System.out.println("getUseClientMode");
		return false;
	}

	@Override
	public boolean getWantClientAuth() {		

		System.out.println("getWantClientAuth. from wrap: " + wrappedsock.getWantClientAuth());

		return wrappedsock.getWantClientAuth();

	}

	@Override
	public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
		System.out.println("removeHandshakeCompletedListener");


	}

	@Override
	public void setEnableSessionCreation(boolean flag) {
		System.out.println("setEnableSessionCreation");

	}

	@Override
	public void setEnabledCipherSuites(String[] suites) {
		System.out.println("setEnabledCipherSuites");
		//		for ( String suite:suites) {
		//			System.out.println("suite "+ suite);
		//		}
		wrappedsock.setEnabledCipherSuites(suites);
	}

	@Override
	public void setEnabledProtocols(String[] protocols) {
		System.out.println("setEnabledProtocols ");
		//		for ( String p: protocols) {
		//			System.out.println("p: " + p);
		//		}
		wrappedsock.setEnabledProtocols(protocols);
	}

	@Override
	public void setNeedClientAuth(boolean need) {
		System.out.println("setNeedClientAuth "+need);

	}

	@Override
	public void setUseClientMode(boolean mode) {
		System.out.println("setUseClientMode "+mode);

	}

	@Override
	public void setWantClientAuth(boolean want) {
		System.out.println("setWantClientAuth " + want);

	}

	@Override
	public void startHandshake() throws IOException {
		System.out.println("startHandshake");
		wrappedsock.startHandshake();

	}

}
