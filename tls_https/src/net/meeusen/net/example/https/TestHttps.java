package net.meeusen.net.example.https;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.URL;
import java.security.KeyStore;
import java.util.Enumeration;

import javax.net.ssl.HttpsURLConnection;

public class TestHttps {

	private static final  String truststoreSysPropKey = "javax.net.ssl.trustStore";
	private static final String javaHomeSysPropKey = "java.home"; 



	// from Oracle website: 
	// 	
	//	If the system property:
	//		javax.net.ssl.trustStore
	//		is defined, then the TrustManagerFactory attempts to find a file using the filename specified by that system property, and uses that file for the KeyStore. If the javax.net.ssl.trustStorePassword system property is also defined, its value is used to check the integrity of the data in the truststore before opening it.
	//		If javax.net.ssl.trustStore is defined but the specified file does not exist, then a default TrustManager using an empty keystore is created.
	//
	//		If the javax.net.ssl.trustStore system property was not specified, then if the file
	//		<java-home>/lib/security/jssecacerts
	//		exists, that file is used. (See The Installation Directory <java-home> for information about what <java-home> refers to.) Otherwise,
	//		If the file
	//		<java-home>/lib/security/cacerts
	//		exists, that file is used.
	//	


	/**
	 * goal: show behaviour of Https connect in two cases: 
	 *   a) default cacerts truststore used
	 *   b) custom truststore used, where CA needed for URL is removed. 
	 * 
	 * change changeTrustStoreSysProp boolean to change behaviour between a) and b)
	 * 
	 * */
	public static void main(String[] args) throws Exception {

		System.out.println("entering main");
		System.out.println(truststoreSysPropKey+ " : " + System.getProperty(truststoreSysPropKey) );


		
		// set default trust store or not: 
		boolean changeTrustStoreSysProp = true;
		if (changeTrustStoreSysProp){
			String newCaCertsFileName = "/home/raf/cacertsfake";
			String[] aliasStringPartsToRemove = new String[] { "equifax", "geotrust" }; 			
			createReducedCopyOfCacerts(newCaCertsFileName, aliasStringPartsToRemove); 
			String newTrustStoreSysProp = newCaCertsFileName;
			System.out.println("setting system property " + truststoreSysPropKey + " to " + newTrustStoreSysProp);
			System.setProperty(truststoreSysPropKey, newTrustStoreSysProp); 
		}

		// connect to an https server: 
		URL                 url = new URL("https://www.google.com" );
		System.out.println("calling openConnection on url");
		HttpsURLConnection  con = (HttpsURLConnection)url.openConnection();		    
		System.out.println("calling connect on connection");
		boolean connectIsSuccess = false; 
		try {
			con.connect();
			connectIsSuccess=true; 
		} catch (Exception e) {
			connectIsSuccess=false; 
			//throw e; 
		}
		
		if ( connectIsSuccess) {
			System.out.println("It seems that connecting to " + url + " has worked fine." );
		} else {
			System.out.println("It seems that connecting to " + url + " did NOT work !");
		}
		System.out.println("exiting main");

	}


	/**
	 * load default cacerts file, 
	 * delete given entries from it,
	 * and save under given new name 
	 * @param aliasStringPartToRemove 
	 * @throws Exception 
	 * */
	static void createReducedCopyOfCacerts ( String newCaCertsFileName, String[] aliasStringPartToRemove ) throws Exception{
		char[] truststorePassword = "changeit".toCharArray();

		String javaHome =  System.getProperty(javaHomeSysPropKey); 
		System.out.println("Java home: " + javaHome);

		// 1. check if we can find cacerts
		String presumableCaCertsFileString = javaHome + "/lib/security/cacerts"; 
		File cacertsFile = new File (presumableCaCertsFileString);
		if ( cacertsFile.exists() ){
			System.out.println(presumableCaCertsFileString + " exists. ");			
		} else {
			System.out.println(presumableCaCertsFileString + " does not exist. Fatal error. ");
			throw new Exception("Error. Could not find " + presumableCaCertsFileString); 
		}

		// 2. load cacerts in keystore object
		File fakeCaCertsFile = new File (newCaCertsFileName);
		KeyStore fakeCaCertsTs = KeyStore.getInstance(KeyStore.getDefaultType());  
		fakeCaCertsTs.load(new FileInputStream(presumableCaCertsFileString), truststorePassword);

		// 3. remove entries
		Enumeration<String> enumAliases = fakeCaCertsTs.aliases();
		while ( enumAliases.hasMoreElements() ) {
			String newAlias = enumAliases.nextElement();
			//System.out.println("new alias: "+ newAlias); 
			for ( String aliasPartToCheck:aliasStringPartToRemove) {
				if ( newAlias.contains(aliasPartToCheck)) {
					System.out.println("will remove alias " + newAlias) ;
					fakeCaCertsTs.deleteEntry(newAlias);
				} else {
					//System.out.println("will keep alias " + newAlias);
				}				
			}			
		}

		// 4. save to new filename		
		fakeCaCertsTs.store(new FileOutputStream(fakeCaCertsFile), truststorePassword);

	}

}
