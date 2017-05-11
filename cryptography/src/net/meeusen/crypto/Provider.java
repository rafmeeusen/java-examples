package net.meeusen.crypto;

import java.security.Security;


public class Provider {

	public static void main(String[] args) {
		System.out.println("Provider info example.");
		System.out.println("Found " + Security.getProviders().length + " security providers: ");		
		for (java.security.Provider provider: Security.getProviders()) {
			System.out.println(provider.getName());
		} 
		System.out.println("- - - - - -");
		System.out.println("Provider details: ");
		for (java.security.Provider provider: Security.getProviders()) {
			System.out.println(provider.getName());
			for (String key: provider.stringPropertyNames())
				System.out.println("\t" + key + "\t" + provider.getProperty(key));
		} 		
	}

}
