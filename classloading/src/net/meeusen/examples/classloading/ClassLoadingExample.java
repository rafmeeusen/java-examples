package net.meeusen.examples.classloading;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;


public class ClassLoadingExample {

	
	public static void main(String[] args) throws ClassNotFoundException, MalformedURLException			 {
		
		System.out.println("Showing 3 different classloaders in java system.");
		System.out.println();
		
		System.out.println("User's main class is loaded by application class loader (aka system class loader, confusing old name)");		
		System.out.println("Parent classloader of application class loader should be extension class loader.");
		System.out.println("Parent classloader of extension class loader should be bootstrap class loader.");
		System.out.println();
		
		System.out.println("1. Let's print class loader delegation hierarchy starting from this Main class.");
		ClassLoader thismaincl = ClassLoadingExample.class.getClassLoader(); 
		System.out.println("Classloader of this Main class: " + thismaincl); 		
		ClassLoader appclassloader = ClassLoader.getSystemClassLoader(); 
		if (appclassloader.equals(thismaincl)) {
			System.out.println("\tOK, method ClassLoader.getSystemClassLoader() returned same class loader. ");
		} else {
			System.out.println("\tMmmm. Not right. Method ClassLoader.getSystemClassLoader() returned another class loader. ");
		}
		ClassLoader parentcl = thismaincl.getParent(); 
		System.out.println("and its parent: " + parentcl);
		ClassLoader grandparentcl = parentcl.getParent(); 
		System.out.println("and its grandparent: " + grandparentcl); 		
		System.out.println("Bootstrap classloader (grandparent) is often null since usually implemented in native code in VM.");
		System.out.println();
		
		System.out.println("2. Let's print the class loader of some well-known classes/interfaces.");
		Class<?> classes[] = new Class[] {
				com.sun.crypto.provider.SunJCE.class,				
				com.sun.nio.zipfs.JarFileSystemProvider.class,
				java.io.File.class, 
				java.security.Provider.class, 
				javax.crypto.SecretKey.class, 
				javax.crypto.Cipher.class, 
				Object.class, 
				sun.security.ec.SunEC.class, 
				}; 		
		for ( Class<?> c: classes ) {
			System.out.println(c + " <---> " + c.getClassLoader());	
		}
		System.out.println();
		
		System.out.println("3. <TODO NOT FINISHED> Let's show that the same class can be loaded by two different class loaders.");
		System.out.println(appclassloader.getResource("test.txt"));
		System.out.println(appclassloader.getResource("net/meeusen/examples/classloading/Main.class"));
		
		URL url1 = new URL("file:/C:/MyLocalData/mygithub/java-examples/crypto/Examples/bin/"); 
		URL url2 = new URL("file:/C:/MyLocalData/mygithub/java-examples/crypto/Examples/bin/"); 
		
		ClassLoader mycl1 = new URLClassLoader(new URL[]{url1}, appclassloader); 
		ClassLoader mycl2 = new URLClassLoader(new URL[]{url2}, appclassloader);
		Class<?> main1 = mycl1.loadClass("net.meeusen.examples.classloading.Main"); 
		Class<?> main2 = mycl2.loadClass("net.meeusen.examples.classloading.Main"); 
		
		classes = new Class[] { main1, main2	}; 		
		for ( Class<?> c: classes ) {
			System.out.println(c + " <---> " + c.getClassLoader());	
		}
		
		System.out.println();
		
	}

}
