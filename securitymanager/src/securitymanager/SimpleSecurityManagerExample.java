package securitymanager;

import java.io.File;
import java.io.FilePermission;
import java.security.AccessControlException;

public class SimpleSecurityManagerExample {

	/**
	 * Enable SecurityManager and check out the security exception resulting from it,
	 * when listing a directory.
	 * (default policy)
	 */
	public static void main(String[] args) {
		final String defaultDirName = "/etc/apt"; 

		String dirName = null; 
		if ( args.length > 0 ) {
			dirName = args[0]; 
		} else {
			dirName = defaultDirName; 
		}
		
		printDir(dirName); 

		SecurityManager sm = new SecurityManager();		
		System.out.println("Now setting security manager. ");
		System.setSecurityManager(sm);

		System.out.println("Now try again listing dir. ");
		try {
			printDir(defaultDirName); 
			System.out.println("Strange. Could still read directory. Not expected. ");
		} catch (AccessControlException se) {
			System.out.println("Got excpected AccessControlException.");		
			FilePermission permissionThatIWouldNeed = (FilePermission) se.getPermission();			
			System.out.println("The permission object of the missing permission: "); 
			System.out.println("    " + permissionThatIWouldNeed );			
		}

	}

	private static void printDir(String dirname) {
		File dirToPrint = new File(dirname);
		File[] filesInDir = dirToPrint.listFiles();
		if ( filesInDir == null ) {
			String message = "Unexpected error trying to read from " + dirname + ". For this example, please use a directory that exists, and to which JVM has read access.";  
			throw new RuntimeException(message); 					
		} else {
			System.out.println("Found " + filesInDir.length + " files in directory " + dirname + ":");
			for ( File dirItem : filesInDir ) {
				System.out.println("    "+ dirItem);
			}
		}
	}

}
