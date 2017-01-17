package securitymanager;

import java.io.FilePermission;
import java.security.CodeSource;
import java.security.PermissionCollection;
import java.security.Policy;
import java.security.ProtectionDomain;

public class SimplePermissionPrinting {


	/**
	 * Print some Java permissions of a class.
	 * Show difference between CodeSource permissions and ProtectionDomain permissions.  
	 * Show usage of implies. 
	 * */
	public static void main(String[] args) {

		ProtectionDomain protDomainOfThisClass = SimplePermissionPrinting.class.getProtectionDomain(); 
		CodeSource codeSourceOfThisClass = protDomainOfThisClass.getCodeSource();
		Policy pol = Policy.getPolicy();
		String dirName = codeSourceOfThisClass.getLocation().getPath(); 
		String pathForContentsOfClassPath = dirName + "*" ;  

		PermissionCollection permissionsOfThisProtectionDomain = pol.getPermissions(protDomainOfThisClass);
		PermissionCollection permissionsOfThisCodeSource = pol.getPermissions(codeSourceOfThisClass); 

		System.out.println("Permissions of ProtectionDomain of this class: ");
		System.out.println(permissionsOfThisProtectionDomain);


		System.out.println("Permissions of CodeSource of this class: ");
		System.out.println(permissionsOfThisCodeSource);


		FilePermission readPermissionForDir = new FilePermission(pathForContentsOfClassPath, "read");

		if ( permissionsOfThisProtectionDomain.implies( readPermissionForDir ) ) {
			System.out.println("Protection domain permissions imply read access to " + dirName);
		} else {
			System.out.println("Protection domain permissions DO NOT imply read access to " + dirName);
		}

		if ( permissionsOfThisCodeSource.implies( readPermissionForDir ) ) {
			System.out.println("Code source permissions imply read access to " + dirName);
		} else {
			System.out.println("Code source permissions DO NOT imply read access to " + dirName);
		}

	}

}
