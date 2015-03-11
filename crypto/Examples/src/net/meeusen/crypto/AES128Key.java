package net.meeusen.crypto;

import net.meeusen.util.ByteString;


public class AES128Key extends ByteString {

	//private ByteString key;
	
	// override, just to have something printable: initialize with invalid all-zero key: 
	public AES128Key () {	
		// TODO make it all-zero AES-key
	}

	public AES128Key (ByteString bs) {	
		super(bs); 		 
	}

	
	// override, to have input checking on length
	public AES128Key (String hexstring) {
		super(hexstring); 
				
//		key = new ByteString (hexstring); 
		if (super.length() != AES128KEY_NR_BYTES ) {
			System.out.println("Error. Faulty length for AES128 key string: " + super.length() + " bytes. "); 
			//System.out.println("Setting to all 0x00 bytes. ");
			//TODO set super to 00 bytes.
			//("00 00 00 00 00 00 00");			
		}
	}
	
	// implement toString
	public String toString() {
		return super.toHexString();
	}
	
	public final int AES128KEY_NR_BYTES = (128/8); 
}
