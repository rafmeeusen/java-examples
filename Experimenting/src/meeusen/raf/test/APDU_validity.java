package meeusen.raf.test;


import javax.smartcardio.CommandAPDU;

public class APDU_validity {

	/**
	 * Use smartcardio classes to check if a byte sequence could be a valid apdu. 
	 *  
	 */
	private static String input = "00 21 00 04 02 00 00 00" ;

	public static void main(String[] args) throws Exception {
		System.out.println("APDU test");	

		
		String input_without_spaces = input.replaceAll(" ", "");

		int len = input_without_spaces.length();
		if ((len %2) != 0) throw new Exception("Not an even number of nibbles in hex string.");
		
		String str_one_byte;
		byte apdu[]=new byte[len/2];		
		for ( int nibble=0, apdu_idx=0; nibble<len; nibble+=2, apdu_idx++) {
			str_one_byte = input_without_spaces.substring(nibble, nibble+2) ;  
			apdu[apdu_idx] = Integer.valueOf(str_one_byte,16).byteValue() ; 	
		}
	
		CommandAPDU myapdu =new CommandAPDU(apdu);
				
		System.out.println("CLA: " + Integer.toHexString(myapdu.getCLA()) ) ;
		System.out.println("INS: " + Integer.toHexString(myapdu.getINS()) )  ;
		System.out.println("P1: " + Integer.toHexString(myapdu.getP1()) ) ;
		System.out.println("P2: " + Integer.toHexString(myapdu.getP2()) ) ;
		
		Integer Nc = myapdu.getNc();
		System.out.println("Nc: 0x" + Integer.toHexString(Nc) + "=" + Nc ) ;
		Integer Ne = myapdu.getNe();
		System.out.println("Ne: 0x" + Integer.toHexString(Ne) + "=" + Ne) ;	

		byte[] data = myapdu.getData(); 
		
		if ( data.length != Nc ) System.out.println("Strange. data.length != Nc");
		
		if (Nc != 0) {
			System.out.print("Data: ");
			int temp; 
			for(byte b: data) {
				temp = (int)b;
				if (temp<0) temp+=256; 
				System.out.print(Integer.toHexString(temp) + " " )  ;
			}
			System.out.println("");
		}

	}

}
