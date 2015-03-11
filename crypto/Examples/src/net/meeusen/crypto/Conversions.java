package net.meeusen.crypto;

public class Conversions {

	public static String Integer2OneByteHexString (Integer intnum) {
		Integer temp_int; 
		String temp_str;

		// check range
		if ((intnum < 0) || (intnum>255)) {
			System.out.println("Error! range of key version. Setting to 255. ");
			temp_int = 255; 
		} else {
			temp_int = intnum; 
		}

		// make string + add leading 0 if needed
		temp_str = Integer.toHexString(temp_int); 
		if (temp_int<16) {
			temp_str = "0" + temp_str; 
		}
		
		return (temp_str); 
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

}
