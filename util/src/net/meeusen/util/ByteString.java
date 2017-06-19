package net.meeusen.util;

import java.math.BigInteger;


public class ByteString {

    protected byte[] bytes = null;
    private String note = "";

    public ByteString() {
    }

    public ByteString(byte[] bytes) {
        if (bytes!=null) this.bytes = bytes.clone();
    }

    public ByteString(BigInteger bi) {
        this.bytes = bi.toByteArray();
    }

    public ByteString(BigInteger bi, int nr_bytes) {
        this.bytes = new byte[nr_bytes]; // all zeros  

        byte[] temp_ba = bi.toByteArray(); // BigInteger class: the most significant byte is in the zeroth element

        if ( temp_ba.length > nr_bytes ) throw new Error("Cannot put big-int in this small amount of bytes."); 
        int len_dif =  nr_bytes - temp_ba.length ;
        // indices recalc for right-alignment of byte arrays
        // idx_from:       0 ==>  temp_ba.length-1 
        // idx_to:   len_dif ==>  len_dif+temp_ba.length
        for ( int idx_to=len_dif, idx_from=0 ; idx_from<temp_ba.length ; idx_to++, idx_from++ ) {
            this.bytes[idx_to] = temp_ba[idx_from];
        } 
    }


    public ByteString(ByteString b) {
        this.bytes = b.getBytes().clone();
    }

    public ByteString(String hexString) {		
        if ( hexString != null ) {            
            this.bytes = hexstring2bytes(hexString) ;
        }
    }

    private byte[] hexstring2bytes (String hexString) {
        // e.g. "AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51"
        // e.g. "AE2D8A571E03AC9C 9EB76FAC45AF8E51"
        // e.g. "AE2D8A571E03AC9C9EB76FAC45AF8E51"
        // e.g. "AE 2D 8A 57 1E 03 AC 9C 9E B7 6F AC 45 AF 8E 51"

        int countHexDigits = 0;

        for (int i = 0 ; i < hexString.length(); i++) {
            char c = hexString.charAt(i);
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                countHexDigits++;
            }
        }

        int numberOfBytes = countHexDigits / 2;

        byte[] returnvalue = new byte[numberOfBytes];

        int currentByteIndex = 0;
        int index = 0;
        while(index < hexString.length()) {
            char c1 = hexString.charAt(index);
            if ((c1 >= '0' && c1 <= '9') || (c1 >= 'a' && c1 <= 'f') || (c1 >= 'A' && c1 <= 'F')) {
                index++;
                char c2 = hexString.charAt(index);
                index++;
                returnvalue[currentByteIndex++] = (byte)(hexCharToInt(c1) * 16 + hexCharToInt(c2));
            } else {
                index++;
            }

        }

        return returnvalue; 
    }

    public ByteString sliceLSBAt0(int from, int to) {
        int n = bytes.length;

        return(slice(n-from-1,n-to-1));
    }

    public ByteString padded8000() {
        byte[] paddedBytes;

        if ((bytes.length % 16) != 0) {
            paddedBytes = new byte[(bytes.length/16+1)*16];
            for (int i = 0 ; i < bytes.length ; i++) {
                paddedBytes[i] = bytes[i];
            }
            paddedBytes[bytes.length] = (byte)(0x80);
            for (int i = (bytes.length+1) ; i < paddedBytes.length ; i++) {
                paddedBytes[i] = (byte)(0x00);
            }
        } else {
            paddedBytes = bytes;
        }

        return(new ByteString(paddedBytes));

    }

    public ByteString forcedPadded8000() {
        byte[] paddedBytes;

        paddedBytes = new byte[(bytes.length/16+1)*16];
        for (int i = 0 ; i < bytes.length ; i++) {
            paddedBytes[i] = bytes[i];
        }
        paddedBytes[bytes.length] = (byte)(0x80);
        for (int i = (bytes.length+1) ; i < paddedBytes.length ; i++) {
            paddedBytes[i] = (byte)(0x00);
        }

        return(new ByteString(paddedBytes));
    }


    private static ByteString concat(ByteString bs1, ByteString bs2) {
        byte[] bs1Bytes = bs1.getBytes();
        byte[] bs2Bytes = bs2.getBytes();

        if ( bs1Bytes == null ) {
            return new ByteString(bs2); 
        } else if (bs2Bytes==null) {
            return new ByteString(bs1);
        } else {
            byte[] bsBytes = new byte[bs1Bytes.length+bs2Bytes.length];
            for (int i = 0 ; i < bs1Bytes.length ; i++) {
                bsBytes[i] = bs1Bytes[i];
            }
            for (int i = 0 ; i < bs2Bytes.length ; i++) {
                bsBytes[i+bs1Bytes.length] = bs2Bytes[i];
            }				
            return(new ByteString(bsBytes));
        }			
    }

    public static ByteString concat(ByteString... bs) {
        if (bs.length == 0) return null; 
        else if (bs.length==1) return bs[0];
        else {
            ByteString temp = bs[0]; 
            for ( int i=1; i<bs.length; i++) {
                temp = concat ( temp, bs[i] );  
            }
            return temp; 
        }			
    }

    public ByteString slice(int from, int to) {
        byte[] slice = new byte[to-from+1];
        ByteString result = new ByteString();
        result.setNote(note);
        result.setBytes(slice);
        for (int i = 0 ; i < (to-from+1) ; i++) {
            slice[i] = bytes[from+i];
        }
        return(result);
    }

    public static int hexCharToInt(char c) {
        switch (c) {
        case '0' : 
            return(0);
        case '1' : 
            return(1);
        case '2' : 
            return(2);
        case '3' : 
            return(3);
        case '4' : 
            return(4);
        case '5' : 
            return(5);
        case '6' : 
            return(6);
        case '7' : 
            return(7);
        case '8' : 
            return(8);
        case '9' : 
            return(9);
        case 'A' :
        case 'a' :
            return(10);
        case 'B' :
        case 'b' :
            return(11);
        case 'C' :
        case 'c' : 
            return(12);
        case 'D' : 
        case 'd' : 
            return(13);
        case 'E' : 
        case 'e' : 
            return(14);
        case 'F' : 
        case 'f' : 
            return(15);
        default: 
            return(0);
        }
    }

    public int length() {
        return(bytes.length);
    }

    public byte at(int i) {
        return(bytes[i]);
    }

    public void set(int i, byte b) {
        bytes[i] = b;
    }

    public byte[] getBytes() {
        return bytes;
    }

    public void setBytes(byte[] bytes) {
        this.bytes = bytes;
    }

    public String getNote() {
        return note;
    }

    public void setNote(String note) {
        this.note = note;
    }

    public void setString (String input) {
        this.bytes = hexstring2bytes(input) ; 
    }

    public boolean equal(ByteString bytes2) {

        if (bytes.length != bytes2.length()) 
            return(false);

        for (int i = 0 ; i < bytes.length; i++) {
            if (bytes[i] != bytes2.at(i)) {
                return(false);
            }
        }
        return(true);
    }

    public String toHexString() {
        String result = "";
        if ( bytes != null ) {
            for (int i = 0 ; i < bytes.length ; i++) {
                result += String.format("%02x", bytes[i]);
            }            
        }

        return(result);
    }

    public String toSpacedHexString() {
        String result = "";

        for (int i = 0 ; i < (bytes.length-1) ; i++) {
            result += String.format("%02x ", bytes[i]);
        }

        if (bytes.length > 0) {
            result += String.format("%02x", bytes[bytes.length-1]);
        }

        return(result);
    }

    public String toCommaHexString() {
        String result = "";

        for (int i = 0 ; i < (bytes.length-1) ; i++) {
            result += String.format("0x%02x, ", bytes[i]);
        }

        if (bytes.length > 0) {
            result += String.format("0x%02x", bytes[bytes.length-1]);
        }

        return(result);
    }

    public int mostSignificantBit() {
        if ((bytes[0] & ((byte)0x80)) != 0) { 
            return(1);
        } else {
            return(0);
        }
    }

    public static ByteString zero(int len) {
        byte[] zeroBytes = new byte[len];
        for (int i = 0 ; i < len ; i++) {
            zeroBytes[i] = 0;
        }
        return(new ByteString(zeroBytes));
    }

    public ByteString xor(ByteString op) {
        byte[] opBytes = op.getBytes();
        byte[] newBytes = new byte[opBytes.length];
        for (int i = 0 ; i < opBytes.length ; i++) {
            newBytes[i] = (byte)(bytes[i] ^ opBytes[i]);
        }
        return(new ByteString(newBytes));
    }

    // TODO: validate or rewrite this messy code
    public ByteString shiftLeft1Bit() {
        byte[] newBytes = new byte[bytes.length];
        int carry = 0;

        for (int i = bytes.length-1; i >= 0; i--) {
            int newCarry = (bytes[i] & (byte)0x80) >>> 7;
        newBytes[i] = (byte)((bytes[i] << 1) | (carry & 0x1));
        carry = newCarry;
        }

        return(new ByteString(newBytes));
    }

    public ByteString rotateLeft1Byte() {
        byte[] rotated = new byte[bytes.length];

        if (bytes.length > 0) {
            rotated[bytes.length-1] = bytes[0];
            for (int i = 0 ; i < bytes.length-1 ; i++) {
                rotated[i] = bytes[i+1];
            }
        }
        return(new ByteString(rotated));
    }

    public ByteString substring(int start, int len) {
        byte[] newBytes = new byte[len];

        for (int i = 0 ; i < len ; i++) {
            newBytes[i] = bytes[i+start];
        }

        return(new ByteString(newBytes));
    }

    public static void main(String args[]) throws Exception {
        System.out.println("Some checks, output to be inspected manually:");
        byte[] test1 = { 
                (byte)0x01, (byte)0x02, (byte)0x03, 
                (byte)0x7f, (byte)0x80, (byte)0xf1, 
                (byte)0xff };

        ByteString test1String = new ByteString(test1);

        System.out.println("Length: " + test1String.length());
        System.out.println("HexString: |" + test1String.toHexString() + "|");
        System.out.println("Comma HexString: |" 
                + test1String.toCommaHexString() + "|");
        System.out.println("Most significant bit: " + test1String.mostSignificantBit());
        System.out.println("Shift left 1: " + test1String.shiftLeft1Bit().toCommaHexString());
        System.out.println("Rotated left by 1 byte: " + test1String.rotateLeft1Byte().toCommaHexString());

        byte[] test2 = { 
                (byte)0xf1, (byte)0x02, (byte)0x03, 
                (byte)0xff };

        ByteString test2String = new ByteString(test2);

        System.out.println("Length: " + test2String.length());
        System.out.println("HexString: |" + test2String.toHexString() + "|");
        System.out.println("Comma HexString: |" 
                + test2String.toCommaHexString() + "|");
        System.out.println("Most significant bit: " + test2String.mostSignificantBit());
        System.out.println("Shift left 1: " + test2String.shiftLeft1Bit().toCommaHexString());

        // e.g. "AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51"
        // e.g. "AE2D8A571E03AC9C 9EB76FAC45AF8E51"
        // e.g. "AE2D8A571E03AC9C9EB76FAC45AF8E51"
        // e.g. "AE 2D 8A 57 1E 03 AC 9C 9E B7 6F AC 45 AF 8E 51"

        System.out.println("hex to ByteString 1: "
                + new ByteString("AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51").toCommaHexString());
        System.out.println("hex to ByteString 2: "
                + new ByteString("AE2D8A571E03AC9C 9EB76FAC45AF8E51").toCommaHexString());
        System.out.println("hex to ByteString 3: "
                + new ByteString("AE2D8A571E03AC9C9EB76FAC45AF8E51").toCommaHexString());
        System.out.println("hex to ByteString 4: "
                + new ByteString("AE 2D 8A 57 1E 03 AC 9C 9E B7 6F AC 45 AF 8E 51").toCommaHexString());
        System.out.println("hex to ByteString 4 (truncated to first 8 bytes): "
                + new ByteString("AE 2D 8A 57 1E 03 AC 9C 9E B7 6F AC 45 AF 8E 51").slice(0,7).toCommaHexString());


        System.out.println("Selftesting some toString() cases.");
        testToString(new byte[]{0,1,2,127}, "0001027f"); 
        testToString(new byte[]{}, ""); 
        testToString(new byte[]{-1,-2}, "fffe");
        testToString(new byte[]{-127,-128, -126}, "818082");

        System.out.println("Selftest OK");



    }

    private static void testToString(byte[] testbytes, String expected) throws Exception {       
        String result = new ByteString(testbytes).toString();  
        if ( ! result.equals(expected) )   throw new Exception("expected " + expected + " but got " + result);
    }

    public String toString() {
        return toHexString();
    }
}
