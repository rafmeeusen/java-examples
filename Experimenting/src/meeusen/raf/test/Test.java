package meeusen.raf.test;

import java.nio.ByteBuffer;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;


public class Test {

	/**
	 * @param args
	 * @throws CardException 
	 */
	public static void main(String[] args) throws CardException {
		// TODO Auto-generated method stub
		System.out.println("Just testing stuff. ");
		
        // show the list of available terminals
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        System.out.println("Terminals: " + terminals);
        // get the first terminal
        CardTerminal OmniKeyCL = null;
        for ( CardTerminal t: terminals ) {
        	System.out.println( t.getName() ); 
        	if ( t.getName().equals("OMNIKEY CardMan 5x21-CL 0") ) {
        		OmniKeyCL = t; 
        	}
        }
        
        if ( OmniKeyCL != null) {
        	
            Card card = OmniKeyCL.connect("T=1");
            System.out.println("card: " + card);
            System.out.println("ATR: " + new ByteString(card.getATR().getBytes()).toHexString() ) ;
            System.out.println("ATR hist. bytes: " + new ByteString(card.getATR().getHistoricalBytes()).toHexString() ) ;
            
          CardChannel channel = card.getBasicChannel();
          
          
          CommandAPDU capdu = new CommandAPDU( new ByteString("ff ca 00 00 00").getBytes() ); 

          
          //byte[] capdu = {0,0,0,0};
          ResponseAPDU rapdu = channel.transmit (capdu);
          //String rapdu = send ( capdu, channel) ; //channel.transmit (new CommandAPDU("00 00 00 00") ); 
          System.out.println("response: " + new ByteString(rapdu.getBytes()).toHexString() );
        }
        
        //CardTerminal terminal = terminals.get();
        // establish a connection with the card

       //ResponseAPDU r = channel.transmit(new CommandAPDU(c1));
//        
        // disconnect
  //      card.disconnect(false);

	}

	   public static String send(byte[] cmd, CardChannel channel) {

	       String res = "";

	       byte[] baResp = new byte[258];
	       ByteBuffer bufCmd = ByteBuffer.wrap(cmd);
	       ByteBuffer bufResp = ByteBuffer.wrap(baResp);

	       // output = The length of the received response APDU
	       int output = 0;

	       try {

	           output = channel.transmit(bufCmd, bufResp);

	       } catch (CardException ex) {
	           ex.printStackTrace();
	       }

	       for (int i = 0; i < output; i++) {
	           res += String.format("%02X", baResp[i]);
	           // The result is formatted as a hexadecimal integer
	       }

	       return res;
	   }

	
}
