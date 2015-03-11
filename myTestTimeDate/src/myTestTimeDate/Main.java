package myTestTimeDate;

import java.util.Date;

public class Main {

    public static void main(String[] args) {
        System.out.println("rafs time date playing around");

        Date d = new Date();
        Date d2 = new Date(System.currentTimeMillis()); 
        System.out.println("just print new date object: " + d);
        System.out.println("just print new date object: " + d2);
        
        
       
    }

}
