package net.meeusen.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class RandomString {


    private SecureRandom rngForBytes=null;
    private static String validChars ="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    public RandomString() throws NoSuchAlgorithmException {
        this.rngForBytes = new SecureRandom();
    }


    public static void main(String[] args) throws NoSuchAlgorithmException {
        RandomString generator = RandomString.getInstance();
        for ( int i=0; i<10; i++) {
            System.out.println(generator.getString(16));
        }

    }

    
    public String getString(int nrChars) {
        
        StringBuilder res=new StringBuilder();
        for (int i = 0; i < nrChars; i++) {
           int randIndex=rngForBytes.nextInt(validChars.length()); 
           res.append(validChars.charAt(randIndex));            
        }
        return res.toString();       
    }

    public static RandomString getInstance() throws NoSuchAlgorithmException {
        return new RandomString();
    }

}
