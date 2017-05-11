package net.meeusen.net.example.https;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.URL;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

public class testHttpsClientAuth {



    /**
     * Read an inputstream completely to return its (remaining) length.
     * @param is inputstream
     * @return length in bytes
     * @throws IOException
     */
    static int getInputStreamLength(InputStream is) throws IOException
    {
        byte  buf[] = new byte[64 * 1024];
        int   count = 0;

        while ( true ) {
            int  sz = is.read(buf);
            if ( sz < 0 ) {
                break;
            }
            count += sz;
        }
        return count;
    }

    static java.security.cert.Certificate[] loadCertChain(
            String fileName) throws FileNotFoundException,
    CertificateException, IOException
    {
        java.security.cert.Certificate[] chain;
        // Load the certificate chain (in X.509 DER encoding).
        FileInputStream     certificateStream  =
                new FileInputStream(fileName);
        CertificateFactory  certificateFactory =
                CertificateFactory.getInstance("X.509");

        // Required because Java is STUPID.  You can't just cast the result
        // of toArray to Certificate[].
        Collection  certColl =
                certificateFactory.generateCertificates(certificateStream);
        chain = new Certificate[certColl.size()];
        System.arraycopy( certColl.toArray(chain), 0, chain, 0,
                certColl.size() );
        certificateStream.close();
        return chain;
    }


    static PrivateKey decodePrivateKey(EncodedKeySpec ks, String algorithm, PrintStream dbg)
            throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        dbg.println( "Loading PKCS8 key in format " + ks.getFormat() );
        KeyFactory  keyFactory = KeyFactory.getInstance(algorithm);
        PrivateKey  privKey    = (PrivateKey)keyFactory.generatePrivate(ks);
        return privKey;
    }

    static PrivateKey loadKey(String keyFile, PrintStream dbg)
            throws FileNotFoundException, IOException, NoSuchAlgorithmException,
            InvalidKeySpecException
    {
        if ( keyFile == null || "".equals(keyFile) ) {
            return null;
        }
        InputStream  bis         = null;
        File         privKeyFile = new File(keyFile);
        FileInputStream     privateKeyIs = new FileInputStream(privKeyFile);
        bis                 = new BufferedInputStream( privateKeyIs );
        byte[] privKeyBytes = new byte[(int)privKeyFile.length()];
        bis.read(privKeyBytes);
        bis.close();
        PrivateKey      privKey = null;

        EncodedKeySpec  ks      = new PKCS8EncodedKeySpec(privKeyBytes);

        privateKeyIs.close();

        try {
            privKey = decodePrivateKey(ks, "RSA", dbg);
        }
        catch ( Exception e ) {
            dbg.println("Could not load key from PKCS8 store as RSA, trying EC");
            privKey = decodePrivateKey(ks, "EC", dbg);
        }
        return privKey;
    }

    /**
     * Load all certificate files in the set of cert file name
     * @param certFiles set of filenames (strings)
     * @param keyStore TODO
     */
    static void loadCertificates(Set certFiles, KeyStore keyStore, PrintStream dbg)
    {
        Iterator  it = certFiles.iterator();

        while ( it.hasNext() ) {
            String  certFile = (String)it.next();
            loadCertificate(certFile, keyStore, dbg);
        }
    }



    //    /**
    //     * Load certificate files into the keystore
    //     * @param keyStore TODO
    //     * @param certs
    //     *          paths to cert files
    //     */
    //    static void loadCertificate(String certFile, KeyStore keyStore, PrintStream dbg)
    //    {
    //        if ( keyStore == null ) {
    //            dbg.println("Could not load cert into null keystore "); // can't load them yet
    //            return;
    //        }
    //
    //        try {
    //            /* Opening & loading certificate file */
    //            FileInputStream     certIs = new FileInputStream(certFile);
    //            CertificateFactory  cf     = CertificateFactory.getInstance("X.509");
    //
    //            dbg.println( "Certificate Factory provider is " + cf.getProvider() );
    //
    //            Certificate  cert = cf.generateCertificate(certIs);
    //
    //            certIs.close();
    //
    //            /* Adding certificate into keystore */
    //            dbg.println("Keystore contains " + keyStore.size() + " certificates");
    //            keyStore.setCertificateEntry(certFile, cert);
    //            dbg.println("Added certificate " + certFile + " into keystore");
    //            dbg.println("Keystore contains " + keyStore.size() + " certificates");
    //        }
    //        catch(IOException e) {
    //            e.printStackTrace(dbg);
    //        }  
    //        catch ( CertificateException e ) {
    //            e.printStackTrace(dbg);
    //        }
    //        catch ( KeyStoreException e ) {
    //            e.printStackTrace(dbg);
    //        }
    //    }




    /**
     * Print info on a certificate chain
     * @param certchain
     * @param out
     */
    static void dumpChain(Certificate[] certs, PrintStream out)
    {
        if ( certs == null ) {
            return;
        }
        out.println("*chain of length " + certs.length + "*");
        out.println("---------");
        for ( int i = 0; i < certs.length; i++ ) {
            if ( certs[i] instanceof X509Certificate ) {
                X509Certificate  x509cert = (X509Certificate)certs[i];
                out.println( "DN:" + x509cert.getSubjectDN() );
                out.println( " type: " + x509cert.getSigAlgName() );
                out.println( " by:" + x509cert.getIssuerDN() );
            }
            else {
                out.println(certs[i]);
            }
            out.println("");
        }
    }

    static void loadKey(String keyFile, String clientCertFile, KeyStore keyStore,
            PrintStream dbg) throws CertificateException
    {
        // try to load a key into the keystore from a pkcs8 file
        // and certificates form a
        if ( keyStore == null ) {
            dbg.println("Could not load private key into null keystore "); // can't load them yet
            return;
        }

        try {
            PrivateKey  privKey = loadKey(keyFile, dbg);

            java.security.cert.Certificate[] chain = {};

            if ( clientCertFile != null && !"".equals(clientCertFile) ) {
                chain = loadCertChain(clientCertFile);
                dumpChain(chain, dbg);
            }

            keyStore.setKeyEntry("clientkey", privKey, "changeit".toCharArray(), chain);
        }
        catch ( FileNotFoundException e ) {
            e.printStackTrace(dbg);
        }
        catch ( KeyStoreException e ) {
            e.printStackTrace(dbg);
        }
        catch ( IOException e ) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        catch ( NoSuchAlgorithmException e ) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        catch ( InvalidKeySpecException e ) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }


    /**
     * Load certificate files into the keystore
     * @param keyStore TODO
     * @param certs
     *          paths to cert files
     */
    static void loadCertificate(String certFile, KeyStore keyStore, PrintStream dbg)
    {
        if ( keyStore == null ) {
            dbg.println("Could not load cert into null keystore "); // can't load them yet
            return;
        }

        try {
            /* Opening & loading certificate file */
            FileInputStream     certIs = new FileInputStream(certFile);
            CertificateFactory  cf     = CertificateFactory.getInstance("X.509");

            dbg.println( "Certificate Factory provider is " + cf.getProvider() );

            Certificate  cert = cf.generateCertificate(certIs);

            certIs.close();

            /* Adding certificate into keystore */
            dbg.println("Keystore contains " + keyStore.size() + " certificates");
            keyStore.setCertificateEntry(certFile, cert);
            dbg.println("Added certificate " + certFile + " into keystore");
            dbg.println("Keystore contains " + keyStore.size() + " certificates");
        }
        catch(IOException e) {
            e.printStackTrace(dbg);
        }  
        catch ( CertificateException e ) {
            e.printStackTrace(dbg);
        }
        catch ( KeyStoreException e ) {
            e.printStackTrace(dbg);
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Trying to reproduce problem with https. artf235408");
        System.out.println("--------------------------------------------------"); 
        System.out.println();

        String trustStoreType="JKS";
        KeyStore  truststore = KeyStore.getInstance(trustStoreType);

        System.out.println( "Truststore provider is " + 
                truststore.getProvider() );
        System.out.println( "Truststore type is " + truststore.getType() );
        System.out.println( "Truststore default type is " + 
                KeyStore.getDefaultType() );

        String trustStoreName="truststore_ec_jsse.jks";
        System.out.println("truststore " + trustStoreName);

        File  trustStoreFile = new File(trustStoreName);
        if ( trustStoreFile.exists() ) {
            /* Loading keystore */
            FileInputStream  fis = new FileInputStream(trustStoreFile);
            truststore.load( fis, "changeit".toCharArray() );
            fis.close();
        }
        else {
            // create empty keystore
            truststore.load(null, null);
        }

        Set      certFiles = new HashSet();
        certFiles.add("/home/raf/repo/atop_cp/bb/java/test_valid/_telecom/test_ecall_le940b6/filesystem/app/certout/ca_ec.cer");
        // load certificates
        loadCertificates(certFiles, truststore, System.out);

        // save truststore
        FileOutputStream  fos = new FileOutputStream(trustStoreFile);
        truststore.store( fos, "changeit".toCharArray() );
        fos.close();

        // set truststore as default
        System.setProperty("javax.net.ssl.trustStore", trustStoreName);
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");

        String clientKeyStoreType="JKS";//""JCEKS";
        KeyStore  keystore = KeyStore.getInstance(clientKeyStoreType);

        String clientKeyStore = "keystore_ec_jsse.jks";
        if ( clientKeyStore != null ) {
            File  keyStoreFile = new File(clientKeyStore);
            if ( keyStoreFile.exists() ) {
                /* Loading keystore */
                FileInputStream  fis = new FileInputStream(keyStoreFile);
                keystore.load( fis, "changeit".toCharArray() );
                fis.close();
            }
            else {
                // create empty keystore
                keystore.load(null, null);
            }

            String clientKeyFile="/home/raf/repo/atop_cp/bb/java/test_valid/_telecom/test_ecall_le940b6/filesystem/app/certout/client_ec_pkcs8.key";

            String clientCertFile="/home/raf/repo/atop_cp/bb/java/test_valid/_telecom/test_ecall_le940b6/filesystem/app/certout/client_ec.cer";
            // load client key if needed
            loadKey(clientKeyFile, clientCertFile, keystore, System.out);

            // save keystore
            fos = new FileOutputStream(keyStoreFile);
            keystore.store( fos, "changeit".toCharArray() );
            fos.close();

            // set keystore as default
            System.setProperty("javax.net.ssl.keyStore", clientKeyStore);
            System.setProperty("javax.net.ssl.keyStorePassword", "changeit");
        }

        // try to connect
        System.out.println("trying to connect...");
        String host="atop.telit.com";
        int port=8548;
        URL                 url = new URL("https://" + host + ":" + port);
        HttpsURLConnection  con = (HttpsURLConnection)url.openConnection();
        con.setHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String hostname, 
                    SSLSession session) {
                return true;
            }
        });
        System.out.println("call to openConnection() done. ");


        System.out.println("calling getInputStream(): ");
        System.out.println("got " + getInputStreamLength( 
                con.getInputStream() ) + " bytes from server");

        System.out.println( "cert type: " + 
                con.getServerCertificates()[0].getClass().toString() );
        System.out.println( "cert : " + 
                con.getServerCertificates()[0].toString() );
        Certificate[] certs = con.getServerCertificates();
        dumpChain(certs, System.out);
        con.disconnect();
    }

}


