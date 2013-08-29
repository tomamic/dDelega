package edu.uiuc.cs.TrustBuilder2.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.util.encoders.Base64;

/**
 * A handful of useful functions for dealing with certificates.
 * 
 * @author Adam J. Lee (adamlee@cs.uiuc.edu)
 *
 */
public class CertificateUtils
{
    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";
    public static final int LINE_WIDTH = 64;
    
    
    /**
     * Private constructor to make this a singleton
     * 
     */
    private CertificateUtils(){
        super();
    }
    
    
    /**
     * Exports a certificate to a file in either Base64 (if binary=false) or
     * binary (if binary=true) format.
     * 
     * @param cert The certificate to export
     * @param file A File object representing where this certificate should be
     *             exported to
     * @param binary A flag indicating whether the certificate should be exported
     *               as Base64 or binary
     */
    public static void exportCert(final Certificate cert, final File file, final boolean binary)
    {
        final String lineSep = System.getProperty("line.separator");
        try {
            // Get the encoded form which is suitable for exporting
            final byte[] buf = cert.getEncoded();

            final FileOutputStream ostream = new FileOutputStream(file);
            if (binary) {
                ostream.write(buf);
            }
            else {
                // Write in text form
                final Writer writer = new OutputStreamWriter(ostream, Charset.forName("UTF-8"));
                writer.write(BEGIN_CERT);
                writer.write(base64EncodeBytes(buf));
                writer.write(lineSep + END_CERT + lineSep);
                writer.flush();
            }
            ostream.close();
        }
        // @PMD:REVIEWED:EmptyCatchBlock: by adamlee on 8/1/06 9:19 AM
        catch (Exception e){
            // do nothing
        }
        
    }  //-- end exportCertificate
    
    
    /**
     * Helper method that takes a byte array and returns a String
     * containing the Base64 representation of the byte array, with
     * line wrapes every LINE_WIDTH characters.
     *
     * @param buffer The buffer to encode
     *
     * @return The Base46 encoded version of buffer
     *
     */
    private static String base64EncodeBytes(final byte[] buffer)
    {
        final String lineSep = System.getProperty("line.separator");
        final StringBuffer strBuff = new StringBuffer();
        final byte[] output = Base64.encode(buffer);
        for(int i=0; i<output.length; i++){
            if((i % LINE_WIDTH) == 0){
                strBuff.append(lineSep);
            }
            strBuff.append((char)output[i]);
        }   

        return strBuff.toString();
    }
    
    
    /**
     * Imports a binary or base64 cert from a file
     * 
     * @param file The file to import from
     * 
     * @return The certificate if it loads, null if there's an error
     */
    public static Certificate importCertificate(final File file) 
    {
        try {
            final FileInputStream istream = new FileInputStream(file);
            final CertificateFactory certFac = CertificateFactory.getInstance("X.509");
            return certFac.generateCertificate(istream);
        } 
        catch (Exception e) {
            return null;
        }
    }

    
    
    /**
     * Exports a binary PKCS8-encoded private key to a file
     * 
     * @param key The private key to export
     * @param file The file to export to
     */
    public static void exportKey(final PrivateKey key, final File file)
    {
        try {
            // Get the encoded form which is suitable for exporting
            final byte[] buf = new PKCS8EncodedKeySpec(key.getEncoded()).getEncoded();
            final FileOutputStream ostream = new FileOutputStream(file);
            ostream.write(buf);
            ostream.close();
        }
        // @PMD:REVIEWED:EmptyCatchBlock: by adamlee on 8/1/06 9:20 AM
        catch (Exception e) {
            // Do nothing
        }
    }
    
    
    /**
     * Imports a binary, DER-encoded, PKCS8 private key from a file.  Currently
     * supported private key types are:
     * 
     * <ul>
     *   <li>RSA
     *   <LI>DSA
     *   <li>Elliptic Curve
     * </ul>
     * 
     * @param file The file to import from
     * @param cert The certificate that this private key is associated with.  This
     *             allows us to infer the type of the certificate
     * 
     * @return The PrivateKey object on success, null on failure
     */
    public static PrivateKey importPrivateKey(final File file, final Certificate cert)
    {
        try{
            final FileInputStream istream = new FileInputStream(file);
            final KeyFactory keyFac;
            
            // set up the key factory based on the keytype used in the certificate
            if(cert.getPublicKey() instanceof RSAPublicKey){            
                keyFac = KeyFactory.getInstance("RSA");
            }
            else if(cert.getPublicKey() instanceof DSAPublicKey){
                keyFac = KeyFactory.getInstance("DSA");
            }
            else if(cert.getPublicKey() instanceof ECPublicKey){
                keyFac = KeyFactory.getInstance("EC");
            }
            
            // unsupported key type
            else{
                return null;
            }
            
            // actually load the key
            final byte[] keyBytes = new byte[((int)file.length())];
            istream.read(keyBytes, 0, ((int)file.length()));
            return keyFac.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        }
        catch(Exception e){
            return null;
        }
    }
    
    
    /**
     * Given a certificate, compute its MD5 fingerprint.
     * 
     * @param cert A certificate
     * @return The MD5 fingerprint of the provided certificate, formatted as
     *         a hex string where each byte is separated by :'s
     * @throws NoSuchAlgorithmException If an MD5 message digest can't be created
     * @throws CertificateEncodingException If the certificate can't be encoded for some reason
     * 
     */
    public static byte[] getFingerprint(final Certificate cert) throws NoSuchAlgorithmException, CertificateEncodingException
    {
        final MessageDigest digest = MessageDigest.getInstance("MD5");
        digest.update(cert.getEncoded());
        return digest.digest();
        
    }  //-- end getFingerprint(Certificate)
    
    
    /**
     * Encodes a byte array as a hex string where each byte is separated by
     * a ':' character
     * 
     * @param bytes The byte array to encode
     * @return The encoded byte array
     */
    public static String hexEncode(final byte[] bytes)
    {
        if(bytes == null){
            return "";
        }
        
        final StringBuffer strBuff = new StringBuffer();
        String oneByte;
        for(int i=0; i<bytes.length; i++){
            if(i>0){
                strBuff.append(':');
            }
            oneByte = Integer.toHexString(bytes[i] & 0xff);
            if(oneByte.length() == 1){
                oneByte = "0" + oneByte;
            }
            strBuff.append(oneByte);
        }
        return strBuff.toString().toUpperCase();
        
    }  //-- end hexEncode(byte[])
    
    
}  //-- end class CertificateUtils
