package negoUtil;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import sun.misc.BASE64Encoder;

public class TrustToken {
	
	private static byte[] secret;
	private static byte[] lifetimeToken;
	private static byte[] clientCertToken;
 	
	//base64 string of trustToken
	private static String trustToken;
	
	static Certificate cert;
	private static PrivateKey privateKey;
	
	static String certPath;
	static String secretPath;
	static String privateKeyPath;
	
	// Signature algorithm used if this cert holds an RSA key pair */
    public static final String RSA_SIG_ALG = "SHA1WithRSAEncryption";
    
    // Signature algorithm used if this cert holds a DSA key pair */
    public static final String DSA_SIG_ALG = "SHA1WithDSA";
    
    // Signature algorithm used if this cert holds an Elliptic curve key pair */
    public static final String EC_SIG_ALG = "SHA1WithECDSA";
	
	
	public TrustToken(String config_file)	{
		
		Properties properties = new Properties();
		try {
		    properties.load(new FileInputStream(config_file));
		} catch (IOException e) {
			
			e.printStackTrace();
		}
		
		certPath = properties.getProperty("certPath");
		secretPath = properties.getProperty("secretPath");
		privateKeyPath = properties.getProperty("privateKeyPath");
		
	}
	
	
	public void setConfiguration ()
	{
		importCertificate();
		importPrivateKey();		
	}
	
	//crea il token da rilasciare dopo la negoziazione
	public static String createTrustToken (String lifetimeText, String clientCert) throws Exception
	{
		
		lifetimeToken = new sun.misc.BASE64Decoder().decodeBuffer(lifetimeText);
		if (clientCert != null) clientCertToken = new sun.misc.BASE64Decoder().decodeBuffer(clientCert);
		
		//viene caricato il token segreto condiviso tra STS e Web Service
		
		File secretFile = new File(secretPath);
		BufferedInputStream bis;
		try {
			bis = new BufferedInputStream(new FileInputStream(secretFile));
		} catch(FileNotFoundException e) {
			throw new Exception("Could not locate keyfile at '" + secretPath + "'", e);
		}
		secret = new byte[(int)secretFile.length()];
		bis.read(secret);
		bis.close();

		
		
		try{
            
			Security.addProvider(new BouncyCastleProvider());
            Signature sig = null;
			// If this cert holds an RSA key pair...
            if(privateKey instanceof RSAPrivateKey){
                sig = Signature.getInstance(RSA_SIG_ALG);
            }
            
            // If it's a DSA key pair...
            else if(privateKey instanceof DSAPrivateKey){
                sig = Signature.getInstance(DSA_SIG_ALG);
            }
            
            // If it's an elliptic curve key pair
            else if(privateKey instanceof ECPrivateKey){
                sig = Signature.getInstance(EC_SIG_ALG);
            }            
           
            
            // calcolo della signature, ovvero il TrustToken
            sig.initSign(privateKey);
            sig.update(secret);
            sig.update(lifetimeToken);
            if (clientCert!= null) sig.update(clientCertToken);
            byte[] trustTokenByte = sig.sign();
            trustToken = new BASE64Encoder().encode(trustTokenByte);
            
		}
		catch (Exception e){
			
			e.printStackTrace();
		}
		
		return trustToken;
	}
	
	//verifica la validità del token di sicurezza
	public boolean verifyTrustToken (String timestampText, String clientCertString, String trustToken) throws Exception
	{
		
		lifetimeToken = new sun.misc.BASE64Decoder().decodeBuffer(timestampText);
		if (clientCertString != null) clientCertToken = new sun.misc.BASE64Decoder().decodeBuffer(clientCertString);
		
		//viene caricato il token segreto condiviso tra STS e Web Service
		
		File secretFile = new File(secretPath);
		BufferedInputStream bis;
		try {
			bis = new BufferedInputStream(new FileInputStream(secretFile));
		} catch(FileNotFoundException e) {
			throw new Exception("Could not locate keyfile at '" + secretPath + "'", e);
		}
		secret = new byte[(int)secretFile.length()];
		bis.read(secret);
		bis.close();

		boolean tokenVerified = false;
		
		try{
            
			Security.addProvider(new BouncyCastleProvider());
            Signature sig = null;
            if(cert.getPublicKey() instanceof RSAPublicKey){
                sig = Signature.getInstance(RSA_SIG_ALG);
            }
            else if(cert.getPublicKey() instanceof DSAPublicKey){
                sig = Signature.getInstance(DSA_SIG_ALG);
            }
            else if(cert.getPublicKey() instanceof ECPublicKey){
                sig = Signature.getInstance(EC_SIG_ALG);
            }
		 
		
		sig.initVerify(cert);
		sig.update(secret);
        sig.update(lifetimeToken);
        if (clientCertString != null) sig.update(clientCertToken);
        byte[] trustTokenByte = new sun.misc.BASE64Decoder().decodeBuffer(trustToken);
        tokenVerified = sig.verify(trustTokenByte);
        
		}
        catch (Exception e) {
           	e.printStackTrace();            
           }
		
		
		return tokenVerified;
	}
	
	//importa il certificato dell'STS
	private static void importCertificate() 
    {
	  if ( certPath != null )
	  {
		
		File certFile = new File(certPath);
		
        try {
            final FileInputStream istream = new FileInputStream(certFile);
            final CertificateFactory certFac = CertificateFactory.getInstance("X.509");
            cert = certFac.generateCertificate(istream);
        } 
        catch (Exception e) {
        	e.printStackTrace();            
        }
	  }    
	}
	  
	
	//viene importata la chiave privata (dell'STS)
	private static void importPrivateKey()
    {
       
	  if ( privateKeyPath != null )
	  {
		
		File keyFile = new File(privateKeyPath);
		
		try{
            final FileInputStream istream = new FileInputStream(keyFile);
            KeyFactory keyFac = null;
            
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
            
            
            // carico la chiave
            final byte[] keyBytes = new byte[((int)keyFile.length())];
            istream.read(keyBytes, 0, ((int)keyFile.length()));
            privateKey = keyFac.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        }
        catch(Exception e){
        	e.printStackTrace();            
        }
	  }
    }

}//fine classe TrustToken
