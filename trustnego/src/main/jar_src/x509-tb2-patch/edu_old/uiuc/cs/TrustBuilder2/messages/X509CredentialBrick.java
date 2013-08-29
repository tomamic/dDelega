package pkg.edu.uiuc.cs.TrustBuilder2.messages;

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERString;

import pkg.edu.uiuc.cs.TrustBuilder2.state.Session;
import pkg.edu.uiuc.cs.TrustBuilder2.util.CertificateUtils;
import pkg.edu.uiuc.cs.TrustBuilder2.util.StaticFunctions;


/**
 * An extension to the AbstractCredentialBrick class to handle the processing
 * of attribute values from X.509 certificates.  
 * 
 * @author Adam Lee <adamlee@cs.uiuc.pkg.edu>
 *
 */
public class X509CredentialBrick extends AbstractCredentialBrick // NOPMD by adamlee on 2/1/07 1:33 PM
{
    /** For serialization purposes */
    private static final long serialVersionUID = -4378413926867342800L;
    
    /** Key used to get the filename storing OID to name mappings */
    public static final String KEY_OID_MAP_FILE = "edu.uiuc.cs.TrustBuilder2.messages.X509CredentialBrick.oidMapfile";
    
    /** The type of this credential brick */
    public static final String TYPE = "X.509";
    
    /** Signature algorithm used if this cert holds an RSA key pair */
    public static final String RSA_SIG_ALG = "SHA1WithRSAEncryption";
    
    /** Signature algorithm used if this cert holds a DSA key pair */
    public static final String DSA_SIG_ALG = "SHA1WithDSA";
    
    /** Signature algorithm used if this cert holds an Elliptic curve key pair */
    public static final String EC_SIG_ALG = "SHA1WithECDSA";
    
    /** The underlying certificate behind this credential brick */
    protected X509Certificate certificate;
    
    /**
     * The private key associated with this certificate. Used only to compute
     * proof of ownership values. This is transient so that it is never
     * accidentally serialized and sent over the wire to the remote party.
     */
    protected transient PrivateKey privateKey;
    
    /** A map associating X.509 extension OIDs to field names */
    protected transient Map<String, String> OIDsToNames;
    
    /** A list of OIDs to ignore */
    protected Set<String> OIDsToIgnore;
    
    /** The logger used by this class (shouldn't be serialized) */
    private static final transient Logger logger = Logger.getLogger(X509CredentialBrick.class.getName());
    
    /** 
     * Were any critical extensions misunderstood?  This variable only makes sense
     * if the extracted boolean is also true.
     */
    protected boolean criticalError;
    
    /** The proof of ownership value, if computed */
    protected byte[] proofOfOwnership = null;
    
    
    /**
     * Basically just sets up the underlying X.509 certificate, the mapping of OIDs
     * to attribute names, and the list of OIDs to ignore.  The following OIDs are
     * ignored by default, as they are either not supported or are used only
     * for credential chain validation (and thus will likely not come into play
     * during policy evaluation):
     * 
     *   - 2.5.29.15 (Key Usage)
     *   - 2.5.29.32 (Certificate Policies)
     *   - 2.5.29.17 (Subject Alternative Name)
     *   - 2.5.29.19 (Basic Constraints)
     *   - 2.5.29.30 (Name Constraints)
     *   - 2.5.29.36 (Policy Constraints)
     *   - 2.5.29.37 (Extended Key Usage)
     *   - 2.5.29.54 (Inhibit Any-Policy)
     * 
     * @param certificate The X.509 certificate that this CredentialBrick is based on
     * @param rid The resource ID for this credential
     * 
     * @throws IllegalArgumentException if either certificate, OIDsToNames, or rid
     *                                  is null, or if rid contains whitespace
     */
    public X509CredentialBrick(X509Certificate certificate, String rid) throws IllegalArgumentException
    {
        this(certificate, null, rid, null);
    }
    
    
    /**
     * Basically just sets up the underlying X.509 certificate, the mapping of OIDs
     * to attribute names, and the list of OIDs to ignore.  The following OIDs are
     * ignored by default, as they are either not supported or are used only
     * for credential chain validation (and thus will likely not come into play
     * during policy evaluation):
     * 
     *   - 2.5.29.15 (Key Usage)
     *   - 2.5.29.32 (Certificate Policies)
     *   - 2.5.29.17 (Subject Alternative Name)
     *   - 2.5.29.19 (Basic Constraints)
     *   - 2.5.29.30 (Name Constraints)
     *   - 2.5.29.36 (Policy Constraints)
     *   - 2.5.29.37 (Extended Key Usage)
     *   - 2.5.29.54 (Inhibit Any-Policy)
     * 
     * @param certificate The X.509 certificate that this CredentialBrick is based on
     * @param rid The resource ID for this credential
     * @param pid The resource ID of the policy protecting this credential
     * 
     * @throws IllegalArgumentException if either certificate, OIDsToNames, or rid
     *                                  is null, or if either id contains whitespace
     */
    public X509CredentialBrick(X509Certificate certificate, String rid, String pid) throws IllegalArgumentException
    {
        this(certificate, null, rid, pid);
    }
    
    
    /**
     * Basically just sets up the underlying X.509 certificate, its associated 
     * private key, the mapping of OIDs to attribute names, and the list of OIDs to 
     * ignore.  The following OIDs are ignored by default, as they are either not 
     * supported or are used only for credential chain validation (and thus will 
     * likely not come into play during policy evaluation):
     * 
     *   - 2.5.29.15 (Key Usage)
     *   - 2.5.29.32 (Certificate Policies)
     *   - 2.5.29.17 (Subject Alternative Name)
     *   - 2.5.29.19 (Basic Constraints)
     *   - 2.5.29.30 (Name Constraints)
     *   - 2.5.29.36 (Policy Constraints)
     *   - 2.5.29.37 (Extended Key Usage)
     *   - 2.5.29.54 (Inhibit Any-Policy)
     * 
     * @param certificate The X.509 certificate that this CredentialBrick is based on
     * @param privateKey The private key associated with this certificate.  This is
     *                   used to compute proof of ownership values and is never
     *                   transmitted to remote entities.
     * @param rid The resource ID for this credential
     * 
     * @throws IllegalArgumentException if either certificate, OIDsToNames, or rid
     *                                  is null, or if either id contains whitespace
     *                                   
     */
    public X509CredentialBrick(X509Certificate certificate, PrivateKey privateKey, String rid) throws IllegalArgumentException
    {
        this(certificate, privateKey, rid, null);
    }
    
    
    /**
     * Basically just sets up the underlying X.509 certificate, its associated 
     * private key, the mapping of OIDs to attribute names, and the list of OIDs to 
     * ignore.  The following OIDs are ignored by default, as they are either not 
     * supported or are used only for credential chain validation (and thus will 
     * likely not come into play during policy evaluation):
     * 
     *   - 2.5.29.15 (Key Usage)
     *   - 2.5.29.32 (Certificate Policies)
     *   - 2.5.29.17 (Subject Alternative Name)
     *   - 2.5.29.19 (Basic Constraints)
     *   - 2.5.29.30 (Name Constraints)
     *   - 2.5.29.36 (Policy Constraints)
     *   - 2.5.29.37 (Extended Key Usage)
     *   - 2.5.29.54 (Inhibit Any-Policy)
     * 
     * @param certificate The X.509 certificate that this CredentialBrick is based on
     * @param privateKey The private key associated with this certificate.  This is
     *                   used to compute proof of ownership values and is never
     *                   transmitted to remote entities.
     * @param rid The resource ID for this credential
     * @param pid The resource ID of the policy protecting this credential
     * 
     * @throws IllegalArgumentException if either certificate, OIDsToNames, or rid
     *                                  is null, or if either id contains whitespace
     *                                   
     */
    public X509CredentialBrick(X509Certificate certificate, PrivateKey privateKey, String rid, String pid) throws IllegalArgumentException
    {
        // Call AbstractCredentialBrick constructor
        super(rid, pid);
        
        // throw an exception if either argument is null
        if( certificate == null ){
            throw new IllegalArgumentException("Null parameter supplied to X509CredentialBrick constructor.");
        }
        
        // set up the fields map
        fields = new HashMap<String, String>();
        
        // set user-supplied params
        this.certificate = certificate;
        this.OIDsToNames = loadOidMap();
        this.privateKey = privateKey;
        
        // see if we're the local owner of this cred
        if(privateKey != null){
            this.localOwner = true;
        }
        
        // set up the default list of OIDS to ignore
        OIDsToIgnore = new HashSet<String>();
        OIDsToIgnore.add("2.5.29.15");
        OIDsToIgnore.add("2.5.29.32");
        OIDsToIgnore.add("2.5.29.17");
        OIDsToIgnore.add("2.5.29.19");
        OIDsToIgnore.add("2.5.29.30");
        OIDsToIgnore.add("2.5.29.36");
        OIDsToIgnore.add("2.5.29.37");
        OIDsToIgnore.add("2.5.29.54");
        
        // no critical error has occurred yet
        criticalError = false;
        
        // set type
        format = TYPE;
        
    }  //-- end X509v3CredentialBrick(X509Certificate, Map<String, String>)
    
    
    /**
     * Loads the mapping of OID numbers to attribute names specified by the
     * file indicated by the system property 
     * "pkg.edu.uiuc.cs.TrustBuilder2.messages.X509CredentialBrick.oidMapFile"
     * 
     * @return A mapping of OID numbers to attribute names, or an empty map
     *         if there was an error reading the map file.
     */
    private static Map<String,String> loadOidMap()
    {
        final HashMap<String,String> oidMap = new HashMap<String,String>();
        final String mapFile = /*"C:\\Users\\filo\\eclipse_workspace\\STSNegotiation\\src\\config\\OidMapFile.txt";*/System.getProperty(KEY_OID_MAP_FILE);
        
        // if no map file is specified, flag a warning
        if(mapFile == null){
            logger.warning("OID map file not defined.");
        }
        
        // If an OID map file is specified, load up the mappings it contains
        else{
            try{
                final BufferedReader reader = new BufferedReader(new FileReader(mapFile));
                String line = reader.readLine();
                while(line != null){
                    processLine(line, oidMap);
                    line = reader.readLine();
                }
            }
            catch(Exception e){
                logger.warning("Error reading OID map file.");
            }
        }
        
        // return the mapping
        return oidMap;
        
    }  //-- end loadOidMap()
    
    
    /**
     * Given a line from an OID map file and an OID map, parse that line.  If
     * the line is null, contains a comment, or is not a valid definition of
     * form [oid] = [name], then just return.  Otherwise, split the line and
     * add a mapping from [oid] to [name] in the specified map object.
     * 
     * @param line The line to process
     * @param oidMap A map from OID numbers to names
     * 
     */
    private static void processLine(final String line, final Map<String,String> oidMap)
    {
        // Return if the line is null, a comment, or does not contain an
        // <oid> = <value> mapping
        if( (line == null) || line.trim().startsWith("#") || !line.matches(".+=.+") ){
            return;
        }
        
        // Split this definition and insert it into the oidMap
        final int pos = line.indexOf('=');
        oidMap.put(line.substring(0, pos-1).trim(), line.substring(pos+1, line.length()).trim());
        
    }  //-- end process line
    

    /**
     * Allows the addition of OIDs to the list of ignored OIDs
     * 
     * @param OIDs A Collection of OID strings to ignore
     * 
     */
    public void addOIDsToIgnore(final Collection<String> OIDs)
    {
        OIDsToIgnore.addAll(OIDs);
    }
    
    
    /**
     * Checks to see if this credential was indeed issued by the owner of
     * the supplied parent credential.
     * 
     * @param parent The credential whose private key was used to sign the
     *               credential represented by this AbstractCredentialBrick.  For
     *               X509CredentialBricks, parent must be an X509CredentialBrick.
     * 
     * @return true if this credential was signed by parent and the date is within
     *         the credential's validity period, false otherwise
     * 
     */
    public boolean validate(final AbstractCredentialBrick parent)
    {
        this.syntaxValidated = true;
        
        // extract values if needed, make sure no critical extensions are
        // misunderstood.  Validity check should fail if there were misunderstandings
        // of critical extension OIDs
        if(!extracted){
            extractFields();
        }
        if(criticalError){
            logger.severe("Critical OID not understood, validation has failed.");
            return false;
        }
        
        // If this cred wasn't issued by the parent, don't even bother checking
        // the more expensive things
        if(!isPotentialChildOf(parent)){
            logger.severe("Credential not issued by this parent, validation has failed.");
            return false;
        }
        
        try{
            // Make sure it's signed by this parent AND within its validity window
            final X509CredentialBrick x509Parent = (X509CredentialBrick)parent;
            certificate.verify(x509Parent.certificate.getPublicKey());
            certificate.checkValidity();
            
            // if we get here, it's valid
            this.syntaxValid = true;
            return syntaxValid;
        }
        
        // If there's an error, return false
        catch(Exception e){
            logger.severe("Error validating credential: " + e.getMessage());
            return false;
        }
        
    }   //-- end validate(AbstractCredentialBrick)
    
    
    /**
     * Helper method to determine whether this credential is self-signed
     * 
     * @return true if isPotentialChildOf(this) is true, false otherwise
     * 
     */
    public boolean isSelfSigned()
    {
        return isPotentialChildOf(this);
    }
    
    
    /**
     * Helper method to determine if this child could have been issued by the
     * supplied parent credential.  This method does not call validate(), so we
     * cannot be sure that this credential was issued by the supplied parent.  This
     * method is helpful when constructing credential chains.
     * 
     * @param parent The possible parent credential
     * 
     * @return true if parent could have issued this credential, false otherwise
     */
    public boolean isPotentialChildOf(final AbstractCredentialBrick parent)
    {
        // For now just compare subject and issuer names (ignoring case).
        // TODO:  Check out RFC 3280 and do this the right way
        if(parent instanceof X509CredentialBrick){
            final X509CredentialBrick X509Parent = (X509CredentialBrick)parent;
            return getIssuer().equalsIgnoreCase(X509Parent.getSubject());
        }
        
        // If the parent wasn't an X509 cred, return false
        return false;
        
    }
    
    
    /**
     * Extracts the field information from the certificate and populates the member
     * variables needed for the getSubject(), getIssuer() and getFields() methods
     * to work correctly.  This method should set the "extracted" variable to true.
     * 
     * @return true on success, false on failure
     *  
     */
    public boolean extractFields() // NOPMD by adamlee on 2/1/07 1:33 PM
    {
        // short-circuit if we've done this already
        if(extracted){
            return true;
        }
        extracted = true;
        
        try{
            // recreate the OID map from the system files if needed
            if(OIDsToNames == null){
                OIDsToNames = loadOidMap();
            }
            
            // get the subject name
            subject = certificate.getSubjectX500Principal().getName();
            
            // get the issuer name
            issuer = certificate.getIssuerX500Principal().getName();
            
            // reset fields map
            fields = new HashMap<String,String>();
            
            // set the fingerprint
            fingerprint = CertificateUtils.hexEncode(CertificateUtils.getFingerprint(certificate));
            
            // extract critical extensions (remove ignored OIDs)
            Set<String> extensions = certificate.getCriticalExtensionOIDs();
            String name, value;
            if(extensions != null)
            {
                extensions.removeAll(OIDsToIgnore);
                for(String oid : extensions){
                    // get the name and value of this oid
                    name = OIDsToNames.get(oid);
                    value = getExtensionValueAsString(certificate.getExtensionValue(oid));
                    
                    // If we don't know what this critical OID is or we can't extract
                    // its value, abort mission!
                    if( (null == name) || (null == value) ){
                        criticalError = true;
                        logger.severe("Error extracting name or value for critical OID " + oid + " (name = " + name + ", value = )" + value);
                        return false;
                    }
                    
                    // if we know both the name and value, insert it!
                    fields.put(name, value);
                }
            }
            
            // extract non-critical extensions (remove ignored OIDs)
            extensions = certificate.getNonCriticalExtensionOIDs();
            if(extensions != null)
            {
                extensions.removeAll(OIDsToIgnore);
                for(String oid : extensions){
                    name = OIDsToNames.get(oid);
                    value = getExtensionValueAsString(certificate.getExtensionValue(oid));
                    
                    // if we don't know the name, insert the oid instead.  Since it's
                    // non-critical, we don't care!
                    if(null == name){
                        name = oid;
                    }
                    
                    // insert it if the value is non-null
                    if(null != value){
                        fields.put(name, value);
                    }
                }
            }
            
            // if we got here, it's all good
            return true;
        }
        
        // return false if any exception conditions arise
        catch(Exception e){
            logger.severe("Error in field extraction: " + e);
            return false;
        }
        
    }  //-- end extractFields()
    
    
    /**
     * Checks to see if a critical error occured during extraction.  The result of
     * this method call only makes sense if the extractFields() method has already
     * been invoked.
     * 
     * @return true if a critical error occurred, false otherwise
     */
    public boolean getCriticalError()
    {
        return criticalError;
    }
    
    
    /**
     * Given the byte-level representation of an X.509 extension, this function
     * extracts the String representation of the extension.  Currently, only
     * extensions of type DERInteger or extensions implementing the DERString
     * interface are supported.
     * 
     * @param extensionBytes The byte-level representation of an X.509 extension
     * 
     * @return The string representation of extensionBytes; null if an error occurs
     *         or the extension type is not currently supported by this class
     */
    protected String getExtensionValueAsString(final byte[] extensionBytes)
    {
        try{
            /*  The ASN.1 definition for X.509 v3 extensions is:
             *
             *  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
             *
             *  Extension  ::=  SEQUENCE  {
             *       extnId        OBJECT IDENTIFIER,
             *       critical      BOOLEAN DEFAULT FALSE,
             *       extnValue     OCTET STRING
             *                     -- contains a DER encoding of a value
             *                     -- of the type registered for use with
             *                     -- the extnId object identifier value
             *   }
             *   
             *   Notice that each extension is encoded as an octet string.  The
             *   following code pulls out the extension as an octet string and then
             *   pulls the DER encoded extension out of that octet string.  This
             *   object is represented as a DERObject.
             */
            final DERObject derObj = new ASN1InputStream(
                    ((DEROctetString) (new ASN1InputStream(extensionBytes)
                            .readObject())).getOctets()).readObject();
        
            // parse it if it's a string (this includes ALL string representations)
            if(derObj instanceof DERString){
                return ((DERString)derObj).getString();
            }
            
            // parse it if it's an integer
            if(derObj instanceof DERInteger){
                return ((DERInteger)derObj).getValue().toString();
            }
            
            // if we don't know how to parse this type, return null
            return null;
        }
        
        // return null on error
        catch(Exception e){
            logger.info("Error extracting OID value: " + e.getMessage());
            return null;
        }
        
    }  //-- end getExtensionValueAsString(byte[])
    
    
    /**
     * Checks the proof of ownership associated with this CredentialBrick.  This
     * works by verifying that the attached proof of ownership value is a signature
     * computed over the local signature material stored in the provided Session
     * object.
     * 
     * @param session The Session in which the proof of ownership is to be checked
     * 
     * @return true if proof of ownership value checks out, false otherise
     * 
     */
    public boolean checkProofOfOwnership(final Session session)
    {
        // If the proofOfOwnership array is null, then the proof is certainly invalid
        if(proofOfOwnership == null){
            return false;
        }
        
        Signature sig;
        try{
            // set up for the supported key types
            if(certificate.getPublicKey() instanceof RSAPublicKey){
                sig = Signature.getInstance(RSA_SIG_ALG);
            }
            else if(certificate.getPublicKey() instanceof DSAPublicKey){
                sig = Signature.getInstance(DSA_SIG_ALG);
            }
            else if(certificate.getPublicKey() instanceof ECPublicKey){
                sig = Signature.getInstance(EC_SIG_ALG);
            }
            
            // fail if we don't support this key type
            else{
                logger.severe("Proof of ownership verification error, unsupported key type: " + certificate.getPublicKey().getClass().getName());
                return false;
            }
            
            // actually check the signature
            sig.initVerify(certificate);
            sig.update(StaticFunctions.byteListToArray(session.getLocalSignatureMaterial()));
            owned = sig.verify(proofOfOwnership);
            return owned;
            
        }
        catch(Exception e){
            logger.severe("Proof of ownership verification error: " + e.getMessage());
            return false;
        }
        
    }  //-- end checkProofOfOwnership(Session)


    /**
     * Sets the proof of ownership associated with this X509CredentialBrick.  This
     * happens by signing the signature material supplied by the remote party using
     * the private key associated with this credential.  Currently, this method
     * works for X509CredentialBricks whose certificates contain the following
     * types of key pairs:
     * 
     * <ul>
     *    <li>RSA (using the signature method SHA1WithRSAEncryption)
     *    <li>DSA (using the signature method SHA1WithDSA)
     *    <li>Elliptic Curve (using the signature method SHA1WithECDSA)
     * </ul>
     * 
     * This method returns true if the proof of ownership value can be computed and
     * false otherwise.  Reasons why this method may fail include:
     * 
     * <ul>
     *   <li>This X509CredentialBrick contains a certificate whose private key is
     *       of an unsupported type
     *   <li>There is no appropriate cryptography provider installed
     *   <li>The private key associated with this X509CredentialBrick is invalid
     * </ul>
     * 
     * @param session The Session object containing the key material needed to
     *                compute the proof of ownership value
     *                
     * @return true on success, false under the error conditions described above
     * 
     */
    public boolean setProofOfOwnership(final Session session)
    {
        if(privateKey == null){
            return false;
        }
        
        try{
            Signature sig;
            
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
            
            // We don't support other signature types yet
            else{
                logger.severe("Proof of ownership computation error, unsupported private key type: " + privateKey.getClass().getName());
                return false;
            }
            
            // Actually compute the signature
            sig.initSign(privateKey);
            sig.update(StaticFunctions.byteListToArray(session.getRemoteSignatureMaterial()));
            proofOfOwnership = sig.sign();
            return true;
        }
        catch(Exception e){
            logger.severe("Proof of ownership computation error: " + e.getMessage());
            return false;
        }
        
    }  //-- end setProofOfOwnership(Session)
    
    
    //aggiunto da Filippo Agazzi - 1/6/2012
    
    public void setProofOfOwnership ( byte[] proof )
    {
    	proofOfOwnership = proof;
    }
    
    //aggiunto da Filippo Agazzi - 1/6/2012
    
    public byte[] getProofOfOwnership()
    {
    	return proofOfOwnership;
    }
    

    /**
     * Gets the underlying X509Certificate object associated with this
     * X509CredentialBrick.
     * 
     * @return This credential brick's underlying X509Certificate
     * 
     */
    public X509Certificate getCertificate()
    {
        return certificate;
    }
    
    
    /**
     * Gets the private key associated with this X509CredentialBrick
     * 
     * @return The private key associated with this X509CredentialBrick
     * 
     */
    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }
    
    
}  //-- end class X509CredentialBrick