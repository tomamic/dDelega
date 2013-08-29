package edu.uiuc.cs.TrustBuilder2.query.profile;

import java.io.File;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

import edu.uiuc.cs.TrustBuilder2.messages.AbstractCredentialBrick;
import edu.uiuc.cs.TrustBuilder2.messages.ClaimBrick;
import edu.uiuc.cs.TrustBuilder2.messages.X509CredentialBrick;
import edu.uiuc.cs.TrustBuilder2.plugins.CredentialLoader;
import edu.uiuc.cs.TrustBuilder2.query.InvalidLoaderFileException;
import edu.uiuc.cs.TrustBuilder2.util.CertificateUtils;

/**
 * This credential loader instantiates X509CredentialBrick objects from descriptions
 * contained in a loader file.  The format of this loader file should be as follows:
 * 
 * <pre>
 * loaderClass = edu.uiuc.cs.TrustBuilder2.query.profile.X509FlatFileLoader
 * certificate_file_1 = <path to Base64-encoded certificate>
 * private_key_file_1 = <path to DER-encoded private key>
 * rid_1 = <resource id>
 * pid_1 = <policy id (optional)>
 *   .
 *   .
 *   .
 * certificate_file_m = <path to Base64-encoded certificate>
 * private_key_file_m = <path to DER-encoded private key>
 * rid_m = <resource id>
 * pid_m = <policy id (optional)>
 * </pre>
 * 
 * That is, the loader file specifies the paths to each certificate and its
 * associated private key.  The resource id and (optionally) policy id of each 
 * certificate can also be specified.  Note that the path to the private key is 
 * optional and will likely only be present in certificates at the leaves of 
 * certificate chains.
 * 
 * During the processing of the loader file, a counter variable is initialized to 1.
 * At each iteration, the key ("certificate_file_" + counter) is searched for.  If
 * found, the corresponding private key is also loaded and an
 * X509CredentialBrick object is created.  The counter variable is then
 * incremented.  The first time that the key ("certificate_file_" + counter) is not
 * found, the algorithm terminates.
 * 
 * @author Adam J. Lee (adamlee@cs.uiuc.edu)
 * 
 */
public class X509FlatFileLoader implements CredentialLoader
{
    /** The name of this class */
    public static final String NAME = "X.509 Flat-file Credential Loader";
    
    /** Key prefix used for retrieving certificate file paths from loader files */
    protected static final String CERT = "certificate_file_";
    
    /** Key prefix used for retrieving private key file names from loader files */
    protected static final String KEY = "private_key_file_";
    
    /** Key prefix used for retrieving OID maps from loader files */
    protected static final String MAP = "oid_map_";
    
    /** Key prefix used when retrieving resource IDs */
    protected static final String RID = "rid_";
    
    /** Key prefix used when retrieving policy IDs */
    protected static final String PID = "pid_";
    
    /** logger */
    protected static final Logger logger = Logger.getLogger(X509FlatFileLoader.class.getName());
    
    /**
     * Loads the list of credentials described by the specified loader file
     * according to the algorithm described in this loader's description.
     * 
     * @param loaderFile The Properties object derived from a loader file
     * 
     * @return A List<X509CredentialBrick> containing entries for each X.509
     *         credential described in the loader file
     *         
     * @throws InvalidLoaderFileException if the loader file does not conform to
     *         the specification described in this loader's description.
     *         
     */
    public List<? extends AbstractCredentialBrick> loadCredentials(final Properties loaderFile) throws InvalidLoaderFileException
    {
        // throw an exception if this is the wrong loader
        if(loaderFile == null){
            throw new InvalidLoaderFileException("Null loader file.");
        }
        if(!loaderFile.getProperty(ProfileManager.KEY_LOADER_CLASS, "").equals(X509FlatFileLoader.class.getName())){
            throw new InvalidLoaderFileException("Wrong loader class.");
        }
        
        // The list of creds that we'll populate
        final List<X509CredentialBrick> creds = new ArrayList<X509CredentialBrick>();
        String cert = null, key = null, rid = null, pid = null;
        Certificate theCert = null;
        
        // iterate over the Properties file and extract credentials
        int counter = 1;
        cert = loaderFile.getProperty(CERT + counter);
        key = loaderFile.getProperty(KEY + counter);
        rid = loaderFile.getProperty(RID + counter);
        pid = loaderFile.getProperty(PID + counter);
        
        
        
        while( (cert != null) && (rid != null) )
        {
            rid = rid.trim();
            if(pid != null){
                pid = pid.trim();
            }
            
            // create the object if possible
            // @PMD:REVIEWED:AvoidInstantiatingObjectsInLoops: by adamlee on 8/1/06 9:28 AM
            theCert = CertificateUtils.importCertificate(new File(cert));
            if(theCert instanceof X509Certificate){
                if(key == null){
                    // @PMD:REVIEWED:AvoidInstantiatingObjectsInLoops: by adamlee on 8/1/06 9:28 AM
                    creds.add(new X509CredentialBrick((X509Certificate)theCert, null, rid, pid));
                }
                else{
                    // @PMD:REVIEWED:AvoidInstantiatingObjectsInLoops: by adamlee on 8/1/06 9:28 AM
                	System.out.println("privata key imported:" + CertificateUtils.importPrivateKey(new File(key), theCert).toString());
                    creds.add(new X509CredentialBrick((X509Certificate)theCert, CertificateUtils.importPrivateKey(new File(key), theCert), rid, pid));
                }
            }
            // next iteration
            counter++;
            cert = loaderFile.getProperty(CERT + counter);
            key = loaderFile.getProperty(KEY + counter);
            rid = loaderFile.getProperty(RID + counter);
            pid = loaderFile.getProperty(PID + counter);
        }
        
        // if we make it here, return!
        logger.info("Loaded " + creds.size() + " credentials");
        return creds;
        
    }  //-- end loadCredentials(Properties)
    
    
    /**
     * If for some reason this loader is invoked to load claims, just return an
     * empty list of ClaimBricks
     */
    public List<ClaimBrick> loadClaims(final Properties loaderFile)
    {
        return new ArrayList<ClaimBrick>();
    }
    
    /**
     * This class does load credentials
     */
    public boolean loadsCredentials()
    {
        return true;
    }
    
    /**
     * This class does not load claims
     */
    public boolean loadsClaims()
    {
        return false;
    }
    
    /**
     * No-op configuration routine
     */
    public boolean configure(final Properties prop)
    {
        return true;
    }
    
    /**
     * Returns the name of this class
     */
    public String getName()
    {
        return NAME;
    }

} //-- end class X509FlatFileLoader
