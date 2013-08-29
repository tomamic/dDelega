package edu.uiuc.cs.TrustBuilder2.query.policy;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Properties;
import java.util.logging.Logger;

import edu.uiuc.cs.TrustBuilder2.TrustBuilder2;
import edu.uiuc.cs.TrustBuilder2.compliance.drools.DroolsPolicyBrick;
//import edu.uiuc.cs.TrustBuilder2.compliance.jess.JessPolicyBrick;
import edu.uiuc.cs.TrustBuilder2.messages.AbstractPolicyBrick;
import edu.uiuc.cs.TrustBuilder2.plugins.PolicyLoader;
import edu.uiuc.cs.TrustBuilder2.query.InvalidLoaderFileException;
import edu.uiuc.cs.TrustBuilder2.query.policy.PolicyManager;
import edu.uiuc.cs.TrustBuilder2.util.StaticFunctions;


public class DroolsPolicyFlatFileLoader implements PolicyLoader {
	
	/** Name of this loader */
    public static final String NAME = "Drools Policy Flat File Loader";
    
    /** Key for file paths */
    private static final String KEY_POLICY = "policy_";
    
    /** Key for resource IDs */
    private static final String KEY_RID = "rid_";
    
    /** Key for policy IDs */
    private static final String KEY_PID = "pid_";
    
    /** Key for preambles */
    private static final String KEY_PREAMBLE = "preamble_";
    
    /** Logger */
    private static final Logger logger = Logger.getLogger(DroolsPolicyFlatFileLoader.class.getName());
    
    /** Path to which policies are relative */
    private String rootPath;
    
    
    /**
     * Default constructor.
     *
     */
    public DroolsPolicyFlatFileLoader()
    {
    	
    }
    
    
    // see description in PolicyLoader
    public Collection<? extends AbstractPolicyBrick> loadPolicies(final Properties loaderFile) throws InvalidLoaderFileException // NOPMD by adamlee on 2/1/07 1:32 PM
    {
        // throw an exception if this is the wrong loader
        if(loaderFile == null){
            logger.severe("Null loader file supplied");
            throw new InvalidLoaderFileException("Null loader file.");
        }
        if(!loaderFile.getProperty(PolicyManager.KEY_LOADER_CLASS, "").equals(DroolsPolicyFlatFileLoader.class.getName())){
            logger.severe("Wrong loader class (" + loaderFile.getProperty(PolicyManager.KEY_LOADER_CLASS) + ")");
            throw new InvalidLoaderFileException("Wrong loader class.");
        }
        
        // The list of policies that we'll return
        final ArrayList<DroolsPolicyBrick> policies = new ArrayList<DroolsPolicyBrick>();
        DroolsPolicyBrick dpb;
        String policy=null, rid=null, pid=null, preamble=null;
        int counter=1;
        
        // iterate over the properties file and build policies
        //preamble = loaderFile.getProperty(KEY_PREAMBLE + counter);
        policy = loaderFile.getProperty(KEY_POLICY + counter);
        rid = loaderFile.getProperty(KEY_RID + counter);
        pid = loaderFile.getProperty(KEY_PID + counter);
        StringBuffer policyText;
        String[] preambles;
        while( (policy != null) && (rid != null) )
        {
            // reset the buffer we're holding the policy in
            policyText = new StringBuffer(100); // NOPMD by adamlee on 1/29/07 10:18 AM
            
            // Trim leading and trailing whitespace from identifiers
            rid = rid.trim();
            if(pid != null){
                pid = pid.trim();
            }
            
            // Build the policy bricks
            try{
                // Load all of the preambles (if there are any).  Fail if any
                // preamble doesn't exist
                if(preamble != null){
                    preambles = preamble.split(",");
                    for(String file : preambles){
                        file = file.trim();
                        if(!"".equals(file)){
                            policyText.append("\n;---------- Begin preamble " + file + "----------\n");
                            policyText.append(StaticFunctions.readAsciiFile(new File(rootPath + file))); // NOPMD by adamlee on 1/29/07 10:13 AM
                            policyText.append("\n;---------- End preamble " + file + "----------\n\n");
                        }
                    }
                }
                
                // Load the actual policy (fail if it doesn't exist)
                policyText.append(StaticFunctions.readAsciiFile(new File(rootPath + policy))); // NOPMD by adamlee on 1/29/07 10:13 AM
                
                // @PMD:REVIEWED:AvoidInstantiatingObjectsInLoops: by adamlee on 8/1/06 9:27 AM
                dpb = new DroolsPolicyBrick(policyText.toString(), rid, pid);
                policies.add(dpb);
            }
            catch(Exception e){
                logger.warning("Error loading policy specified by file " + rootPath + policy);
            }
            
            // get ready for next iteration
            counter++;
            preamble = loaderFile.getProperty(KEY_PREAMBLE + counter);
            policy = loaderFile.getProperty(KEY_POLICY + counter);
            rid = loaderFile.getProperty(KEY_RID + counter);
            pid = loaderFile.getProperty(KEY_PID + counter);
        }
        
        // if we make it here, return
        return policies;
        
    }  //-- end loadPolicies(Properties)
    
    // configure method
    public boolean configure(final Properties prop)
    {
        // set up relative path for policy files
        final String sep = System.getProperty("file.separator");
        final String tb2Root = prop.getProperty(TrustBuilder2.KEY_TB2_ROOT);
        
        // Add the TrustBuilder2 root if needed
        rootPath = "";
        if(tb2Root == null){
            rootPath = System.getProperty("user.dir");
        }
        else{
            rootPath = tb2Root;
        }
        if(!rootPath.endsWith(sep)){
            rootPath += sep;
        }
        
        // Add the policy loader root
        rootPath += prop.getProperty(PolicyManager.KEY_LOADER_FILE_DIR,"");
        if(!rootPath.endsWith(sep)){
            rootPath += sep;
        }
        
        return true;
    }
    
    // see description in ConfigurablePlugin
    public String getName()
    {
        return NAME;
    }
	

}
