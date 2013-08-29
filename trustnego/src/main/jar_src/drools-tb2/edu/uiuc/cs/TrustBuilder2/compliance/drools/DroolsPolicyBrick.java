package edu.uiuc.cs.TrustBuilder2.compliance.drools;

import java.io.File;

import edu.uiuc.cs.TrustBuilder2.messages.AbstractPolicyBrick;
import edu.uiuc.cs.TrustBuilder2.util.StaticFunctions;


public class DroolsPolicyBrick extends AbstractPolicyBrick {
	
	/** For serialization purposes */
    private static final long serialVersionUID = -3122756619748702397L;
    
    /** The actual rules defining the policy will be stored here */
    private String thePolicy;
    
    public DroolsPolicyBrick(String policy, String rid) throws IllegalArgumentException
    {
        this(policy,rid, null);
    }
    
    public DroolsPolicyBrick(String policy, String rid, String pid) throws IllegalArgumentException
    {
        super(rid, pid);
        thePolicy = policy;
    }
    
    public DroolsPolicyBrick(File policy, String rid) throws IllegalArgumentException
    {
        this(policy, rid, null);
    }
    
    public DroolsPolicyBrick(File policy, String rid, String pid) throws IllegalArgumentException
    {
        // Call PolicyBrick constructor
        super(rid, pid);
        
        // Get contents of policy file as string
        try{
            thePolicy = StaticFunctions.readAsciiFile(policy);
        }
        catch(Exception e){
            throw new IllegalArgumentException("Error reading supplied policy file");
        }
    }
    
 // see description in PolicyBrick
    public String getAsciiPolicy()
    {
        return thePolicy;
    }
    
 // See description in Object
    public String toString()
    {
        return "(DroolsPolicyBrick [id: " + this.getIdentifier() + "]: " + thePolicy + ")";
    }

}
