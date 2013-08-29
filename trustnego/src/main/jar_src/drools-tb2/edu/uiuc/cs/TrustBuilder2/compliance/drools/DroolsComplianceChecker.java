package edu.uiuc.cs.TrustBuilder2.compliance.drools;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;


import org.drools.KnowledgeBase;
import org.drools.builder.KnowledgeBuilder;
import org.drools.builder.KnowledgeBuilderFactory;
import org.drools.builder.ResourceType;
import org.drools.io.ResourceFactory;
import org.drools.runtime.StatefulKnowledgeSession;

import edu.uiuc.cs.TrustBuilder2.compliance.ComplianceCheckerException;
import edu.uiuc.cs.TrustBuilder2.compliance.ComplianceCheckerInterface;
import edu.uiuc.cs.TrustBuilder2.compliance.Decision;
import edu.uiuc.cs.TrustBuilder2.compliance.SatisfyingSet;
import edu.uiuc.cs.TrustBuilder2.messages.AbstractCredentialBrick;
import edu.uiuc.cs.TrustBuilder2.messages.AbstractPolicyBrick;
import edu.uiuc.cs.TrustBuilder2.messages.ClaimBrick;
import edu.uiuc.cs.TrustBuilder2.messages.X509CredentialBrick;
import edu.uiuc.cs.TrustBuilder2.state.Session;
import edu.uiuc.cs.TrustBuilder2.util.CertificateUtils;
import edu.uiuc.cs.TrustBuilder2.verification.CredentialChain;
import edu.uiuc.cs.TrustBuilder2.verification.SimpleChainBuilder;

public class DroolsComplianceChecker implements ComplianceCheckerInterface {
	
	/** The name of this compliance checker */
    public static final String NAME = "Drools compliance checker";
    
    /** Key that loads base definitions file */
    public static final String KEY_DEFNS = DroolsComplianceChecker.class.getName() + ".baseDefinitions";
    
    /** The logger for this class */
    public static final Logger logger = Logger.getLogger(DroolsComplianceChecker.class.getName());
    
    /** The Jess base file to use */
    //private String jessDefinitions;
    
    /** The types of policies supported by this CC */
    private final List<String> supportedPolicyClasses;
    
    private StatefulKnowledgeSession ksession;
    
    private final String ROOT_CERT_FILE = "edu.uiuc.cs.TrustBuilder2.compliance.drools.DroolsComplianceCkecker.rootCerfile";
    
    /**
     * Default constructor.
     *
     */
    public DroolsComplianceChecker()
    {
        super();
        
        // set up the "list" of supported policy types
        supportedPolicyClasses = new ArrayList<String>();
        supportedPolicyClasses.add(DroolsPolicyBrick.class.getName());
    }
    
 // see comments in interface
    public String getName()
    {
        return NAME;
    }

    @Override
    public boolean configure(Properties prop) {
    	// TODO Auto-generated method stub
    	return false;
    }

    @Override
    public int getComplianceCheckerType() {

    	return ComplianceCheckerInterface.TYPE_3;
    }
    
    public List<String> getSupportedPolicyClasses()
    {
        return new ArrayList<String>(supportedPolicyClasses);
    }

    @Override
    public Decision makeDecision(Session sess, AbstractPolicyBrick policy, Collection<CredentialChain> chains, Collection<ClaimBrick> claims) throws ComplianceCheckerException

    {
    	logger.info("chains:" + chains.toString());
    	logger.info("policy:" + policy.toString());
    	
    	final List<SatisfyingSet> sets = new ArrayList<SatisfyingSet>();
    	// Check that the policy is of the correct type
        DroolsPolicyBrick jpb;
        try{
            jpb = (DroolsPolicyBrick)policy;
        }
        catch(Exception e){
            throw new IllegalArgumentException("Policy was not a DroolsPolicyBrick");
        }
        

			try {
				ksession = readKnowledgeBase(jpb, chains, claims);
				
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			//
			ArrayList<AbstractCredentialBrick> creds = new ArrayList<AbstractCredentialBrick>();
			ArrayList<ClaimBrick> claimsList = new ArrayList<ClaimBrick>();
			//boolean policy_satisfied = false;
			ksession.insert(creds);
			//ksession.insert(policy_satisfied);
			ksession.fireAllRules();
			
			//***debug
			logger.info("Creds dopo regole: " + creds.size());
			//
			
			//verify chain root certificate authenticity
			
			SimpleChainBuilder chainBuilder = new SimpleChainBuilder();
			
			Collection<CredentialChain> credentialChainColl = chainBuilder.createChains(sess, null, creds);
			
			Iterator<CredentialChain> iterator = credentialChainColl.iterator();
			CredentialChain chain = new CredentialChain();
			while ( iterator.hasNext() )
			{
				chain = iterator.next();
			}
			
			X509CredentialBrick rootCert = (X509CredentialBrick) chain.getRoot();
			
			logger.info("rootCert fingerprint" + rootCert.getFingerprint());
			
			final String rootCertFile = System.getProperty(ROOT_CERT_FILE);
			Certificate rootCertLocal = CertificateUtils.importCertificate(new File(rootCertFile));
			X509CredentialBrick rootCertCredential = new X509CredentialBrick((X509Certificate)rootCertLocal, null, "root", "root");
			logger.info("rootCertLocal fingerprint" + rootCertCredential.getFingerprint());
			
			if ( !rootCert.getFingerprint().equals(rootCertCredential.getFingerprint()) )
			{
				logger.info("Root certificate is not valid!");
				for ( int i = 0; i < creds.size(); i++ )
				{
					creds.remove(i);
				}
			}
			
			if ( creds.size() > 0 ) sets.add(new SatisfyingSet(creds, claimsList));
			
			try {
				
			
			
			if(sets.size() > 0){
            	//***debug 
            	logger.info("Sets è ok");
            	//
                return new Decision(sets, ComplianceCheckerInterface.TYPE_3);
            }
            //***debug
            else logger.info("Sets non è ok");
            //
            	// error case
            	return new Decision((AbstractPolicyBrick)null, ComplianceCheckerInterface.TYPE_3);
            	
			}
			
			catch(Exception e){
	            logger.severe("makeDecision: " + e.getMessage());
	            throw new ComplianceCheckerException(e.getMessage());
	        }
			
    }
    
    private StatefulKnowledgeSession readKnowledgeBase(final DroolsPolicyBrick policy, final Collection<CredentialChain> chains, final Collection<ClaimBrick> claims) throws Exception {
    	
    	KnowledgeBuilder kbuilder = KnowledgeBuilderFactory.newKnowledgeBuilder();
    	
    	// insert the policy
    	kbuilder.add(ResourceFactory.newInputStreamResource(new ByteArrayInputStream((policy.getAsciiPolicy()).getBytes())), ResourceType.DRL);
    	KnowledgeBase kbase = kbuilder.newKnowledgeBase();
        kbase.addKnowledgePackages(kbuilder.getKnowledgePackages());
        
        //insert credential
        //insert the credential chains
        //StringBuffer chainBuff;
        final HashSet<AbstractCredentialBrick> credsToInsert = new HashSet<AbstractCredentialBrick>();
        for(CredentialChain chain : chains){
            if(chain.getCredentials().size() > 0){
                // @PMD:REVIEWED:AvoidInstantiatingObjectsInLoops: by adamlee on 8/1/06 9:21 AM
                //chainBuff = new StringBuffer("(assert (credential-chain (credentials");
                for(AbstractCredentialBrick cred : chain.getCredentials()){
                    //chainBuff.append(" \"" + cred.getIdentifier() + "\"");
                    credsToInsert.add(cred);
                }
                //chainBuff.append(")))");
                
            }
        }
        
        StatefulKnowledgeSession ksession = kbase.newStatefulKnowledgeSession();
        
        for(AbstractCredentialBrick cred : credsToInsert){
        	
        	logger.info("Credenziale inserita:" + cred.toString());
        	ksession.insert(cred);
        }
        
        
        
           	
    	
    	
    	return ksession;
    	
    }



}
