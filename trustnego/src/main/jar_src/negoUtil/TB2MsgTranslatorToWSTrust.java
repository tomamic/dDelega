package negoUtil;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import javax.xml.namespace.QName;
import javax.xml.stream.FactoryConfigurationError;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMDataSource;
import org.apache.axiom.om.OMDocument;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.om.OMNode;
import org.apache.axiom.om.OMXMLBuilderFactory;
import org.apache.axiom.om.OMXMLParserWrapper;
import org.apache.axiom.om.ds.InputStreamDataSource;
import org.apache.axiom.om.ds.ParserInputStreamDataSource;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.om.impl.llom.OMSourcedElementImpl;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axiom.om.util.ElementHelper;
import org.apache.axiom.om.util.StAXUtils;
import org.apache.axis2.util.XMLUtils;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import edu.uiuc.cs.TrustBuilder2.messages.AbstractCredentialBrick;
import edu.uiuc.cs.TrustBuilder2.messages.AbstractPolicyBrick;
import edu.uiuc.cs.TrustBuilder2.messages.InitBrick;
import edu.uiuc.cs.TrustBuilder2.messages.StatusBrick;
import edu.uiuc.cs.TrustBuilder2.messages.TrustBrick;
import edu.uiuc.cs.TrustBuilder2.messages.TrustMessage;
import edu.uiuc.cs.TrustBuilder2.messages.X509CredentialBrick;
import edu.uiuc.cs.TrustBuilder2.state.Configuration;
import edu.uiuc.cs.TrustBuilder2.util.StaticFunctions;
import sun.misc.BASE64Encoder;






public class TB2MsgTranslatorToWSTrust {
	
	private TrustMessage inTB2Msg;

	private OMElement tnInitElement, tnExchElement, tnPolicyColl, tnTokenColl;
	
	private boolean testPolicy; 
	
	private List<Byte> remoteSignMaterial;
	
	//negoStatus viene messo a true quando la negoziazione termina con successo
	private boolean negoStatus;
	
	
	//campi di configurazione
	private String wspolicy_file;
	
	// Signature algorithms
    public static final String RSA_SIG_ALG = "SHA1WithRSAEncryption";
    public static final String DSA_SIG_ALG = "SHA1WithDSA";
    public static final String EC_SIG_ALG = "SHA1WithECDSA";
	
	private String x509uri = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
		
	//tiene traccia degli issuer delle credenziali, alle quali va aggiunto il tn:proofOfOwnership
	private ArrayList<String> requestedProofs;
	


	
	public TB2MsgTranslatorToWSTrust(String config_file) {
		
		
		Properties properties = new Properties();
		try {
		    properties.load(new FileInputStream(config_file));
		} catch (IOException e) {
			
			e.printStackTrace();
		}
		
		wspolicy_file = properties.getProperty("wspolicy_file");
		
	}

	// crea RSTResponse a partire da TB2 TrustMessage con InitBrick
	
	public OMElement createTNInitElement(TrustMessage msg, OMFactory factory) {
		
		inTB2Msg = msg;
		
		//creo elemento TNInit
		
		//OMFactory omFactory = OMAbstractFactory.getOMFactory();
		OMFactory omFactory = factory;
		OMNamespace xsiNamespace = omFactory.createOMNamespace("http://www.w3.org/2001/XMLSchema-instance","xsi"); 
        tnInitElement = omFactory.createOMElement(new QName ("http://localhost:8081/tn", "TNInit", "tn") );
        OMAttribute tnInitattribute = omFactory.createOMAttribute("schemaLocation",xsiNamespace,"http://localhost:8081/tn http://localhost:8081/tn/tn.xsd");
        tnInitElement.addAttribute(tnInitattribute);
        
        //tn:SignatureMaterial
        
        OMElement tnSignMaterialElem = omFactory.createOMElement(new QName ("http://localhost:8081/tn", "SignatureMaterial", "tn"));
        
        List<TrustBrick> initBrickList = inTB2Msg.getOtherBricks();
        Iterator<TrustBrick> initBrickIterator = initBrickList.iterator();
        List<Byte> signMaterial = null;
        InitBrick initBrick = null;
        while (initBrickIterator.hasNext())
		 {
        	initBrick = (InitBrick) initBrickIterator.next();
        	signMaterial = initBrick.getSenderSignatureMaterial();
		 }
        
        byte[] signMaterialArray = new byte [signMaterial.size()];
        signMaterialArray = StaticFunctions.byteListToArray(signMaterial);
        String tnSignMaterialBase64 = new sun.misc.BASE64Encoder().encode(signMaterialArray);
                
        tnSignMaterialElem.setText(tnSignMaterialBase64);
        tnInitElement.addChild(tnSignMaterialElem);
        
        //Ottengo la lista delle configurazioni
        
        ArrayList<Configuration> configurationsList = initBrick.getConfigurations();
        Iterator<Configuration> configListIterator = configurationsList.iterator();
        Configuration configuration = null;
        
        //tn:StrategyFamily: per ogni configurazione crea elemento tn:StrategyFamily
        String strategy;
        while ( configListIterator.hasNext() )
        {
        	configuration = configListIterator.next();
        	strategy = configuration.getStrategy();
        	String[] strategyString = strategy.split( "\\.");
        	strategy = strategyString[strategyString.length-1];
        	OMElement tnStrategyFamilyElem = omFactory.createOMElement(new QName ("http://localhost:8081/tn", "StrategyFamily", "tn"));
        	tnStrategyFamilyElem.setText(strategy);
        	tnInitElement.addChild(tnStrategyFamilyElem);
        	
        	
        }
        
        //tn:TokenFormat
        
        List<String> tokenFormatList = configuration.getCredentialTypes();
    	Iterator<String> tokenFormatListIterator = tokenFormatList.iterator();
    	String tokenFormat = null;
    	String[] tokenFormatString;
    	while ( tokenFormatListIterator.hasNext() )
    	{
    		tokenFormat = tokenFormatListIterator.next();
    		OMElement tnTokenFormatElement = omFactory.createOMElement(new QName ("http://localhost:8081/tn", "TokenFormat", "tn"));
    		tokenFormatString = tokenFormat.split("\\.");
    		tokenFormat = tokenFormatString[(tokenFormatString.length)-1];
    		if ( tokenFormat.equals("X509CredentialBrick") ) tokenFormat = x509uri;
    		tnTokenFormatElement.setText(tokenFormat);
    		tnInitElement.addChild(tnTokenFormatElement);
    		
    	}       
        
		
    	return tnInitElement;
	}
	

	
	public void createTnExchElement (TrustMessage msg, OMFactory factory) throws XMLStreamException, FactoryConfigurationError, Exception {
		
		inTB2Msg = msg;
		
		//controllo se è finita con successo la negoziazione
		StatusBrick status = inTB2Msg.getStatus();
		if ( status != null && status.getTrustEstablished() ) 
		{	
			negoStatus = true;
			return;
		}
		//creo elemento TNExchange
		
		OMFactory omFactory = factory;//OMAbstractFactory.getOMFactory();
		OMNamespace xsiNamespace = omFactory.createOMNamespace("http://www.w3.org/2001/XMLSchema-instance","xsi"); 
		tnExchElement = omFactory.createOMElement(new QName ("http://localhost:8081/tn", "TNExchange", "tn") );
		OMAttribute tnInitattribute = omFactory.createOMAttribute("schemaLocation",xsiNamespace,"http://localhost:8081/tn http://localhost:8081/tn/tn.xsd");
		tnExchElement.addAttribute(tnInitattribute);
		
		//***Policy***
		
		//ottengo la lista delle Policy
		List<AbstractPolicyBrick> policyList = inTB2Msg.getPolicyBricks();
		
		//policyList = null;
		if ( policyList != null )
		{
			Iterator<AbstractPolicyBrick> policyListIter = policyList.iterator();
			tnPolicyColl = omFactory.createOMElement(new QName ("http://localhost:8081/tn", "PolicyCollection", "tn"));
			tnExchElement.addChild(tnPolicyColl);
			AbstractPolicyBrick policy;
			
			while (policyListIter.hasNext())
			{
				policy = policyListIter.next();
				
				//ultima prova mattina
				if ( testPolicy ) { policy.toString();}
				
				//rid relativo alla policy da inviare (contenuto nel file ldr, di TB2, delle policy)
				String rid = policy.getIdentifier();
				
				String policy_file = null;
				policy_file = wspolicy_file + rid + ".xml";

				
				FileInputStream policyStream = null;
				try {
					policyStream = new FileInputStream (policy_file);
				} catch (FileNotFoundException e) {
					e.printStackTrace();
				}
				StAXOMBuilder stAXOMBuilder = new StAXOMBuilder(policyStream);
				OMElement documentElement = stAXOMBuilder.getDocumentElement();
				documentElement.build();
				OMElement prova = OMAbstractFactory.getOMFactory().createOMElement("prova", null);
				prova.build();
				OMElement imported = ElementHelper.importOMElement(documentElement, omFactory.getClass().newInstance());
				tnPolicyColl.addChild(imported);
				
			}
		}
		
		//***Credenziali***
		
		List<AbstractCredentialBrick> credentialList = inTB2Msg.getCredentialBricks();
		
		if ( credentialList != null )
		{
			tnTokenColl = omFactory.createOMElement(new QName ("http://localhost:8081/tn", "TokenCollection", "tn"));
			tnExchElement.addChild(tnTokenColl);
			Iterator<AbstractCredentialBrick>credentialIter = credentialList.iterator();
			AbstractCredentialBrick credential;
			OMElement token, tokenType, requestedToken, ownProof;
			while ( credentialIter.hasNext() )
			{
				credential = credentialIter.next();
				token = omFactory.createOMElement(new QName ("http://localhost:8081/tn", "Token", "tn"));
				tokenType = TrustUtil.createTokenTypeElement(RahasConstants.VERSION_05_02, token);
				requestedToken = TrustUtil.createRequestedSecurityTokenElement(RahasConstants.VERSION_05_02, token);
				
				if ( credential instanceof X509CredentialBrick )
				{
					System.out.println("\nCredential di tipo x509!!");
					tokenType.setText(x509uri);
					X509Certificate cert = ((X509CredentialBrick)credential).getCertificate();
					requestedToken.setText(new BASE64Encoder().encodeBuffer(cert.getEncoded()));
					token.addChild(tokenType);
					token.addChild(requestedToken);
					
					//elemento tn:OwnershipProof -> controllare se la credential ha un proofofownership per metterlo nel msg soap
					
					byte[] proofOwner;
					proofOwner = createProofOfOwnership((X509CredentialBrick)credential);//((X509CredentialBrick)credential).getProofOfOwnership();
					if ( proofOwner != null )
					{
						String issuer = ((X509CredentialBrick)credential).getIssuer();
						String proofsListElem;
						Iterator<String> proofsIdIter = requestedProofs.iterator();
						System.out.println("requesteProofs: " + requestedProofs.toString());
						while ( proofsIdIter.hasNext() )
						{
							proofsListElem = proofsIdIter.next();
							proofsListElem = proofsListElem.trim();
							
							System.out.println("issuer: " + issuer);
							System.out.println("requestedProofsElem: " + proofsListElem);
							
							if ( issuer.equals(proofsListElem) )
							{
								ownProof = omFactory.createOMElement(new QName ("http://localhost:8081/tn", "OwnershipProof", "tn"));
						        ownProof.setText(new BASE64Encoder().encode(proofOwner));
						        token.addChild(ownProof);
							}
						}
					}
					
					
				}				
			
				tnTokenColl.addChild(token);
			}			
			
		}

		
	
	}
	
	 private byte[] createProofOfOwnership(X509CredentialBrick credential)
	    {
	        
		 PrivateKey privateKey = credential.getPrivateKey();
		 byte[] proofOfOwnership;
		 inTB2Msg.getSession();
		 
		 
		 if(privateKey == null){
	            return null;
	        }
	        
	        try{
	            Signature sig = null;
	            
	            // If this cert holds an RSA key pair...
	            if(privateKey instanceof RSAPrivateKey){
	                sig = Signature.getInstance(RSA_SIG_ALG);
	                
	            }
	            
	            // If it's a DSA key pair...
	            if(privateKey instanceof DSAPrivateKey){
	                sig = Signature.getInstance(DSA_SIG_ALG);
	            }
	            
	            // If it's an elliptic curve key pair
	            if(privateKey instanceof ECPrivateKey){
	                sig = Signature.getInstance(EC_SIG_ALG);
	            }
	            
	            
	            // Actually compute the signature
	            sig.initSign(privateKey);
	            sig.update(StaticFunctions.byteListToArray(remoteSignMaterial));
	            proofOfOwnership = sig.sign();
	            return proofOfOwnership;
	        }
	        catch(Exception e){
	            e.printStackTrace();
	            return null;
	        }
	        
	    }
	
	private OMElement createWspPolicyElem (AbstractPolicyBrick policy, OMFactory factory) throws Exception, XMLStreamException, FactoryConfigurationError
	{
		//viene processato il policyBrick: conversione in WSPolicy e altre operazioni necessarie per creare 
		//elemento <WSPolicy>
		
		OMFactory omFactory = factory;
		
		//ultima prova mattina
		
		
		if ( testPolicy ) { policy.toString();}
		
		//rid relativo alla policy da inviare (contenuto nel file ldr, di TB2, delle policy)
		String rid = policy.getIdentifier();
		
		String policy_file = null;
		policy_file = wspolicy_file + rid + ".xml";
		//OMElement wspolicyElem = getPolicy(policy_file, omFactory);
		
		//ultima prova mattina
		FileReader soapFileReader = new FileReader(policy_file);
		XMLStreamReader parser =  XMLInputFactory.newInstance().createXMLStreamReader(soapFileReader); 
		StAXOMBuilder stAXOMBuilder =  new StAXOMBuilder(factory, parser);
		OMElement documentElement = stAXOMBuilder.getDocumentElement();
		////ultima prova mattina-fine
		
		//return getPolicy(policy_file, omFactory) ;
		return omFactory.createOMElement("prova", null);
		//return documentElement;
	}
	
	private OMElement getPolicy (String policy_file, OMFactory factory) throws XMLStreamException, FactoryConfigurationError, FileNotFoundException
	{
		FileInputStream policy = null;
		OMFactory omFactory = factory;
		/*try {
			policy = new FileInputStream (policy_file);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} */
        
		FileReader soapFileReader = new FileReader(policy_file);
		XMLStreamReader parser =  XMLInputFactory.newInstance().createXMLStreamReader(soapFileReader); 
		StAXOMBuilder stAXOMBuilder =  new StAXOMBuilder(factory, parser);
        /*try {
			stAXOMBuilder = new StAXOMBuilder(policy);
		} catch (XMLStreamException e) {
			
			e.printStackTrace();
		} */
        
        OMElement documentElement = stAXOMBuilder.getDocumentElement();
        System.out.println("policy from file:" + documentElement.toString());
        String xmlFragment = documentElement.toString();
        documentElement.build();
        //OMElement wspolicy = AXIOMUtil.stringToOM(omFactory, xmlFragment);
        //OMElement wspolicy = omFactory.createOMElement("prova", null);
        
        //XMLStreamReader reader = documentElement.getXMLStreamReader();
      
        //create the builder
        /*OMXMLParserWrapper builder = OMXMLBuilderFactory.createOMBuilder(policy);

        //get the root element
        OMElement documentElement = builder.getDocumentElement(); */
        
        //OMDataSource yourOMDataSourceObject = documentElement.getXMLStreamReader();
		//OMElement myDataElement = new OMSourcedElementImpl(qNameOfYourElement, properOMFactory, yourOMDataSourceObject );
        
        //return documentElement;
        return omFactory.createOMElement("prova", null);
	}
	
	/*public OMElement getTNInitElement() {
		
		
		return tnInitElement;
	} */
	
	public OMElement getTNExchElement()
	{
		return tnExchElement;
	}
	
	public boolean getNegoStatus()
	{
		return negoStatus;
	}
	
	public void setRemoteSignMaterial ( List<Byte> signMaterial )
	{
		remoteSignMaterial = signMaterial;
	}
	
	public void setRequestedProofs ( ArrayList<String> list  )
	{
		
		requestedProofs = list;
		
		
	}
	
	public  ArrayList<String> getRequestedProofs ()
	{
		return requestedProofs;
	}
	

	

}




