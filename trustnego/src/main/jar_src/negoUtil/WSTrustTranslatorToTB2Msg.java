package negoUtil;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.Reader;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;
import java.util.Properties;


import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.apache.axiom.om.OMElement;
import org.drools.compiler.PackageBuilderConfiguration;
import org.drools.compiler.xml.XmlPackageReader;
import org.drools.lang.DrlDumper;
import org.drools.lang.descr.PackageDescr;

import edu.uiuc.cs.TrustBuilder2.Constants;
import edu.uiuc.cs.TrustBuilder2.compliance.drools.DroolsPolicyBrick;
import edu.uiuc.cs.TrustBuilder2.messages.AbstractPolicyBrick;
import edu.uiuc.cs.TrustBuilder2.messages.InitBrick;
import edu.uiuc.cs.TrustBuilder2.messages.NegotiationTarget;
import edu.uiuc.cs.TrustBuilder2.messages.TrustMessage;
import edu.uiuc.cs.TrustBuilder2.messages.X509CredentialBrick;
import edu.uiuc.cs.TrustBuilder2.util.StaticFunctions;
import edu.uiuc.cs.TrustBuilder2.state.Configuration;
import sun.misc.BASE64Decoder;

public class WSTrustTranslatorToTB2Msg {


	private OMElement tnInitElem, tnExchElem;
	private TrustMessage initTB2Msg, tb2Msg ;
	
	List<Byte> signMaterial;
	
	//campi di configurazione
	
	private String policyClass;// = "edu.uiuc.cs.TrustBuilder2.compliance.drools.DroolsPolicyBrick";
	private String wspolicy_rec_filepath; // = "src/pkg/wspolicy_rec.xml";
	//private String wspolicy_rec_filepath_server; // = "C:\\Users\\filo\\eclipse_workspace\\STSNegotiation\\src\\pkg\\wspolicy_rec.xml";
	private String xsl_filepath; // = "src/pkg/transform.xsl";
	//private String xsl_filepath_server = "C:\\Users\\filo\\eclipse_workspace\\STSNegotiation\\src\\pkg\\transform.xsl" ;
	private String droolsXmlpolicy_filepath; // = "src/pkg/wspolicy_rec_xmldrools.xml";
	private String tb2strategy_pack;
	private String credential_pack;
	//private String droolsXmlpolicy_filepath_server = "C:\\Users\\filo\\eclipse_workspace\\STSNegotiation\\src\\pkg\\wspolicy_rec_xmldrools.xml" ;
	//private String droolsDrlpolicy_filepath_client = "src/pkg/drlpolicy_rec.drl";
	//private String droolsDrlpolicy_filepath_server = "C:\\Users\\filo\\eclipse_workspace\\STSNegotiation\\src\\pkg\\drlpolicy_rec.drl";
	
	
	private boolean output_control = false;
	
	//flag da settare a true se è richiesta la proofOfOwnership nella policy ricevuta
	//private boolean requestedProof;
	
	//tiene traccia degli issuer delle credenziali, alle quali va aggiunto il tn:proofOfOwnership
	private ArrayList<String> requestedProofs;
	
	// valori: serverInit, clientInit
	private String trustMsgType;  
	
	private String x509uri = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
	
	public WSTrustTranslatorToTB2Msg (String config_file) {
		
		
		initTB2Msg = new TrustMessage();
		tb2Msg = new TrustMessage();
		requestedProofs = new ArrayList<String>();
		
		Properties properties = new Properties();
		try {
		    properties.load(new FileInputStream(config_file));
		} catch (IOException e) {
			
			e.printStackTrace();
		}
		
		policyClass = properties.getProperty("policyClass");
		tb2strategy_pack = properties.getProperty("stategy_pack");
		credential_pack = properties.getProperty("credential_pack");
		wspolicy_rec_filepath = properties.getProperty("wspolicy_rec_filepath");
		xsl_filepath = properties.getProperty("xsl_filepath");
		droolsXmlpolicy_filepath = properties.getProperty("droolsXmlpolicy_filepath");
		
	}
	
	
	/** Creo il messaggio iniziale di TB2, dal messaggio WSTrust (RSTR) contenente TNInit */
	
	public TrustMessage createInitTB2Msg ( OMElement tnInit, String msgType ) throws IOException {
		
		tnInitElem = tnInit;
		trustMsgType = msgType;
		
		// *** ESTRAGGO LA CONFIGURAZIONE ***
		
		String configuration;
		String strategy = null; 
		ArrayList<String> credentialType = new ArrayList<String> ();
        String tnSignMaterialBase64 = null;
        byte[] sigMaterial = new byte[Constants.SIG_MATERIAL_LENGTH];
        
		//setto la TB2 policy class, che non è trasportata nel messaggio WSTrust
		String policyclass = policyClass;
		
		//estraggo la strategy, il tipo di credenziali e il signature material
		
		Iterator<OMElement> tnInitIter = tnInitElem.getChildElements();
		String credential_type = null;
		while ( tnInitIter.hasNext() )
		{
			OMElement elem = tnInitIter.next();
			if (output_control)
				if ( elem != null ) System.out.println("\n child: " + elem.toString() + elem.getText() + elem.getLocalName() );
			if ( elem.getLocalName() == "StrategyFamily" )  strategy = elem.getText();
			if ( elem.getLocalName() == "TokenFormat" )  
			{
				//System.out.println("\nIndice dell'array delle credenziali: " + i);
				if ( elem.getText().equals(x509uri) ) credential_type = credential_pack + ".X509CredentialBrick";
				//questo per TB2-Uncertified Credential
				else credential_type = credential_pack + "." + elem.getText();
				credentialType.add(credential_type);
			}
			if ( elem.getLocalName() == "SignatureMaterial" )  tnSignMaterialBase64 = elem.getText();
		}
		
		strategy = tb2strategy_pack + "." + strategy;
		
		if ( output_control )
			System.out.println ("\n strategy: " + strategy + "\n credentialType: " + credentialType + "\n signmaterial: " + tnSignMaterialBase64);
		

		
		//creo la stringa di configurazione
		
		StringBuffer configBuffer = new StringBuffer();
		configBuffer.append(strategy);
		configBuffer.append(";");
		for (int n = 0; n < credentialType.size(); n++)
		{
			configBuffer.append(credentialType.get(n));
			if ( (n+1) < credentialType.size() ) configBuffer.append(",");
		}
		configBuffer.append(";");
		configBuffer.append(policyclass);
		configuration = configBuffer.toString();
		
		Configuration configurationObj = Configuration.fromString(configuration);
		List<Configuration> configList = new ArrayList<Configuration>();

		configList.add(configurationObj);
		if ( output_control )
			System.out.println ("\nLista: " + configList.toString());
		

		// *** Creo messaggio iniziale
		
		
        final InitBrick init = new InitBrick(configList);
        init.setVersion(Constants.TB2_VERSION);
        init.setSessionId(0);

        // decodifico signature material
        
        sigMaterial = new sun.misc.BASE64Decoder().decodeBuffer(tnSignMaterialBase64);
        signMaterial = StaticFunctions.byteArrayToList(sigMaterial);
        
        
        init.setSenderSignatureMaterial(signMaterial);
        

        // Fine configurazione del messaggio
        if ( trustMsgType == "serverInit" )
        	initTB2Msg.setSessionId(0);
        if ( trustMsgType == "clientInit" )
        	initTB2Msg.setSessionId(-2);
        
        initTB2Msg.getOtherBricks().add(init);
        initTB2Msg.setContinue(true);

        return initTB2Msg;
        
    }
	
	public TrustMessage createResourceRequestTB2Msg ( String resource )
	{
        tb2Msg.setContinue(true);
        tb2Msg.setSessionId(0);
        tb2Msg.getOtherBricks().add(new NegotiationTarget(resource));
        return tb2Msg;
		
	}
	
	public TrustMessage createTB2Msg (OMElement tnExch) throws Exception
	{
		tnExchElem = tnExch;
		Iterator<OMElement> tnExchIter = tnExchElem.getChildElements();
		OMElement elem, policyColl = null, tokenColl = null;
		while ( tnExchIter.hasNext() )
		{
			elem = tnExchIter.next();
			if ( elem.getLocalName() == "PolicyCollection" ) policyColl = elem;
			if ( elem.getLocalName() == "TokenCollection" ) tokenColl = elem;
		}
		
		//***Policy
		
		if ( policyColl != null )
		{
			Iterator<OMElement> policyCollIter = policyColl.getChildElements();
			
			//estrarre elementi wsPolicy
			OMElement policy;
			int idNum = 0;
			while ( policyCollIter.hasNext() )
			{
				elem = policyCollIter.next();
				if ( elem.getLocalName() == "Policy" )
				{
					policy = elem;
					processPolicy(policy, idNum);
					idNum++;
					
					//***Verifico se è richiesto proofOfOwnership
					
					//estraggo elemento padre di X509Token
					while ( !(elem.getFirstElement().getLocalName() == "X509Token") )
					{
						elem = elem.getFirstElement();
					}
					//elem = elem.getFirstElement();
					System.out.println("elem:"+elem.toString());

					Iterator<OMElement> x509Iter = elem.getChildElements();
					String issuer = null;
					//svuoto la lista dei proofsId
					if ( !requestedProofs.isEmpty() )
					{
						for ( int i=0; i<requestedProofs.size(); i++ )
						{
							requestedProofs.remove(i);
						}
					}
					
					//itero sugli elementi sp:X509Token e riempio la lista dei proofsId
					while ( x509Iter.hasNext() )
					{
						elem = x509Iter.next();
						if ( elem.getLocalName() == "X509Token" )
						{
							Iterator<OMElement> x509tokenIter = elem.getChildElements();
							OMElement elem1;
							while ( x509tokenIter.hasNext() )
							{
								elem1 = x509tokenIter.next();
								if ( elem1.getLocalName() == "IssuerName" ) issuer = elem1.getText();
								if ( elem1.getLocalName() == "Claims" )
								{
									Iterator<OMElement> claimIter = elem1.getChildElements();
									OMElement elem2;
									while ( claimIter.hasNext() )
									{
										elem2 = claimIter.next();
										
										if ( elem2.getLocalName() == "Ownership" ) 
										{
											addRequestedProofsId(issuer);											
										}
									}
								}
							}
						}

					}
					
				}
				
			}

		}
		
		//***Credenziali
		
		//AbstractCredentialBrick credential = null;
		
		if ( tokenColl != null )
		{
			Iterator<OMElement> tokenCollIter = tokenColl.getChildElements();
			OMElement token;
			int idNum = 0;
			while ( tokenCollIter.hasNext() )
			{
				elem = tokenCollIter.next();
				if ( elem.getLocalName() == "Token" ) 
				{
					token = elem;
					processToken(token, idNum);
					idNum++;
				}
			}
		}
		
		tb2Msg.setContinue(true);
		tb2Msg.setSessionId(0);
		
		return tb2Msg;
	}
	
	private void processToken(OMElement token, int idNum) throws CertificateException, IOException {
		
		System.out.println("\nFunzione processToken\n");
		Iterator<OMElement> tokenIter = token.getChildElements();
		OMElement elem, tokenType = null, requestedToken = null, ownProof = null;
		
		String id = "res_";
		//AbstractCredentialBrick credential;
		while ( tokenIter.hasNext() )
		{
			elem = tokenIter.next();
			if ( elem.getLocalName() == "TokenType" ) tokenType = elem;
			if ( elem.getLocalName() == "RequestedSecurityToken" ) requestedToken = elem;
			if ( elem.getLocalName() == "OwnershipProof" ) ownProof = elem;
		}
		
		//output control
		if ( output_control ) System.out.println("\nTokenType text:" + tokenType.getText());
		if ( output_control ) System.out.println("\nx509uri: " + x509uri);
		
		tokenType.getText();
		
		if ( (tokenType.getText()).equals(x509uri) )
		{
			System.out.println("Fase di processazione del certificato");
			byte[] byteCertificate = new BASE64Decoder().decodeBuffer(requestedToken.getText());
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			InputStream x509InputStram = new ByteArrayInputStream(byteCertificate);
			X509Certificate certificate = (X509Certificate) cf.generateCertificate(x509InputStram);
			id = id.concat(""+ idNum);
			X509CredentialBrick credential = new X509CredentialBrick(certificate, id);
			if ( ownProof != null ) 
				credential.setProofOfOwnership(new BASE64Decoder().decodeBuffer(ownProof.getText()));
				
			tb2Msg.getCredentialBricks().add(credential);
			
		}
		else System.out.println("\nStringhe non uguali");
		
	}
	
	private void processPolicy ( OMElement policy, int idNum ) throws Exception

	{
		AbstractPolicyBrick policyBrick;
		String id = "policy_";
		
		//salvo su file ws-policy ricevuta
		File wspolicy_rec = null;
		wspolicy_rec = new File (wspolicy_rec_filepath);

        FileOutputStream wspolicyFileRec = new FileOutputStream(wspolicy_rec);
        PrintStream OutputWs = new PrintStream(wspolicyFileRec);
        OutputWs.println(policy.toString());
		
		//conversione di ws-Policy in Drools-XML (tramite XSL)
        TransformerFactory factory = TransformerFactory.newInstance();
        File xsl = null;
        xsl = new File(xsl_filepath);

        Source xslt = new StreamSource(xsl);
        Transformer transformer = factory.newTransformer(xslt);
        
        //salvo su file la policy in formato Drools-XML
        Source text = new StreamSource(wspolicy_rec);
        File policy_xmlDrools = null; 
        policy_xmlDrools = new File(droolsXmlpolicy_filepath);

        transformer.transform(text, new StreamResult(policy_xmlDrools));


        //conversione di Drools-XML in Drools-Drl
        String drlRule = convertXmlToDrlFile(policy_xmlDrools);
        
		//creazione di PolicyBrick e aggiunta al TB2Msg
        id = id.concat(""+ idNum);
        policyBrick = new DroolsPolicyBrick(drlRule, id);
		tb2Msg.getPolicyBricks().add(policyBrick);
        
        
		
	}
	
	
	//CONVERSIONE Drools-XML -> Drools-DRL: ritorna stringa drl
	private String convertXmlToDrlFile(File xmlFile/*String xmlFileName*/) throws Exception 
	{
		
		Reader source = new InputStreamReader(new FileInputStream(xmlFile));
		PackageBuilderConfiguration conf = new PackageBuilderConfiguration();
        XmlPackageReader reader = new XmlPackageReader(conf.getSemanticModules()); 
		PackageDescr pkgDesc = reader.read(source);
		DrlDumper drlDumper = new DrlDumper();
		String drl = drlDumper.dump(pkgDesc);
		return drl;
	}
	
	public List<Byte> getRemoteSignMaterial()
	{
		return signMaterial;
	}
	
	
	/*public TrustMessage getInitTB2Msg() {
		
		
		return initTB2Msg;
	} */
	
	private void addRequestedProofsId ( String issuer )
	{
		
		requestedProofs.add(issuer);
		
		
	}
	
	public  ArrayList<String> getRequestedProofs ()
	{
		return requestedProofs;
	}
	
		
	

}
