package negoService;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

import negoUtil.TB2MsgTranslatorToWSTrust;
import negoUtil.TrustToken;
import negoUtil.WSTrustTranslatorToTB2Msg;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMDocument;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.om.OMNode;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.soap.SOAP11Constants;
import org.apache.axiom.soap.SOAPBody;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPFactory;
import org.apache.axiom.soap.SOAPFault;
import org.apache.axiom.soap.SOAPFaultCode;
import org.apache.axiom.soap.SOAPFaultReason;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.util.XMLUtils;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.RahasData;
import org.apache.rahas.TokenIssuer;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;


import edu.uiuc.cs.TrustBuilder2.messages.TrustMessage;

public class NegoIssuer implements TokenIssuer {
	

  	private String policyFileName = "C:\\Users\\filo\\eclipse_workspace\\STSNegotiation\\src\\claim_ok_for_cl_issue.xml";
	
  	private static String NEGO_ISSUER_CONFIG = "C:\\Users\\filo\\eclipse_workspace\\STSNegotiation\\src\\negoService\\negoissuer.properties";
  	
  	private boolean output_control = false;
  	
  	private static String HOST; // = "127.0.0.1";
  	private static /*final*/ int PORT; // = 8083;
  	
  	private String[] trusted_services; 
  	
  	private static int call_num = 0;
  	
  	private static Socket sock;
  	private static ObjectOutputStream output;
  	private static ObjectInputStream input;
  	
  	//oggetti translator TB2<->WSTrust
  	WSTrustTranslatorToTB2Msg wsTrustTranslator;
  	TB2MsgTranslatorToWSTrust tb2Translator;
  	
  	private static List<Byte> sigMaterial;

  	public NegoIssuer() {
  		
  		config();
  	}
  	
  	private void config() {
  		
  		
  		String oidMapFile;
  		String oidPropertyName;
  		Properties properties = new Properties();
		try {
		    properties.load(new FileInputStream(NEGO_ISSUER_CONFIG));
		} catch (IOException e) {
			
			e.printStackTrace();
		}
		
		HOST = properties.getProperty("host");
		PORT = Integer.parseInt(properties.getProperty("port"));
		trusted_services = properties.getProperty("trusted_services").split(",");
		oidMapFile = properties.getProperty("oidMapFile");
		oidPropertyName = properties.getProperty("oidPropertyName");
		System.setProperty(oidPropertyName, oidMapFile);
		
		
		wsTrustTranslator = new WSTrustTranslatorToTB2Msg(NEGO_ISSUER_CONFIG);
		tb2Translator = new TB2MsgTranslatorToWSTrust(NEGO_ISSUER_CONFIG);
		tb2Translator.setRemoteSignMaterial(sigMaterial);
		
		
  	}
  	
	@Override
	public String getResponseAction(RahasData arg0) throws TrustException {
		return "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue";
	}

	@Override
	public SOAPEnvelope issue(RahasData data) throws TrustException {
		
		//System.out.println("Working directory Issuer: " + System.getProperty("user.home"));
        
		MessageContext inMsgCtx = data.getInMessageContext();
        SOAPEnvelope env = TrustUtil.createSOAPEnvelope(inMsgCtx
                .getEnvelope().getNamespace().getNamespaceURI());
        
        TrustMessage inMsg, outMsg;
        OMElement rstElem = null;
        OMElement rstrElem = null;
        OMElement RstrFinal = null;
        OMElement tnInit = null;
        OMElement tnInit_ = null;
        OMElement tnExch = null;
        OMElement appliesTo = null;
        String resource;
        boolean finished = false;
        boolean negoError = false;
        String faultMessage = null;
        
        String token;
        
        //lista generale per i requestedProofsID
      	ArrayList<String> requestedProofs = new ArrayList<String>();
      	//lista temporanea per i proofsId del particolare msg ricevuto 
      	ArrayList<String> requestedProofsTemp;
      	
      	
      	
      	
      	
      	//controllo se la socket deve essere inizializzata
        
        try {
        	System.out.println ("\ncall number: " + call_num);
        	
			if ( sock == null || output == null || input == null /*(input.read() == -1)*/ || sock.isClosed() ) initializeSocket();
			
			//controllo della connessione con TB2 Server
	        //output.write(1);
	        //input.read();
			
		} catch (UnknownHostException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
        
        
        call_num++;
        
        try 
        {
        	
        System.out.println ("\n                   ***ISSUER***\n");

        //***Estraggo element RSTR***

        SOAPBody responseBody = inMsgCtx.getEnvelope().getBody();
        if ( responseBody != null && output_control ) System.out.println(responseBody.toString());
        //rstrElem = responseBody.getFirstElement();
        rstrElem = responseBody.getFirstChildWithName(new QName ("http://schemas.xmlsoap.org/ws/2005/02/trust", "RequestSecurityTokenResponse"));
        rstElem = responseBody.getFirstChildWithName(new QName ("http://schemas.xmlsoap.org/ws/2005/02/trust", "RequestSecurityToken"));
        if ( rstrElem == null ) rstrElem = rstElem;
        if ( rstrElem != null && output_control )System.out.println("ISSUER: Rstr ricevuto: " + rstrElem.toString());
        
        //controllo se c'è header TrustNegotiation
        SOAPHeader header = inMsgCtx.getEnvelope().getHeader();
    	Iterator<OMElement> headerIter = header.getChildElements();
    	OMElement headerElem = null;
    	boolean trustNegoHeaderPresent = false;
    	while ( headerIter.hasNext() )
    	{
    		headerElem = headerIter.next();
    		if ( headerElem.getLocalName().equals("TrustNegotiation") ) trustNegoHeaderPresent = true;
    	}
        
    	if ( !trustNegoHeaderPresent ) 
    	{
    		negoError = true;
			faultMessage = "Negotiation Failure: missing TrustNegotiation header";
    	}
    		 
        
        if ( rstrElem != null && !negoError)
        	
        {
        	
        	if ( output_control )
        	{	
        		System.out.println("ISSUER: Rstr ricevuto(estratto con QName): " + rstrElem.toString());
        		System.out.println("ISSUER: estraggo TNInit o AppliesTo o TNExchange");
        	}
        	
            //***Estraggo TNInit o TNExchange*** per valutare se sono nella prima o nella seconda fase della negoziazione
        	
			Iterator<OMElement> rstrChildIter = rstrElem.getChildElements();
			
			while ( rstrChildIter.hasNext() )
			{
				OMElement elem = rstrChildIter.next();
				if ( elem.getLocalName() == "TNInit" ) tnInit = elem;
				if (elem.getLocalName() == "AppliesTo" ) appliesTo = elem;
				if ( elem.getLocalName() == "TNExchange" ) tnExch = elem;
				
			}
	
        }
        
        if (appliesTo != null && output_control) System.out.println ("AppliesTo: " + appliesTo.toString());
        	
		if (tnInit != null && !negoError ) //*** INIZIALIZZAZIONE DELLA NEGOZIAZIONE ***
		{	
			if ( output_control ) System.out.println ("TNInit: " + tnInit.toString() + "\n");


        		
				
				System.out.println("\n***INIZIALIZZAZIONE DELLA NEGOZIAZIONE***");
				inMsg = wsTrustTranslator.createInitTB2Msg(tnInit, "clientInit");
				//inMsg = wsTrustTranslator.getInitTB2Msg();
				sigMaterial = wsTrustTranslator.getRemoteSignMaterial();
				if ( output!= null ) output.writeObject(inMsg);
				else System.out.println ("\noutput null!!!");
				output.flush();
	            outMsg = (TrustMessage)input.readObject();
	            
	            if ( !outMsg.getContinue() ) 
	            {
	            	negoError = true;
	            	faultMessage = "Negotiation Failure: inizialitazion error";
	            }
	            else 
	            {
	            	System.out.println("\n***INIZIALIZZAZIONE CONCLUSA***\n" + outMsg.toString());
	            	
	            	//tnInit = tb2Translator.getTNInitElement();
	            	OMElement Rstr = TrustUtil.createRequestSecurityTokenResponseElement(RahasConstants.VERSION_05_02, env.getBody() );
	            	OMFactory Rstrfac = Rstr.getOMFactory();
	            	tnInit = tb2Translator.createTNInitElement(outMsg, Rstrfac);

	            	Rstr.addChild(tnInit);

	            	
	            	
	            	
	            	
	            	//firstChild = XMLUtils.toOM((Element) firstChildDom);
	            	
	            	//env.getBody().addChild((OMNode) firstChild);
	            	//tnInit_ = tnInit.cloneOMElement();
	            	//tnInit_.build();
	            	//OMElement prova = OMAbstractFactory.getOMFactory().createOMElement("prova", null);
	            	//Rstr.addChild(prova);
	            	System.out.println("\n***DOPO AGGIUNTA TNINIT!!!!***\n");
	            	return env;
	            }
				
		}
        
		else
		{
				//****LOOP PRINCIPALE della negoziazione****
			
				//lista generale per i requestedProofsID
		      	/*ArrayList<String> requestedProofs = new ArrayList<String>();
		      	//lista temporanea per i proofsId del particolare msg ricevuto 
		      	ArrayList<String> requestedProofsTemp; */
				
				if ( appliesTo != null && !negoError ) 
				{	
					//primo round della negoziazione
					
					System.out.println( "\n***NEGOZIAZIONE***");
					
					//resource target e invio resource policy 
					System.out.println("\n****ISSUER: estrazione risorsa");
					resource = getResourceFromAppliesTo(appliesTo);
					if ( resource != null )
					{
						
					inMsg = wsTrustTranslator.createResourceRequestTB2Msg(resource);
					//System.out.println (inMsg.toString());
					output.writeObject(inMsg);
					output.flush();
					outMsg = (TrustMessage)input.readObject();
					if ( output_control ) System.out.println (outMsg.toString());
					
						if ( !outMsg.getContinue() ) 
						{
							negoError = true;
							faultMessage = "Negotiation Failure: inizialitazion error";
						}
						else
						{
							OMElement Rstr = TrustUtil.createRequestSecurityTokenResponseElement(RahasConstants.VERSION_05_02, env.getBody());
							OMFactory Rstrfac = Rstr.getOMFactory();
							tb2Translator.createTnExchElement(outMsg, Rstrfac);
							tnExch = tb2Translator.getTNExchElement();
							if ( output_control ) System.out.println("tnExchange Element:" + tnExch.toString());
							
							Rstr.addChild(tnExch);

							return env;
						}
					}
					else
					{
						negoError = true;
						faultMessage = "Negotiation Failure: inizialitazion error - Service not trusted";
					}
				}
				
				if ( tnExch != null && !negoError )
				{
					//round successivi della negoziazione
					
					System.out.println( "\n***NEGOZIAZIONE: round successivi***");
					
					inMsg = wsTrustTranslator.createTB2Msg(tnExch);
					if (output_control) System.out.println ("\ntb2Msg creato dal Trust-msg ricevuto: \n " + inMsg.toString());
					output.writeObject(inMsg);
					output.flush();
					outMsg = (TrustMessage)input.readObject();
					if ( output_control ) System.out.println("\nMessaggio ricevuto dal server: \n" + outMsg.toString());
					
					//prima di costruire il TnExchElement, ottengo lista dei RequestedProofs
	      			requestedProofsTemp = wsTrustTranslator.getRequestedProofs();
	      			requestedProofs.addAll(requestedProofsTemp);
	      			System.out.println("requestedproof:" + requestedProofs.toString());
	      			tb2Translator.setRequestedProofs(requestedProofs);
	      			
	      			//svuoto requestedProofsTemp
	      			if ( !requestedProofsTemp.isEmpty() )
					{
						for ( int i=0; i<requestedProofsTemp.size(); i++ )
						{
							requestedProofsTemp.remove(i);
						}
					}
					
					//tb2Translator.createTnExchElement(outMsg);
	      			OMElement Rstr = TrustUtil.createRequestSecurityTokenResponseElement(RahasConstants.VERSION_05_02, env.getBody());
					OMFactory Rstrfac = Rstr.getOMFactory();
					tb2Translator.createTnExchElement(outMsg, Rstrfac);
					
					if ( tb2Translator.getNegoStatus() ) 
					{
						finished = true;
						RstrFinal = Rstr;
					}
					
					else if ( !tb2Translator.getNegoStatus() && !outMsg.getContinue() ) 
						 {
							negoError = true;
							faultMessage = "Negotiation-Failure:halted";
						 }
					
						 else
						 {
							 
							 tnExch = tb2Translator.getTNExchElement();
							 
							 Rstr.addChild(tnExch);
							 return env;
						 } 
									
				}
			
		}		
		
		}
		
        catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}			

		
		
		//risposta alla prima RST
        //OMElement Rstr = null;
		if ( !negoError )
		{
			 //Rstr = TrustUtil.createRequestSecurityTokenResponseElement(RahasConstants.VERSION_05_02, env.getBody());
		}
		
		
		
        if ( finished )  //***NEGOTIATION SUCCESS: invio requestedSecurityTokenElement e chiudo socket***
        {
        	
        	
        	try {
				sock.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        	
        	//OMElement Rstr = TrustUtil.createRequestSecurityTokenResponseElement(RahasConstants.VERSION_05_02, env.getBody());
        	
        	//aggiungo wst:Lifetime
        	long ttl = 3600000;
        	OMElement lifeTime = TrustUtil.createLifetimeElement(RahasConstants.VERSION_05_02, RstrFinal, ttl);
        	OMElement created = lifeTime.getFirstChildWithName(new QName("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd","Created"));
			OMElement expires = lifeTime.getFirstChildWithName(new QName("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd","Expires"));
        	String lifeTimeText = created.getText() + expires.getText();
			
        	TrustToken trustToken = new TrustToken(NEGO_ISSUER_CONFIG);
        	trustToken.setConfiguration();
        	
        	//estraggo il certificato del client, se presente, e lo uso per creare AccessToken
        	SOAPHeader header = inMsgCtx.getEnvelope().getHeader();
        	Iterator<OMElement> headerIter = header.getChildElements();
        	OMElement clientCertElem = null;
        	OMElement elem, elem2;
        	boolean certFound = false;
        	while ( headerIter.hasNext() && certFound == false )
        	{
        		elem = headerIter.next();
        		if ( elem.getLocalName().equals("Security") )
        		{
        			Iterator<OMElement> secHeaderIter = elem.getChildElements();
        			while ( secHeaderIter.hasNext() && certFound == false )
        			{
        				elem2 = secHeaderIter.next();
        				if ( elem2.getLocalName().equals("BinarySecurityToken") )
        				{
        					Iterator<OMAttribute> attribIter = elem2.getAllAttributes();
        					while ( attribIter.hasNext() )
        					{
        						OMAttribute attr = attribIter.next();
        						if ( attr.getLocalName().equals("ValueType") && attr.getAttributeValue().equals("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3") )
        							clientCertElem = elem2;
        							certFound = true;
        				
        					}
        				}
        			}
        		}
        	}
        	
        	String clientCertString = null;
        	if ( clientCertElem != null ) clientCertString = clientCertElem.getText();
        	System.out.println("Client cert:" + clientCertString.toString());
        	
        	//ottengo il trust token e completo il messaggio
        	try {
        		
				String trust_token = trustToken.createTrustToken(lifeTimeText, clientCertString);
			
				OMElement requestedToken = TrustUtil.createRequestedSecurityTokenElement(RahasConstants.VERSION_05_02, RstrFinal);
				//adding AccessToken
				 OMFactory fac = RstrFinal.getOMFactory();//OMAbstractFactory.getOMFactory();
		        //OMNamespace accessTokenNS = fac.createOMNamespace ("urn:it:unipr:TrustNego" , null);
		        OMElement accessToken = fac.createOMElement("AccessToken", null);
		        OMAttribute accessTokenNS = fac.createOMAttribute("xmlns", null, "urn:it:unipr:TrustNego");
		        accessToken.addAttribute(accessTokenNS);
		        accessToken.setText(trust_token);
		        requestedToken.addChild(accessToken);
				
				//requestedToken.setText(trust_token);
        	
        	} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        	
        	return env;
        }
        
        
        if ( negoError )   //***NEGOTIATION FAILURE: invio soap-Fault msg***
        {
        	
        	try {
				sock.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        	
        	System.out.println("Negotiation failure!!");
        	SOAPFactory soapFactory = OMAbstractFactory.getSOAP11Factory();
        	SOAPFault soapFault = soapFactory.createSOAPFault(soapFactory.getDefaultEnvelope().getBody());
        	
        	SOAPFaultCode soapFaultCode = soapFactory.createSOAPFaultCode(soapFault);
        	soapFaultCode.setText("Service-Fault");
        	//SOAPFaultValue soapFaultValue = soapFactory.createSOAPFaultValue(soapFaultCode);
        	//soapFaultValue.setText(new QName("http://test.org", "TestFault", "test"));
        	//soapFaultCode.addChild(soapFaultValue);
        	
        	SOAPFaultReason soapFaultReason = soapFactory.createSOAPFaultReason(soapFault);
        	soapFaultReason.setText(faultMessage);
        	//SOAPFaultText soapFaultText = soapFactory.createSOAPFaultText(soapFaultReason);
        	//soapFaultText.setText("Negotiation-Failure:halted");
        	
        	
        	inMsgCtx.setProperty(SOAP11Constants.SOAP_FAULT_CODE_LOCAL_NAME, soapFaultCode);
        	inMsgCtx.setProperty(SOAP11Constants.SOAP_FAULT_STRING_LOCAL_NAME, soapFaultReason);

        	env.getBody().addFault(soapFault);
        }
        
        return env;
		
	}
	
	
	private String getResourceFromAppliesTo ( OMElement appliesToElem )
	{
		String resource = null;
		OMElement epr = null;
		boolean resource_found = false;
		String[] resource_strings;
		
		Iterator<OMElement> appliesToIter = appliesToElem.getChildElements();
		while (appliesToIter.hasNext())
		{
			OMElement elem = appliesToIter.next();
			if ( elem.getLocalName() == "EndpointReference" ) epr = elem; 
		}
		
		Iterator<OMElement> eprIter = epr.getChildElements();
		while ( eprIter.hasNext() )
		{
			OMElement elem = eprIter.next();
			if ( elem.getLocalName() == "Address" ) resource = elem.getText();
		}
		
		for ( int i=0; i<trusted_services.length; i++ )
		{
			if ( resource.equals(trusted_services[i]) ) resource_found = true; 
		}
		
		if (resource_found) 
		{
			resource_strings = resource.split("/");
			resource = resource_strings[resource_strings.length-1];
			return resource;
		}
		else return null;
	}
	
	private void initializeSocket() throws UnknownHostException, IOException
	{
		sock = new Socket(HOST, PORT);
		output = new ObjectOutputStream(sock.getOutputStream());
		input = new ObjectInputStream(sock.getInputStream());
	}

	
	
	//prende wsp:Policy da file
	private OMElement getPolicy ()
	{
		FileInputStream policy = null;
		try {
			policy = new FileInputStream (policyFileName);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
        
		StAXOMBuilder stAXOMBuilder = null;
        try {
			stAXOMBuilder = new StAXOMBuilder(policy);
		} catch (XMLStreamException e) {
			
			e.printStackTrace();
		}
        
        OMElement documentElement = stAXOMBuilder.getDocumentElement();
        
        return documentElement;
		
	}

	@Override
	public void setConfigurationElement(OMElement arg0) {}

	@Override
	public void setConfigurationFile(String arg0) {}

	@Override
	public void setConfigurationParamName(String arg0) {}

}
