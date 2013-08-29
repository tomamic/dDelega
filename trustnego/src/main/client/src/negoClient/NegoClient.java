package negoClient;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;

import javax.xml.namespace.QName;

import negoUtil.TB2MsgTranslatorToWSTrust;
import negoUtil.WSTrustTranslatorToTB2Msg;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.soap.SOAP11Constants;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPFactory;
import org.apache.axiom.soap.SOAPFault;
import org.apache.axiom.soap.SOAPFaultCode;
import org.apache.axiom.soap.SOAPFaultReason;
import org.apache.axiom.soap.SOAPHeaderBlock;
import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.OperationClient;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.axis2.wsdl.WSDLConstants;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.rampart.RampartMessageData;

import edu.uiuc.cs.TrustBuilder2.TrustBuilder2;
import edu.uiuc.cs.TrustBuilder2.messages.TrustMessage;
import sun.misc.BASE64Encoder;

public class NegoClient {
	
	//File di configurazione NegoClient */
    private static String CLIENT_CONFIG = "src/config/client/client.properties";
    private static String NEGO_CLIENT_CONFIG = "src//negoClient//negoclient.properties";
    
    private static String action = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue";
	private static String reqType = "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue";
	private static String tokenType = "urn:it:unipr:TrustNego:AccessToken";
	
	private static String sts_epr;// = "http://localhost:8082/STSNegotiation/services/STS";
	private static String service_epr;// = "http://localhost:8082/STSNegotiation/services/ServiceNego";
	private static String certPath;
	
	private static String stsPolicy;// "C:\\Users\\filo\\eclipse_workspace\\STSNegotiationClient\\src\\sts_policy.xml";
	
	private static boolean output_control = true;
	static HttpClient httpClient;
	
	private static String resource; // = "project_x";
	private static Certificate cert;
	private static SOAPHeaderBlock secHeader;
	private static OMNamespace wsseNs;
	
	public static void main(String[] args) throws Exception {
		
				
		config();
		
		if ( certPath != null ) importCertificate();	
		
		
		ConfigurationContext ctx = ConfigurationContextFactory.createConfigurationContextFromFileSystem("C:\\Users\\filo\\eclipse_workspace\\STSNegotiationClient\\WebContent\\WEB-INF", null);
		
		SOAPFactory soapFactory = OMAbstractFactory.getSOAP11Factory();
		
		SOAPEnvelope soapEnvelope = soapFactory.getDefaultEnvelope();
		
		SOAPEnvelope responseEnvelope;
		
		TrustMessage inMsg, outMsg;
		
		// creates a new connection manager and a http client object
		MultiThreadedHttpConnectionManager httpConnectionManager = new MultiThreadedHttpConnectionManager();
		httpClient = new HttpClient(httpConnectionManager);
		
		ServiceClient client = new ServiceClient(ctx, null);
		// set the above created objects to re use (per evitere errori di tipo "timeout waiting for connection")
		client.getOptions().setProperty(HTTPConstants.REUSE_HTTP_CLIENT, Constants.VALUE_TRUE);
		client.getOptions().setProperty(HTTPConstants.CACHED_HTTP_CLIENT, httpClient);
		
		//instanzio le classi translator
		TB2MsgTranslatorToWSTrust TB2translator = new TB2MsgTranslatorToWSTrust(NEGO_CLIENT_CONFIG);
        
        WSTrustTranslatorToTB2Msg WSTrustTranslator = new WSTrustTranslatorToTB2Msg(NEGO_CLIENT_CONFIG);
        
        
		//			***invio primo messaggio con RST***
        
        //OMElement rstElem = TrustUtil.createRequestSecurityTokenElement(RahasConstants.VERSION_05_02);
		
		//rstElem = createReqTokenTypeElem (rstElem); 
		
		//soapEnvelope.getBody().addChild(rstElem);
		//OperationClient opClient = sendMsg(soapEnvelope, client);
		
        //processo la risposta
        
        //responseEnvelope = getResponseEnvelope (opClient);
		
        /* if (  output_control )
        {	
        System.out.println("\nResponse : \n" + responseEnvelope.toString() + "\n");

        OMElement responseBody = responseEnvelope.getBody();
        Iterator<OMElement> childIterator = responseBody.getChildElements();

        System.out.println ("Body: " + responseBody.toString());

        while (childIterator.hasNext())
        {
        	OMElement elem = childIterator.next();
        	System.out.println("Elemento RSTR: \n" + elem.toString());
        }
		
		//OMElement element = responseBody.getFirstChildWithName(new QName ("http://schemas.xmlsoap.org/ws/2005/02/trust","RequestSecurityTokenResponse"));
        } */
        
        
		//               **** INIZIALIZZAZIONE DELLA NEGOZIAZIONE **** **** RST con TINit 
		
		//client di Tb2 che genera l' InitBrick -> si chiama createTNInitElement ->
		// si crea il msg soap con RSTR a cui si aggiunge il TNInit ricavato
        
        System.out.println ("\n				****CLIENT*** \n");
        System.out.println ("\n				****INIZIALIZZAZIONE NEGOZIAZIONE*** \n");
		
		final TrustBuilder2 tb2client = new TrustBuilder2(CLIENT_CONFIG);
		
		
		OMElement rstElem = TrustUtil.createRequestSecurityTokenElement(RahasConstants.VERSION_05_02);
 
		soapEnvelope.getBody().addChild(rstElem);
		
		long start = System.currentTimeMillis();
		
		outMsg = tb2client.generateInitMessage();
		
        
        //creo TNInit a partire da messaggio TB2 e lo aggiunge a elemento Rst
      		
        
		OMElement tnInitElement = TB2translator.createTNInitElement(outMsg, rstElem.getOMFactory());
      	//OMElement tnInitElement = TB2translator.getTNInitElement();

      	//SOAPEnvelope soapEnvelopeRstr = soapFactory.getDefaultEnvelope();        
        //OMElement rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(RahasConstants.VERSION_05_02, soapEnvelopeRstr.getBody());
        
        //necessari elementi RequestType e TokenType, altrimenti in Rahas.TokenRequestDispatcher.handle viene lanciata eccezione
        rstElem = createReqTokenTypeElem (rstElem);
      	rstElem.addChild(tnInitElement);
      	
      	if (  output_control ) System.out.println ("WSTrust msg con TNInit: " + soapEnvelope.toString());
      	
      	// INVIO RST con TNInit
      	
      	if ( cert != null )
      	{	
      		client = addWsSecHeader(client);
      		soapEnvelope.getHeader().addChild(secHeader);
      		addCertificateHeader();
      	}
      	
      	OMElement trustNegoHeader = addTrustNegotiationHeader();
      	soapEnvelope.getHeader().addChild(trustNegoHeader);
      	OperationClient opClient = sendMsg(soapEnvelope, client);
      	long end = System.currentTimeMillis();
      	System.out.println("\nDurata inizializzazione: " + (end - start) + " ms.");
      	
      	//opClient = sendMsg (soapEnvelopeRstr, client);
      	if ( opClient == null ) return;
      	
      	
      	
      	
      	// PROCESSO RISPOSTA per finire l'inizializzazione
      	
      	responseEnvelope = getResponseEnvelope(opClient);
      	
      	
      	OMElement rstrElem = responseEnvelope.getBody().getFirstChildWithName(new QName ("http://schemas.xmlsoap.org/ws/2005/02/trust", "RequestSecurityTokenResponse"));
      	Iterator<OMElement> rstrChildIter = rstrElem.getChildElements();
		
		while ( rstrChildIter.hasNext() )
		{
			OMElement elem = rstrChildIter.next();
			if ( elem.getLocalName() == "TNInit" ) tnInitElement = elem;
		}
		inMsg = WSTrustTranslator.createInitTB2Msg(tnInitElement, "serverInit");
      	//inMsg = WSTrustTranslator.getInitTB2Msg();
      	TB2translator.setRemoteSignMaterial(WSTrustTranslator.getRemoteSignMaterial());

      	if(!tb2client.finishSessionEstablishment(inMsg)) 
      	{
      		System.err.println("Error establishing session");
            return;	
      	}
      	
      	else System.out.println ("\nCLIENT: fine inizializzazione negoziazione");
      	
      	// 						**** INVIO MESSAGGIO CON TARGET DELLA NEGOZIAZIONE ****
      	
      	
      	SOAPEnvelope soapEnvelopeRstr = soapFactory.getDefaultEnvelope();
      	rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(RahasConstants.VERSION_05_02, soapEnvelopeRstr.getBody());
      	OMElement appliesTo = TrustUtil.createAppliesToElement( rstrElem, resource, "http://schemas.xmlsoap.org/ws/2004/08/addressing");
      	rstrElem = createReqTokenTypeElem (rstrElem);
      	
      	if ( cert != null )
      	{	
      		client = addWsSecHeader(client);
      		soapEnvelopeRstr.getHeader().addChild(secHeader);
      		addCertificateHeader();
      	}
      	
      	soapEnvelopeRstr.getHeader().addChild(trustNegoHeader);      	
      	opClient = sendMsg(soapEnvelopeRstr, client);
      	if ( opClient == null ) return;
      	
      	
      	//						**** LOOP PRINCIPALE DELLA NEGOZIAZIONE***
      	
      	OMElement tnExchElement = null;
      	OMElement requestedToken = null;
      	OMElement lifetime = null;
      	OMElement created = null;
      	OMElement expires = null;
      	
      	//lista generale per i requestedProofsID
      	ArrayList<String> requestedProofs = new ArrayList<String>();
      	//lista temporanea per i proofsId del particolare msg ricevuto 
      	ArrayList<String> requestedProofsTemp;
      	
  		responseEnvelope = getResponseEnvelope(opClient);
  		int round = 1;
  		
      	while ( responseEnvelope != null )
      	{
      		
      		if ( responseEnvelope.getBody().getFirstElement().getLocalName() == "Fault" ) break;
      		
      		rstrElem = responseEnvelope.getBody().getFirstChildWithName(new QName ("http://schemas.xmlsoap.org/ws/2005/02/trust", "RequestSecurityTokenResponse"));
      		rstrChildIter = rstrElem.getChildElements();


		
      		while ( rstrChildIter.hasNext() )
      		{
      			OMElement elem = rstrChildIter.next();
      			if ( elem.getLocalName() == "TNExchange" ) tnExchElement = elem;
      			if ( elem.getLocalName() == "RequestedSecurityToken" ) requestedToken = elem;
      			if ( elem.getLocalName() == "Lifetime" ) 
      			{
      				lifetime = elem;
      				created = lifetime.getFirstChildWithName(new QName("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd","Created"));
      				expires = lifetime.getFirstChildWithName(new QName("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd","Expires"));      				
      			}
      		}
      		
      		if (requestedToken != null) System.out.println("RequestedToken: " + requestedToken.toString());
      		
      		if ( tnExchElement != null )
      		{
      			//continua la negoziazione
      			
      			System.out.println("\n				****NEGOZIAZIONE*** \n");
      			
      			
      			inMsg = WSTrustTranslator.createTB2Msg(tnExchElement);
      			if( output_control ) System.out.println("Round " + round + "\nTB2Msg ricevuto: " + inMsg.toString());
      			responseEnvelope = null;
      			outMsg = tb2client.negotiate(inMsg);
      			if ( output_control ) System.out.println("\nTB2Msg da inviare: " + outMsg.toString());
      			
      			//prima di costruire il TnExchElement, ottengo lista dei RequestedProofs
      			requestedProofsTemp = WSTrustTranslator.getRequestedProofs();
      			requestedProofs.addAll(requestedProofsTemp); 
      			TB2translator.setRequestedProofs(requestedProofs);
      			
      			//creo il TnExchElement
      			TB2translator.createTnExchElement(outMsg, rstrElem.getOMFactory());
      			tnExchElement = TB2translator.getTNExchElement();
      			
      			//costrusico il soap envelope con Rstr, contentente il TnExchElement appena creato
      			soapEnvelopeRstr = soapFactory.getDefaultEnvelope();
      	      	rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(RahasConstants.VERSION_05_02, soapEnvelopeRstr.getBody());
      	      	rstrElem = createReqTokenTypeElem (rstrElem);
            	rstrElem.addChild(tnExchElement);
            	
            	//invio il messaggio soap
            	
            	if ( cert != null )
              	{	
              		client = addWsSecHeader(client);
              		soapEnvelopeRstr.getHeader().addChild(secHeader);
              		addCertificateHeader();
              	}
            	
            	soapEnvelopeRstr.getHeader().addChild(trustNegoHeader);
            	opClient = sendMsg(soapEnvelopeRstr, client);
            	if ( opClient == null ) return;
      			responseEnvelope = getResponseEnvelope(opClient);
      			
      			//svuoto gli elementi
      			tnExchElement = null;

      			//svuoto la lista dei proofsIdTemp
				if ( !requestedProofsTemp.isEmpty() )
				{
					for ( int i=0; i<requestedProofsTemp.size(); i++ )
					{
						requestedProofsTemp.remove(i);
					}
				}
      			
      			round++;
      			
            	//responseEnvelope = null;
      			
      		}
      		
      		else if ( requestedToken != null )
      		{	
      			//fine negoziazione
      			responseEnvelope = null;
      			/*long*/ end = System.currentTimeMillis();
      			System.out.println ("\n				***FINE NEGOZIAZIONE***");
      			System.out.println ("\nSecurity Token received: " + requestedToken.toString());
      		    System.out.println("\nDurata: " +  (end - start) + " ms.");
      			
      		}
      		
      		
      		
      	
      		
      	}
      	
      	Thread.currentThread();
		Thread.sleep(3000);
      	
      	
      	//		****ACCESSO AL WEB SERVICE, con wsse:BinarySecurityToken contentente il token ricevuto dall'STS****
  		
      	
  		ServiceClient servClient = new ServiceClient(ctx, null);
		
        Options options = new Options();
        options.setAction("urn:Service");
        options.setTo(new EndpointReference(service_epr));
        servClient.setOptions(options);
        
        servClient = addWsSecHeader(servClient);
        addTrustToken(created, expires, requestedToken);
        addCertificateHeader();
        
        OMElement response = servClient.sendReceive(getPayload());
        System.out.println("        ****Risposta del WS****");
        System.out.println(response.toString());
      	
      	
      	httpConnectionManager.closeIdleConnections(0);
      	httpConnectionManager.shutdown(); 
       		
		
	}
	
	static void config() 
	{
		Properties properties = new Properties();
		try {
		    properties.load(new FileInputStream(NEGO_CLIENT_CONFIG));
		} catch (IOException e) {
			
			e.printStackTrace();
		}
		
		sts_epr = properties.getProperty("sts_epr");
		service_epr = properties.getProperty("service_epr");
		resource = properties.getProperty("resource");
		certPath = properties.getProperty("client_cert");
		stsPolicy = properties.getProperty("stsPolicy");
		
	}
	
	static OMElement createReqTokenTypeElem (OMElement parent) throws TrustException
	
	{
		
		TrustUtil.createRequestTypeElement(RahasConstants.VERSION_05_02, parent, reqType);
		TrustUtil.createTokenTypeElement(RahasConstants.VERSION_05_02, parent).setText(tokenType);
			
		return parent;
	}
	
	static SOAPEnvelope getResponseEnvelope ( OperationClient opClient ) throws AxisFault
	{
		MessageContext responseMsgCtx = opClient.getMessageContext(WSDLConstants.MESSAGE_LABEL_IN_VALUE); // WSDLConstants.MESSAGE_LABEL_IN_VALUE == "In"
        SOAPEnvelope responseEnvelope = responseMsgCtx.getEnvelope();
		
		return responseEnvelope;
	}
	
	static OperationClient sendMsg (SOAPEnvelope env, ServiceClient client) throws Exception
	{
	
		OperationClient opClient = null;
		
		try {
			
		client.engageModule("addressing");
		client.engageModule("rampart");
		Options options = client.getOptions();
		options.setAction(action);
		options.setTo(new EndpointReference(sts_epr));
		
		// set the above created objects to re use.
		client.getOptions().setProperty(HTTPConstants.REUSE_HTTP_CLIENT, Constants.VALUE_TRUE);
		client.getOptions().setProperty(HTTPConstants.CACHED_HTTP_CLIENT, httpClient);
		
		//Rampart signature
		options.setProperty(RampartMessageData.KEY_RAMPART_POLICY,  loadPolicy(stsPolicy));
		
	  	MessageContext msgctx = new MessageContext();
	  	msgctx.setEnvelope(env);
	  	opClient = client.createClient(ServiceClient.ANON_OUT_IN_OP);
	  	opClient.addMessageContext(msgctx);
	    opClient.execute(true);
		
		}
		catch ( AxisFault e )
		{
			System.out.println("Negotiation failure!");
			e.printStackTrace();
			return null;
		}
		
	    return opClient;
		
	}
	
	private static Policy loadPolicy(String xmlPath) throws Exception {
		StAXOMBuilder builder = new StAXOMBuilder(xmlPath);
		return PolicyEngine.getPolicy(builder.getDocumentElement());
	}
	
	static void sendFaultMsg ( ConfigurationContext ctx, String faultMessage ) throws AxisFault
	{
		ServiceClient client = new ServiceClient(ctx, null);
		
		OperationClient opClient = null;
		client.engageModule("addressing");
		Options options = client.getOptions();
		options.setAction(action/*"http://www.w3.org/2005/08/addressing/fault"*/);
		options.setTo(new EndpointReference(sts_epr));
		
		// set the above created objects to re use.
		client.getOptions().setProperty(HTTPConstants.REUSE_HTTP_CLIENT, Constants.VALUE_TRUE);
		client.getOptions().setProperty(HTTPConstants.CACHED_HTTP_CLIENT, httpClient);
		
		SOAPFactory soapFactory = OMAbstractFactory.getSOAP11Factory();
    	SOAPFault soapFault = soapFactory.createSOAPFault(soapFactory.getDefaultEnvelope().getBody());
    	
    	SOAPFaultCode soapFaultCode = soapFactory.createSOAPFaultCode(soapFault);
    	soapFaultCode.setText("Fault");
    	//SOAPFaultValue soapFaultValue = soapFactory.createSOAPFaultValue(soapFaultCode);
    	//soapFaultValue.setText(new QName("http://test.org", "TestFault", "test"));
    	//soapFaultCode.addChild(soapFaultValue);
    	
    	SOAPFaultReason soapFaultReason = soapFactory.createSOAPFaultReason(soapFault);
    	soapFaultReason.setText(faultMessage);
    	//SOAPFaultText soapFaultText = soapFactory.createSOAPFaultText(soapFaultReason);
    	//soapFaultText.setText("Negotiation-Failure:halted");
    	
    	MessageContext msgctx = new MessageContext();
    	msgctx.setProperty(SOAP11Constants.SOAP_FAULT_CODE_LOCAL_NAME, soapFaultCode);
    	msgctx.setProperty(SOAP11Constants.SOAP_FAULT_STRING_LOCAL_NAME, soapFaultReason);
    	
    	SOAPEnvelope env = soapFactory.getDefaultEnvelope();
    	env.getBody().addFault(soapFault);
		
	  	//MessageContext msgctx = new MessageContext();
	  	msgctx.setEnvelope(env);
	  	opClient = client.createClient(ServiceClient.ANON_OUT_IN_OP);
	  	opClient.addMessageContext(msgctx);
	    opClient.execute(true);
	
	}
	
	private static OMElement getPayload() {
		OMFactory factory = OMAbstractFactory.getOMFactory();
		OMNamespace ns = factory.createOMNamespace("http://negoService","ns1");
		OMElement elem = factory.createOMElement("Service", ns);
		//OMElement childElem = factory.createOMElement("arg", null);
		//childElem.setText(value);
		//elem.addChild(childElem);
		        
		return elem;
		
	    }
	
	private static SOAPHeaderBlock addTrustNegotiationHeader ()
	{
		//OMFactory fac = OMAbstractFactory.getOMFactory();
		SOAPFactory factory = OMAbstractFactory.getSOAP12Factory();

	    //wsse:Security header

	    //OMElement trustNegotiationHeader = fac.createOMElement("TrustNegotiation", null); 
	    //OMAttribute trustNegoNS = fac.createOMAttribute("xmlns", null, "urn:it:unipr:TrustNego");
	    
		//trustNegotiationHeader.addAttribute(trustNegoNS);
	    
	    //client.addHeader(trustNegotiationHeader);
		
		SOAPHeaderBlock trustNegotiationHeader = factory.createSOAPHeaderBlock("TrustNegotiation", null);
		OMAttribute trustNegoNS = factory.createOMAttribute("xmlns", null, "urn:it:unipr:TrustNego");
		trustNegotiationHeader.addAttribute(trustNegoNS);
		
		return trustNegotiationHeader;
	}
	
	
	private static ServiceClient addWsSecHeader (ServiceClient client)
	{
		//OMFactory fac = OMAbstractFactory.getOMFactory();
		SOAPFactory factory = OMAbstractFactory.getSOAP12Factory();
	    //wsse:Security header
		
		 

	    wsseNs = factory.createOMNamespace( "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "wsse");
	    secHeader = factory.createSOAPHeaderBlock("Security", wsseNs);
	    //SOAPHeaderBlock header;
	    client.addHeader(secHeader);
		
		return client;
	}
	
	//aggiunge un wsse:Security header, con Timestamp (con valori presi da LifeTime del msg dell' STS), 
	//contenente il TrustToken ricevuto dall' STS
	
	private static void addTrustToken ( OMElement created, OMElement expires, OMElement requestedToken )
	{

        OMFactory fac = OMAbstractFactory.getOMFactory();

        /*//wsse:Security header

        wsseNs = fac.createOMNamespace( "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "wsse");
        secHeader = fac.createOMElement("Security", wsseNs); */

        // wssw:BinarySecurityToken

        OMElement binarySecToken = fac.createOMElement("BinarySecurityToken", wsseNs);
        OMAttribute encodingType = fac.createOMAttribute("EncodingType", null, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
        binarySecToken.addAttribute(encodingType);
        
        //adding Timestamp: creato manualmente per inserire stessi valori del wst:LifeTime del msg ricevuto dall' STS
        OMNamespace wsu = fac.createOMNamespace("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "wsu");
        OMElement timestamp = fac.createOMElement("Timestamp", wsu);
        OMElement created_ts = fac.createOMElement("Created", wsu);
        created_ts.setText(created.getText());
        timestamp.addChild(created_ts);
        OMElement expires_ts = fac.createOMElement("Expires", wsu);
        expires_ts.setText(expires.getText());
        //expires_ts.setText("2012-08-06T16:41:05.872Z");
        timestamp.addChild(expires_ts);
        binarySecToken.addChild(timestamp);      

        secHeader.addChild(binarySecToken);
        //inserisco l'AccessToken in modo trasparente
        OMElement accessToken = requestedToken.getFirstElement();
        binarySecToken.addChild(accessToken);
        //binarySecToken.setText(requestedToken.getText());
        //binarySecToken.setText("ciao");
        
	}
	
	private static void addCertificateHeader ( )
	{
		
		OMFactory fac = OMAbstractFactory.getOMFactory();
		OMElement binarySecToken = fac.createOMElement("BinarySecurityToken", wsseNs);
        OMAttribute encodingType = fac.createOMAttribute("EncodingType", null, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
		OMAttribute vauteType = fac.createOMAttribute("ValueType", null, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
		binarySecToken.addAttribute(vauteType);
		binarySecToken.addAttribute(encodingType);
		
		try {
			binarySecToken.setText(new BASE64Encoder().encode(cert.getEncoded()));
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		secHeader.addChild(binarySecToken);
		
	}
	
	
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
	

}
