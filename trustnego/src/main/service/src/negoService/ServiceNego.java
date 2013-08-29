package negoService;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.SimpleTimeZone;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPException;
import javax.xml.ws.soap.SOAPFaultException;

import negoUtil.TrustToken;

import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPHeader;

import javax.xml.soap.SOAPFactory;
import javax.xml.soap.SOAPFault;

import org.apache.axis2.context.MessageContext;

public class ServiceNego {
	
	private static String NEGO_SERVICE_CONFIG = "C:\\Users\\filo\\eclipse_workspace\\STSNegotiation\\src\\negoService\\negoservice.properties";
	
	public String Service() throws Exception {
		
		MessageContext messageContext = MessageContext.getCurrentMessageContext();
		
		//estrazione, con controllo temporale incluso, del Timestamp
		String timestampText = getTimestampText(messageContext);
		if ( timestampText == "Message Expired" ) throwSoapNegoFault("Message Expired");
		
		//estrazione certificato client, se presente
		String clientCertString = getClientCertificate(messageContext);
		
		//instanziazione di un TrustToken per verificare il token di sicurezza 
		String trustNegoTokenString = getTrustNegoTokenString(messageContext);
		TrustToken trustToken = new TrustToken(NEGO_SERVICE_CONFIG);
		trustToken.setConfiguration();
		
		//se il token non è valido, viene inviato un messaggio SoapFault
		if ( !(trustToken.verifyTrustToken(timestampText, clientCertString, trustNegoTokenString)) ) throwSoapNegoFault("Invalid Trust Nego Token");

		//se il token è valido, viene svolta l'operazione richiesta
		System.out.println("\n****Web Service: trustNegoToken validated!!!****");
		
		return "This is the service, after the negotiation";
		
		
	}
	
	private String getClientCertificate (MessageContext messageContext)
	{
		String clientCertString = null;
		
		SOAPHeader header = messageContext.getEnvelope().getHeader();
    	Iterator<OMElement> headerIter = header.getChildElements();
    	OMElement clientCertElem = null;
    	OMElement elem, elem2;
    	while ( headerIter.hasNext() )
    	{
    		elem = headerIter.next();
    		if ( elem.getLocalName().equals("Security") )
    		{
    			Iterator<OMElement> secHeaderIter = elem.getChildElements();
    			while ( secHeaderIter.hasNext() )
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
    				
    					}
    				}
    			}
    		}
    	}

    	if ( clientCertElem != null ) clientCertString = clientCertElem.getText();
		
		return clientCertString; 
	}
	
	
	// - estrae dalla request il testo dell'elemento Timestamp (formato da Created e Expires)
	// - controlla che il messaggio non sia scaduto
	private String getTimestampText (MessageContext messageContext) throws ParseException, SOAPException
	{
		String timestampText = null;
		
		SOAPHeader soapHeader = messageContext.getEnvelope().getHeader();
		OMElement secHeader = soapHeader.getFirstChildWithName(new QName("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Security"));
		Iterator<OMElement> secHeaderIter = secHeader.getChildrenWithName(new QName("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "BinarySecurityToken"));
		OMElement binaryToken;
		OMElement timestamp = null;
		while ( secHeaderIter.hasNext() )
		{
			binaryToken = secHeaderIter.next();
			timestamp = binaryToken.getFirstChildWithName(new QName("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Timestamp"));
			if ( timestamp != null ) break;
		}
		if ( timestamp != null )
		{
		Iterator<OMElement> timestampIter = timestamp.getChildElements();
		OMElement elem, created = null, expires = null;
		while ( timestampIter.hasNext() )
		{
			elem = timestampIter.next();
			if ( elem.getLocalName() == "Created" ) created = elem;
			if ( elem.getLocalName() == "Expires" ) expires = elem;
		}
		
		if ( !checkTimestamp( created, expires ) ) return "Message Expired";
		
		else 
		{ 
			timestampText = created.getText() + expires.getText();
			
		}
		}
		else throwSoapNegoFault("Missin Timestamp");
		
		return timestampText;
	}
	
	// controllo della validità temporale del messaggio
	private boolean checkTimestamp ( OMElement created, OMElement expires ) throws ParseException
	{
		boolean checked = false;
		
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		dateFormat.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));
		//get current date time with Date()
		Date dateObj = new Date();
		String actualDateTime = dateFormat.format(dateObj);
		String[] temp = actualDateTime.split(" ");
		String date = temp[0];
		//System.out.println("acutal date string: " + date );
		String time = temp[1];
		
		String expiresDateTime = expires.getText();
		//System.out.println ("expires text: " + expiresDateTime);
		String temp_2[] = expiresDateTime.split("T");
		//System.out.println( "temp_2[0]: " + temp_2[0] + " temp_2[1]: " + temp_2[1] );
		String dateTimestamp = temp_2[0];
		String timeTimestamp = temp_2[1].substring(0, (temp_2[1].length()-5));
		//System.out.println("timestamp time: " + timeTimestamp);
		
		String DateTimestampFormatted = temp_2[0] + " " + timeTimestamp;
		Date d1=dateFormat.parse(DateTimestampFormatted);
	    Date d2=dateFormat.parse(actualDateTime);
	    //System.out.println("Actual date time: " + d2.toString() + "expir_time: " + d1.toString());
	    long d1Ms=d1.getTime();
	    long d2Ms=d2.getTime();
	    //System.out.println ( "expir sec: " + d1Ms + "actual sec:" + d2Ms );
	    long diff = d1Ms-d2Ms;
	    
	    //System.out.println( "date equals: " + date.equals(dateTimestamp) + "diff: " + diff );
		
		if ( date.equals(dateTimestamp) && diff > 0 ) checked = true;
		else checked = false;
		

		return checked;
	}
	
	// estrae dal messaggio il token di sicurezza per l'accesso
	private String getTrustNegoTokenString ( MessageContext messageContext )
	{
		
		String trustTokenString = null;
		
		SOAPHeader soapHeader = messageContext.getEnvelope().getHeader();
		OMElement secHeader = soapHeader.getFirstChildWithName(new QName("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Security"));
		Iterator<OMElement> secHeaderIter = secHeader.getChildrenWithName(new QName("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "BinarySecurityToken"));
		OMElement accessToken = null, elem;
		while ( secHeaderIter.hasNext() )
		{
			elem = secHeaderIter.next();
			Iterator<OMElement> binaryTokenIter = elem.getChildrenWithLocalName("AccessToken");  
			if ( binaryTokenIter.hasNext() ) accessToken = binaryTokenIter.next();
		}
		trustTokenString = accessToken.getText();
		
		return trustTokenString;		
	}
	
	// invia un messaggio SoapFault contenente un messaggio specifico
	private void throwSoapNegoFault (String faultMessage) throws SOAPException
	{
		
		//SOAPFactory soapFactory = OMAbstractFactory.getSOAP11Factory();
    	SOAPFault soapFault = SOAPFactory.newInstance(SOAPConstants.SOAP_1_1_PROTOCOL).createFault();  
    	
    	soapFault.setFaultCode(new QName(SOAPConstants.URI_NS_SOAP_ENVELOPE, "Sender"));
    	soapFault.setFaultString(faultMessage); 
    	
    	throw new SOAPFaultException((SOAPFault) soapFault);
	
	}

}
