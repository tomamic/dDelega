package it.unipr.ddelega.xacmldd.impl;

import it.unipr.ddelega.xacmldd.XacmlddConstants;
import it.unipr.ddelega.xacmldd.XacmlddStatement;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Iterator;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Element;

import org.opensaml.common.impl.AbstractSAMLObjectMarshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;

import com.sun.xacml.AbstractPolicy;

/**
 * Defualt marshaller for {@link org.opensaml.samlext.xacml.XACMLPolicyStatement} objects.
 * 
 * @author Thomas Florio
 * 
 */
public class XacmlddMarshaller extends AbstractSAMLObjectMarshaller {

	/** Default constructor */
	public XacmlddMarshaller() {
		// super(XacmlddConstants.XACML_SAML_NS, XacmlddStatement.DEFAULT_ELEMENT_LOCAL_NAME);
	}

	/**
	 * Construct object with given namespace and localname
	 * 
	 * @param targetNamespaceURI  the namespace URI of either the schema type QName or element QName of the elements this marshaller operates on.
	 * @param targetLocalNamethe local name of either the schema type QName or element QName of the elements this marshaller operates on
	 * @throws NullPointerException if any of the arguments are null (or empty in the case of String parameters)
	 */
	protected XacmlddMarshaller(String targetNamespaceURI, String targetLocalName)
			throws NullPointerException {
		// super(targetNamespaceURI, targetLocalName);
	}

	/** {@inheritDoc} */
	@Override
	protected void marshallElementContent(XMLObject xmlObject, Element domElement)
			throws MarshallingException {
		XacmlddStatement policyStatement = (XacmlddStatement) xmlObject;

		// Add all the Policy and PolicySet elements
		Iterator<AbstractPolicy> iter = policyStatement.getUniquePolicesList().iterator();
		while (iter.hasNext()) {
			AbstractPolicy p = iter.next();
			Element elem = marshallPolicy( p );
			// If element is correct add it to the DOM
			if (elem != null) {
				domElement.appendChild(domElement.getOwnerDocument().adoptNode(elem));
			}
		}
	}

	/** 
	 * Marshall the give AbastractPolicy into a DOM Element
	 * 
	 * @param p the policy to be marshalled
	 * @return the marshalled DOM element
	 */
	private Element marshallPolicy(AbstractPolicy p) {
		// Marshall the policy into a text xml byte array
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		p.encode(out);

		// Now unmarshall the byte array in a DOM element
		ByteArrayInputStream in = new ByteArrayInputStream( out.toByteArray() );

		// Create the classes to build the doc
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();

		Element elem;
		try {
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			elem = dBuilder.parse(in).getDocumentElement();
		} catch(Exception e) {
			// Something wrong: return null
			return null;
		}

		// Return the main element of this doc
		return elem;
	}

}
