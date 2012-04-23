package it.unipr.ddelega.xacmldd.impl;

import it.unipr.ddelega.xacmldd.XacmlddStatement;

import org.opensaml.common.impl.AbstractSAMLObjectUnmarshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;

import org.w3c.dom.Element;

import com.sun.xacml.ParsingException;
import com.sun.xacml.Policy;
import com.sun.xacml.PolicySet;

/**
 * Default unmarshaller for {@link org.opensaml.samlext.xacml.XACMLPolicyStatement} objects.
 * @author Thomas Florio
 *
 */
public class XacmlddUnmarshaller extends AbstractSAMLObjectUnmarshaller {

	/** Default Constructor */
	public XacmlddUnmarshaller() {
		// super(XacmlddConstants.XACML_SAML_NS, XacmlddStatement.DEFAULT_ELEMENT_LOCAL_NAME);
	}

	/**
	 * Build the unmarshaller with the given namespace and localname
	 * 
	 * @param targetNamespaceURI the namespace URI of either the schema type QName or element QName of the elements this unmarshaller operates on
	 * @param targetLocalName the local name of either the schema type QName or element QName of the elements this unmarshaller operates on
	 * @throws NullPointerException if any of the arguments are null (or empty in the case of String parameters)
	 */
	protected XacmlddUnmarshaller(String namespaceURI, String elementLocalName) {
		// super(namespaceURI, elementLocalName);
	}

	/** {@inheritDoc} */
	@Override
	protected void processChildElement(XMLObject parentSAMLObject, XMLObject childSAMLObject)
			throws UnmarshallingException {
		XacmlddStatement xps = (XacmlddStatement) parentSAMLObject;

		Element elem = childSAMLObject.getDOM();
		if (elem.getLocalName().equals("Policy")) {
			// It's a <Policy>. Let's create a new object
			try {
				Policy p = Policy.getInstance(elem);
				xps.getPolicies().add(p);
			} catch (ParsingException e) {
				throw new UnmarshallingException("Unable to unmarshall XACML Policy", e);
			}
		} else if (elem.getLocalName().equals("PolicySet")) {
			// It's a <PolicySet>. Let's create a new object
			try {
				PolicySet p = PolicySet.getInstance(elem);
				xps.getPolicySets().add(p);
			} catch (ParsingException e) {
				throw new UnmarshallingException("Unable to unmarshall XACML Policy", e);
			}

		} else {
			// Unknown Object! 
			super.processChildElement(parentSAMLObject, childSAMLObject);
		}
	}

}
