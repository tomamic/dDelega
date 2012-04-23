package it.unipr.ddelega.xacmldd.impl;

import it.unipr.ddelega.xacmldd.XacmlddConstants;
import it.unipr.ddelega.xacmldd.XacmlddStatement;

import org.opensaml.common.impl.AbstractSAMLObjectBuilder;

/**
 * Default builder for {@link org.opensaml.samlext.xacml.XACMLPolicyStatement} objects.
 */
public class XacmlddBuilder extends AbstractSAMLObjectBuilder<XacmlddStatement> {

	/** Default constructor */
	public XacmlddBuilder() {
	}

	/** {@inheritDoc} */
	@Override
	public XacmlddStatement buildObject() {
		return buildObject(XacmlddConstants.XACML_SAML_NS,
				XacmlddStatement.DEFAULT_ELEMENT_LOCAL_NAME, XacmlddConstants.XACML_SAML_PREFIX);
	}

	/** {@inheritDoc} */
	@Override
	public XacmlddStatement buildObject(String namespaceURI,
			String localName, String namespacePrefix) {
		return new XacmlddImpl(namespaceURI, localName, namespacePrefix);
	}

}
