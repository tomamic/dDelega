package it.unipr.ddelega.xacmldd;

import java.security.Provider;

/**
 * The SAML SPKI security provider.
 * 
 * @author Thomas Florio
 *
 */
public final class XacmlddProvider extends Provider {

	private static final long serialVersionUID = -3956843774785372365L;

	/** Base constructor */
	public XacmlddProvider()
	{
		super( "dDelega/Xacml", 1.0, "A provider to build dDelega certificates in XACML" );
		
		put( "CertificateFactory.dDelega/Xacml", "it.unipr.ddelega.xacmldd.authz.CertificateFactory" );
		put( "CertPathBuilder.dDelega/Xacml",  "it.unipr.ddelega.xacmldd.authz.CertPathBuilder" );
		put( "CertPathValidator.dDelega/Xacml", "it.unipr.ddelega.xacmldd.authz.CertPathValidator");		
	}
}
