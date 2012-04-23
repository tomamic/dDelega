package it.unipr.ddelega.samldd;

import java.security.Provider;

/**
 * The SAML dDelega security provider.
 * 
 * @author Thomas Florio
 *
 */
public final class SamlddProvider extends Provider {

	private static final long serialVersionUID = -3956843774785372365L;

	/** Base constructor */
	public SamlddProvider() {
		super("dDelega", 1.0, "A provider to build dDelega certificate in SAML");
		
		put("CertificateFactory.dDelega/Saml", "it.unipr.ddelega.samldd.name.CertificateFactory");
		put("CertPathBuilder.dDelega/Saml",  "it.unipr.ddelega.samldd.name.CertPathBuilder");
		put("CertPathValidator.dDelega/Saml", "it.unipr.ddelega.samldd.name.CertPathValidator");
		
		//put("CertificateFactory.dDelega/ddXacml", "it.unipr.ddelega.ddxacml.CertificateFactory");
		//put("CertPathBuilder.dDelega/ddXacml",  "it.unipr.ddelega.ddxacml.CertPathBuilder");
		//put("CertPathValidator.dDelega/ddXacml", "it.unipr.ddelega.ddxacml.CertPathValidator");
	}
}
