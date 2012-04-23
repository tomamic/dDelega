package it.unipr.ddelega.samldd.name;

import java.security.cert.CertPathParameters;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;

/**
 * A specification of the parameters needed to create a certification path. 
 * These parameters are used by the <code>CertPathBuilder</code> class and
 * contain the list of certificates to be processed. 
 * 
 * @see CertPathBuilder#engineBuild(CertPathParameters)
 * @see java.security.cert.CertPathParameters
 * @see java.security.cert.CertPathBuilder#build(CertPathParameters)
 * 
 * @author Thomas Florio
 */
public class PathBuilderParameters implements CertPathParameters {

	private List<SamlddNameCertificate> certs;

	/** Default constructor. Creates an empty list. */ 
	public PathBuilderParameters() {
		certs = new ArrayList<SamlddNameCertificate>();
	}

	/**
	 * Builds the parameters frome the give list of <code>SPKINameCertificate</code>.  
	 * 
	 * @param list
	 * 			The list of certificate to build as a path.
	 */
	public PathBuilderParameters(Collection<? extends Certificate> list) {
		certs = new ArrayList<SamlddNameCertificate>();
		Iterator<? extends Certificate> iter = list.iterator(); 
		while (iter.hasNext()) {
			Certificate certificate = iter.next();
			// Check if the certificate type is correct
			if (certificate instanceof SamlddNameCertificate) {
				certs.add((SamlddNameCertificate) certificate);
			}
		}
	}

	/**
	 * Gets the list of certificates that will build the path.
	 * 
	 * @return the immutable list of certificates
	 */
	public List<SamlddNameCertificate> getCertificates() {
		return Collections.unmodifiableList(certs);
	}

	/**
	 * Clones this <code>PathBuilderParameters</code> object;
	 * 
	 *  @see java.lang.Object#clone()
	 */
	@Override
	public Object clone() {
		return new PathBuilderParameters(certs);
	}	

	/**
	 * Adds a new certificate to the list of certificates.
	 * 
	 * @param cert the new SAML SPKI certficate 
	 */
	public void addCertificate(SamlddNameCertificate cert) {
		certs.add(cert);
	}

	/**
	 * Removes a certificate from the list of certificates to be processed.
	 * 
	 * @param cert the certificate to be removed
	 * 
	 * @return <tt>true</tt> when the given certificate was present in the list.
	 */
	public boolean removeCertificate(SamlddNameCertificate cert) {
		return certs.remove(cert);
	}
}
