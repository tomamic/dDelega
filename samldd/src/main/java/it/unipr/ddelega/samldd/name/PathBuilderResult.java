package it.unipr.ddelega.samldd.name;

import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderResult;


/**
 * A specification of the result of the SAMLSPKI certificate builder algorithm. 
 * It contains the newly created certification path rapresented by the 
 * <code>CertPath</code> object.
 * 
 * @see CertPathBuilder#engineBuild(java.security.cert.CertPathParameters)
 * @see SamlddCertPath
 * 
 * @see java.security.cert.CertPathBuilderResult
 * @see java.security.cert.CertPathBuilder#build(java.security.cert.CertPathParameters)
 * @see java.security.cert.CertPath
 * 
 * @author Thomas Florio
 */
public class PathBuilderResult implements CertPathBuilderResult {

	private SamlddCertPath certificationPath;

	/** Builds an empty result. */
	public PathBuilderResult() {
		certificationPath = new SamlddCertPath();
	}

	/** Builds a CertPathBuilder result from the given CertPath. */
	public PathBuilderResult(SamlddCertPath certPath) {
		certificationPath = certPath;
	}

	/**
	 * {@inheritDoc}
	 */
	public CertPath getCertPath() {
		return certificationPath;
	}

	/**
	 * Creates a copy of this <code>PathBuilderResult</code> instance. 
	 */
	@Override
	public Object clone() {
		return new PathBuilderResult( (SamlddCertPath) certificationPath.clone() );
	}

}
