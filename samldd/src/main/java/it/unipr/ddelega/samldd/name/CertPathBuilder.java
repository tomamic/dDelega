package it.unipr.ddelega.samldd.name;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertPathParameters;


/**
 * Create certification paths from a list of certificates.
 * 
 * @author Thomas Florio
 */
public class CertPathBuilder extends CertPathBuilderSpi {

	/** Base constructor */
	public CertPathBuilder() {
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public CertPathBuilderResult engineBuild(CertPathParameters params)
			throws CertPathBuilderException,
			InvalidAlgorithmParameterException {
		// Check if the parameters are correct
		if( !( params instanceof PathBuilderParameters ) )
			throw new InvalidAlgorithmParameterException(
					"Paramaters not instance of PathBuilderParameters" );

		SamlddCertPath certPath = new SamlddCertPath(
				((PathBuilderParameters) params).getCertificates());

		return new PathBuilderResult(certPath);
	}
}
