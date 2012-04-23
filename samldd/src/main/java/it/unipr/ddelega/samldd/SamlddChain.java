package it.unipr.ddelega.samldd;

import it.unipr.ddelega.samldd.name.SamlddNameCertificate;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;


public class SamlddChain {

	protected List<SamlddNameCertificate> nameCerts;
	//List<SPKIAuthzCertificate> authzCerts;
	
	/** Default constructor. */
	public SamlddChain() {
		nameCerts = new ArrayList<SamlddNameCertificate>();
		//authzCerts = new ArrayList<SPKIAuthzCertificate>();
	}
	
	/**
	 * Appends a certificate to the chain. The certificate can be a name or an authorization certficate.
	 * 
	 * @param cert the certificate to be added in the chain
	 * @return <code>true</code> if the certificate was added, <code>false</code> if the format is wrong or unknown.
	 */
	public boolean addCertificate(SamlddCertificate cert) {
		if (cert.isNameCertificate()) {
			nameCerts.add((SamlddNameCertificate) cert);
		} else if (cert.isAuthorizationCertificate()) {
				//authzCerts.add((SPKIAuthzCertificate) cert);
		} else {
			return false;
		}
		return true;
	}
	
	/**
	 * Validate a request authorization based on the policies defined in this certificate chain. First the name
	 * certificates are resolved into a role list associated to the principal in the chain. Then the request is evaluated
	 * based on the roles belonging to the principal and the policies present in the chain. 
	 * 
	 * @param keyRing
	 * @param request
	 * @throws CertPathValidatorException
	 * @throws InvalidKeyException
	 * @throws CertificateException
	 * @throws SignatureException
	 * @throws ConditionNotValidException
	 */
	/*
	public List<AuthorizationResponse> validate(List<PublicKey> keyRing, AuthorizationRequest request) throws CertPathValidatorException, InvalidKeyException, CertificateException, SignatureException, ConditionNotValidException {
		try	{
			// Create the certificate path
			CertPathBuilder pathBuilder = CertPathBuilder.getInstance("SPKI");
			PathBuilderParameters params = new PathBuilderParameters(nameCerts);
			CertPath path = pathBuilder.build(params).getCertPath();

			// Validate the certification path
			CertPathValidator validator = CertPathValidator.getInstance("SPKI");
			ValidatorParameters vParams = new ValidatorParameters(keyRing);
			KeyRoles roles = (KeyRoles) validator.validate(path, vParams);
			
			// Now evaluate the request against the known roles from the name path and the policy in the authz  certificates
			// AuthorizationEvaluator eval = new AuthorizationEvaluator(); // TODO
			// Add the validated roles 
			request.addSubject(roles, "MD5");
			return true; // eval.evaluate(authzCerts, request, keyRing, null );
		} catch(NoSuchAlgorithmException e) {
			// Should never happen
			throw new RuntimeException("FATAL: unable to find SPKI provider. Initialize the library using SPKIHelper.init() before using it", e);
		} catch(CertPathBuilderException e) {
			throw new CertificateException("Unable to build certification path", e);
		} catch(InvalidAlgorithmParameterException e) {
			// Should never happen
			throw new RuntimeException("FATAL: Unexpected Invalid algorithm exeception", e);
		}
		
	}
	*/
}
