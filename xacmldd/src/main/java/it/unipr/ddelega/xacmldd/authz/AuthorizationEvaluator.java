package it.unipr.ddelega.xacmldd.authz;

import it.unipr.ddelega.samldd.ValidationContext;
import it.unipr.ddelega.samldd.ValidationContextParamaters;
import it.unipr.ddelega.samldd.cond.ConditionNotValidException;
import it.unipr.ddelega.samldd.cond.ValidityCondition;
import it.unipr.ddelega.xacmldd.XacmlddHelper;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Collections;

import com.sun.xacml.PDP;
import com.sun.xacml.PDPConfig;
import com.sun.xacml.ctx.ResponseCtx;
import com.sun.xacml.ctx.Result;
import com.sun.xacml.finder.AttributeFinder;
import com.sun.xacml.finder.AttributeFinderModule;
import com.sun.xacml.finder.PolicyFinderModule;
import com.sun.xacml.finder.ResourceFinder;
import com.sun.xacml.finder.ResourceFinderModule;

import com.sun.xacml.finder.PolicyFinder;
import com.sun.xacml.finder.impl.CurrentEnvModule;

public class AuthorizationEvaluator {

	private Set<PolicyFinderModule> externalPolicyFinders;
	private List<AttributeFinderModule> externalAttrFinders;
	private List<ResourceFinderModule> externalRscFinders;

	/** Default constructor */
	public AuthorizationEvaluator() {
		externalPolicyFinders = null;
		externalAttrFinders = null;
		externalRscFinders = null;
	}

	/**
	 * Build the validator specifying additional finder modules for policy, attribute and resorces.
	 * 
	 * @param policyFinders additional policy finder modules
	 * @param attributeFinders additiona attribute finder modules
	 * @param resourceFinders additional resource finder modules
	 */
	public AuthorizationEvaluator( List<PolicyFinderModule>  policyFinders, List<AttributeFinderModule> attributeFinders, List<ResourceFinderModule> resourceFinders ) {
		externalPolicyFinders = new HashSet<PolicyFinderModule>();
		externalAttrFinders = new ArrayList<AttributeFinderModule>();
		externalRscFinders = new ArrayList<ResourceFinderModule>();

		externalPolicyFinders.addAll( policyFinders );
		externalAttrFinders.addAll( attributeFinders );
		externalRscFinders.addAll( resourceFinders );
	}

	/**
	 * Evaluate an access request against the policies in the given SPKI Authorization Certificate.
	 * 
	 * @param cert the certificate that provides the authorization policies
	 * @param request the authorization request to be evaluated
	 * @param params the validation context parameters to evaluate conditions
	 * 
	 * @return the authorization decision 
	 * 
	 * @throws ConditionNotValidException when a condition in the certificate is not valid
	 * @throws SignatureException  when the signature of the certificate is wrong
	 * @throws CertificateException when the certificate is wrong
	 * @throws InvalidKeyException when the issuer key is invalid for checking the signature
	 */
	@SuppressWarnings("unchecked")
	public List<AuthorizationResponse> evaluate( XacmlddCertificate cert,
			AuthorizationRequest request, ValidationContextParamaters params )
					throws ConditionNotValidException, InvalidKeyException,
					CertificateException, SignatureException {
		return evaluate( Collections.singletonList( cert ), request, Collections.EMPTY_SET, params );
	}

	/**
	 * Evaluate an access request against the policies collected from the given list of SPKI Authorization Certificates.
	 * 
	 * @param certs a collection of certificate that provides the authorization policies.
	 * @param request the authorization request to be evaluated.
	 * @param params the validation context parameters to evaluate conditions.
	 * 
	 * @return the authorization decision.
	 * 
	 * @throws ConditionNotValidException when a condition in the certificate is not valid
	 * @throws SignatureException  when the signature of the certificate is wrong
	 * @throws CertificateException when the certificate is wrong
	 * @throws InvalidKeyException when the issuer key is invalid for checking the signature
	 */
	@SuppressWarnings("unchecked")
	public List<AuthorizationResponse> evaluate( List<XacmlddCertificate> certs,
			AuthorizationRequest request, ValidationContextParamaters params )
					throws ConditionNotValidException, InvalidKeyException,
					CertificateException, SignatureException {
		return evaluate( certs, request, Collections.EMPTY_SET, params ) ;
	}

	/**
	 * Evaluate an access request against the policies collected from the given list of SPKI Authorization Certificates.
	 * 
	 * @param certs a collection of certificate that provides the authorization policies.
	 * @param request the authorization request to be evaluated.
	 * @param keyRing a collection of known public keys.
	 * @param params the validation context parameters to evaluate conditions.
	 * 
	 * @return the authorization decision.
	 * 
	 * @throws ConditionNotValidException when a condition in the certificate is not valid
	 * @throws SignatureException  when the signature of the certificate is wrong
	 * @throws CertificateException when the certificate is wrong
	 * @throws InvalidKeyException when the issuer key is invalid for checking the signature
	 */
	public List<AuthorizationResponse> evaluate( List<XacmlddCertificate> certs, AuthorizationRequest request,
			Collection<PublicKey> keyRing, ValidationContextParamaters params )
					throws ConditionNotValidException, InvalidKeyException,
					CertificateException, SignatureException {
		// Creates the basic policy finder module
		AuthzPolicyFinderModule finderModule = new AuthzPolicyFinderModule();

		Iterator<XacmlddCertificate> iter = certs.iterator();
		while ( iter.hasNext() ) {
			XacmlddCertificate c = (XacmlddCertificate) iter.next();
			finderModule.addAuthzPolicy( c );	
		}

		// Create the PDP
		PDP rolePDP = createPDP( finderModule );		

		// Create the validation context
		ValidationContext context = new ValidationContext();
		context.setExtraParameters( params );

		// Check the validity of all the certificates
		int certificateNumber = 0;
		iter = certs.iterator();
		while ( iter.hasNext() ) {
			XacmlddCertificate cert = iter.next();

			// Check the conditions
			List<ValidityCondition> conditions = cert.getConditions();
			context.setCurrentCertificate( cert );
			checkConditions( conditions, context );

			// Check the signature
			PublicKey issuerKey = cert.getIssuerKey();
			if ( issuerKey == null ) {
				try	{
                    issuerKey = getIssuerKeyFromKeyring( cert.getIssuer(), keyRing );
                } catch( NoSuchAlgorithmException e ) {
                    throw new CertificateException(  "Issuer public key Hashing algorithm wrong or unknown from certificate #" + certificateNumber, e  );
                }

				if ( issuerKey == null ) {
					throw new CertificateException(  "Unable to find the issuer public key of certificate #" + certificateNumber  );
				}
			}
			cert.verify( issuerKey );
		}

		// Now evaluate the request against the certificate
		ResponseCtx response = rolePDP.evaluate( request.getXACMLRequest() );

		// Convert the response format
		List<AuthorizationResponse> authzResponses = new ArrayList<AuthorizationResponse>();

		Iterator iterator= response.getResults().iterator();
		while ( iterator.hasNext() ) {
			AuthorizationResponse aRes = new AuthorizationResponse( (Result) iterator.next() );
			authzResponses.add( aRes );
		}

		return authzResponses;
	}

	/**
	 * Check the validity of all the conditions in the given list.
	 * 
	 * @param conditions the list of conditions to be checked
	 * @param context the context of the validation process
	 * @throws ConditionNotValidException when a condition is not valid
	 */
	private void checkConditions( List<ValidityCondition> conditions, ValidationContext context )
			throws ConditionNotValidException {
		Iterator<ValidityCondition> iter = conditions.iterator();
		while ( iter.hasNext() ) {
			ValidityCondition cond = iter.next();
			cond.validate( context );
		}
	}

	/** Creates the PDP adding the given policy finder and the specified extra modules
	 * 
	 * @param finderModule the role policy finder module containing the policies from the SPKI role certificate 
	 * @return the created PDP
	 */ 
	private PDP createPDP( AuthzPolicyFinderModule finderModule ) {
		// Create the set of policy finder modules
		Set<PolicyFinderModule> policyModules = new HashSet<PolicyFinderModule>();

		// Add the default module
		policyModules.add( finderModule );

		// If external modules are specified, add them all
		if ( externalPolicyFinders != null) {
			policyModules.addAll( externalPolicyFinders );
		}

		// Initiate a policy finder with all the allocated modules
		PolicyFinder polFinder = new PolicyFinder();
		polFinder.setModules(  policyModules );

		// Create the default evaluation environment for the validation
		CurrentEnvModule env = new CurrentEnvModule();

		// Create the set of attribute finder modules
		List<AttributeFinderModule> attrModules = new ArrayList<AttributeFinderModule>();

		// Add the default environment
		attrModules.add( env );

		// If external attribute modules are specified, add them
		if ( externalAttrFinders != null ) {
			attrModules.addAll( externalAttrFinders );
		}

		// Create the attribute finder
		AttributeFinder attrFinder = new AttributeFinder();
		attrFinder.setModules( attrModules );

		// Create a resource finder based on the given finder modules
		ResourceFinder resFinder;
		if ( externalRscFinders != null ) {
			// Just create a resource finder with the given modules. 
			resFinder = new ResourceFinder();
			resFinder.setModules( externalRscFinders );
		}
		else {
			resFinder = null;
		}

		// Create the PDP
		return new PDP( new PDPConfig( attrFinder, polFinder, resFinder ) );		
	}

	/** 
	 * Check if the key with the given hash is in the keyRing and returns it.
	 *   
	 * @param hash the hash of the public key.
	 * @param keyRing the collections of known keys.
	 * @return the public key if present, <code>null</code> if the key is unknown.
	 * @throws NoSuchAlgorithmException 
	 */
	private PublicKey getIssuerKeyFromKeyring( String hash, Collection<PublicKey> keyRing )
			throws NoSuchAlgorithmException {
		Iterator<PublicKey> iter = keyRing.iterator();
		while ( iter.hasNext() ) {
			PublicKey key = (PublicKey) iter.next();
			if ( hash.equals( XacmlddHelper.hashPublicKey( key, XacmlddHelper.getHashingAlgorithm( hash ) ) ) )
				return key;
		}

		return null;
	}

}
