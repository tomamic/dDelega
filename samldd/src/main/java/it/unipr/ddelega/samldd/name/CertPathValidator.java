package it.unipr.ddelega.samldd.name;

import it.unipr.ddelega.samldd.SamlddHelper;
import it.unipr.ddelega.samldd.ValidationContext;
import it.unipr.ddelega.samldd.cond.ConditionNotValidException;
import it.unipr.ddelega.samldd.cond.ValidityCondition;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;


/**
 * Validates a certification path. Checks if the path of certificates ends into a public key and so the local names
 * correctly identifies a key. 
 * 
 * @author Thomas Florio
 */
public class CertPathValidator extends CertPathValidatorSpi {

	/** Default constructor */
	public CertPathValidator() {}

	/**
	 * Validates the given certification path with the specified parameters.
	 * 
	 * @param certPath the certification path to validate
	 * @param params the parameters needed for the validation
	 * 
	 * @return the result of the validation process as a <code>ValidatorResult</code>
	 * 
	 * @throws CertPathValidatorException when the validation fails
	 * @throws InvalidAlgorithmParameters when the arguments are not correct or the certificate type is not supported
	 */
	@Override public CertPathValidatorResult engineValidate( CertPath certPath, CertPathParameters params )
		throws CertPathValidatorException, InvalidAlgorithmParameterException
	{
		// First check if the parameters and the path are from SAMLSPKI
		if( !certPath.getType().equals( "dDelega/Saml" ) )
			throw new InvalidAlgorithmParameterException( certPath.getType() + " certificates not supported" );

		if( !( params instanceof ValidatorParameters ) )
			throw new InvalidAlgorithmParameterException( "Parameters not instance of ValidatorParameters" );

		// Convert the certPath
		SamlddCertPath samlCertPath = (SamlddCertPath) certPath;
		// Get the keyRing from the paramaters
		ValidatorParameters vParam = (ValidatorParameters) params;
		Collection<PublicKey> keyRing = vParam.getKeyRing();
		// Iterator over the path
		Iterator<SamlddNameCertificate> iterator = samlCertPath.getCertificates().iterator();
		int certificateNumber = 0;

		/*
		 * These strings contains the subject (name & qualifier) of the previous certificate of the path. These fields
		 * are needed to check the chain.
		 */
		String oldSubjectName = null;
		String oldSubjectQualifier = null;

		// The public key the certification path refers to
		PublicKey certPathKey = null;
		// Memorize all the roles (names) associated to this public key
		List<String> roles = new ArrayList<String>();
		
		// Create the validation context.
		ValidationContext context = new ValidationContext();
		// Set the context parameters
		context.setExtraParameters( vParam.getValidationContextParameters() );
		
		try
		{
			while( iterator.hasNext() )
			{
				SamlddNameCertificate cert = (SamlddNameCertificate) iterator.next();
				
				// Update the validation context
				// context.setCurrentCertificate( cert ); // TODO
				
				PublicKey issuerKey = cert.getIssuerKey();
				if( issuerKey == null )
				{
					// The issuer key is not in the certificate. check if its on the keyRing
					issuerKey = getIssuerKeyFromKeyring( cert.getIssuer(), keyRing );
					if( issuerKey == null )
						throw new CertPathValidatorException( "Unable to find issuer public key in certificate #" +certificateNumber + ": unknown key or wrong hash" );
				}

				// If it is the first element check if I know the key
				if( oldSubjectName == null && !keyRing.contains( issuerKey ) )
					throw new CertPathValidatorException( "Unknown public key from certificate #" + certificateNumber );

				// Verifiy this certificate with the issuer public key
				cert.verify( issuerKey );
				// Check if all the conditions are valid
				checkConditions( cert.getConditions(), context );
				
				/* If it's not the last certificate the path is wrong; the (key, name) certificate can't be in the
				 * middle of the path
				 */
				if( cert.getCertificateType() == SamlddNameCertificate.KEY_NAME_CERT && iterator.hasNext() )
					throw new CertPathValidatorException( "Malformed certification path" );
				
				// If it's the last certificate of the path, the path is wrong because it must end with a public key
				if( cert.getCertificateType() == SamlddNameCertificate.NAME_NAME_CERT && !iterator.hasNext() )
					throw new CertPathValidatorException( "Certification path doesn't end in a public key" );
				
				// Unknown certificate type: wrong!			
				if( cert.getCertificateType() == SamlddNameCertificate.UNDEF_CERT )
					throw new CertPathValidatorException( "Undefined certificate #" + certificateNumber );

				// If it's not the first of the path
				if( oldSubjectName != null )
				{
					// Find out the algorithm used for the key hashing
					String algo = SamlddHelper.getHashingAlgorithm( oldSubjectQualifier );
					// Compute the key hash
					String hash = SamlddHelper.hashPublicKey( issuerKey, algo );
					
					/* if the subject name in previous certificate is different from the name stated in this
					 * certificate or the qualifier of the previous certificate doesn't corrispond to the issuer key
					 * of this certificate, the cert path is not valid. 
					 */
					if( !oldSubjectName.equals( cert.getStatedName() )
								|| !oldSubjectQualifier.equals( hash ) )
						throw new CertPathValidatorException( "Wrong certificate #" + certificateNumber );
				}
				
				// Here the certificate is valid: update the references and go evaluate the next cert.
				oldSubjectName = cert.getSubjectLocalName();
				oldSubjectQualifier = cert.getSubjectQualifier();
			
				// Add the fully qualified name to the role list
				roles.add( SamlddHelper.createFullyQualifiedName( SamlddHelper.hashPublicKey( issuerKey, vParam.getHashAlgorithm() ), cert.getStatedName() ) );
				
				// If it's the last certificate
				if( !iterator.hasNext() )
					// Save the suject key
					certPathKey = cert.getPublicKey();
				
				certificateNumber++;
			}
		}
		// Catch all exception and rethrow them
		catch( InvalidKeyException e )
		{
			throw new CertPathValidatorException( "Invalid key in certificate #" + certificateNumber, e );
		}
		catch( CertificateParsingException e )
		{
			throw new CertPathValidatorException( "Error parsing Certificate #" + certificateNumber, e );
		}
		catch( CertificateException e )
		{
			throw new CertPathValidatorException( "Error in certificate #" + certificateNumber, e );
		}
		catch( SignatureException e )
		{
			throw new CertPathValidatorException( "Signature not valid in certifcate #" + certificateNumber, e );
		}
		catch( NoSuchAlgorithmException e )
		{
			throw new CertPathValidatorException( "Unknown hashing algoritm in certificate #" + certificateNumber, e );
		}
		catch( ConditionNotValidException e )
		{
			throw new CertPathValidatorException( "Condition not valid in certificate #" + certificateNumber, e );
		}

		KeyRoles result = new KeyRoles( certPathKey, roles );
		return result;
	}

	/** 
	 * Check if the key with the given hash is in the keyRing and returns it.
	 *   
	 * @param hash the hash of the public key.
	 * @param keyRing the collections of known keys.
	 * @return the public key if present, <code>null</code> if the key is unknown.
	 * @throws NoSuchAlgorithmException 
	 */
	private PublicKey getIssuerKeyFromKeyring( String hash, Collection<PublicKey> keyRing ) throws NoSuchAlgorithmException
	{
		Iterator<PublicKey> iter = keyRing.iterator();
		while( iter.hasNext() )
		{
			PublicKey key = (PublicKey) iter.next();
			if( hash.equals( SamlddHelper.hashPublicKey( key, SamlddHelper.getHashingAlgorithm( hash ) ) ) )
				return key;
		}
		
		return null;
	}

	/**
	 * Check the validity of all the conditions in the given list.
	 * 
	 * @param conditions the list of conditions to be checked
	 * @param context the context of the validation process
	 * @throws ConditionNotValidException when a condition is not valid
	 */
	private void checkConditions( List<ValidityCondition> conditions, ValidationContext context ) throws ConditionNotValidException
	{
		Iterator<ValidityCondition> iter = conditions.iterator();
		while( iter.hasNext() )
		{
			ValidityCondition cond = iter.next();
			cond.validate( context );
		}
	}

}
