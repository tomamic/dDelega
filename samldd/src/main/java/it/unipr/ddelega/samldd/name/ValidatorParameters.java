package it.unipr.ddelega.samldd.name;

import it.unipr.ddelega.samldd.ValidationContextParamaters;

import java.security.PublicKey;
import java.security.cert.CertPathParameters;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
/**
 * A specification of the parameters needed during the certificate path 
 * validation process. The parameters are:
 * <p>
 * <ul>
 * <li>the list of the "known" key (aka key ring).</li>
 * <li>the algorithm type used to hash the public keys.</li>
 * </ul>
 * <p>Note that the hashing algorithm is only used when building the list of roles (names)
 * associated to the certificate path (if this path is correct).
 *  
 * @author Thomas Florio
 *
 */
public class ValidatorParameters implements CertPathParameters {
	
	private Collection<PublicKey> keyRing;
	private String hashAlgorithm;
	private ValidationContextParamaters context;
	
	
	/** 
	 * Construct a validator parameter from the map view of the keyring.
	 *
	 * @param keys the keyring containing the known keys.
	 */
	public ValidatorParameters( Collection<PublicKey> keys )
	{
		keyRing = new ArrayList<PublicKey>();
		keyRing.addAll( keys );
		hashAlgorithm = "MD5";
		context = null;
	}
	
	/**
	 * Construct a validator parameter object from its components.
	 * 
	 * @param keys the keyring containing the known keys.
	 * @param algo the hasing algorithm used to hash the public keys.
	 * @param params the validation context parameters.
	 */
	public ValidatorParameters( Collection<PublicKey> keys, String algo, ValidationContextParamaters params )
	{
		keyRing = new ArrayList<PublicKey>();
		keyRing.addAll( keys );
		hashAlgorithm = new String( algo );
		
		if( params != null )
			context = params.clone();
		else
			context = null;
	}
	
	/**
	 * Clone this <code>ValidatorParameters</code> object.
	 * 
	 * @return a copy of this object.
	 */
	@Override public Object clone()
	{
		return new ValidatorParameters( keyRing, hashAlgorithm, context ); 
	}

	/**
	 * Returns the keyRing associated to this parameter set.
	 * 
	 * @return the keys needed to validate the SPKICertPath
	 */
	public Collection<PublicKey> getKeyRing()
	{
		return Collections.unmodifiableCollection( keyRing );
	}

	/**
	 * Gets the current message digest algorithm used to compute key hashes in the roles list.
	 * 
	 * @return the current hash algorithm.
	 */
	public String getHashAlgorithm()
	{
		return hashAlgorithm;
	}

	/**
	 * Sets the algorithm used to compute the message digests of public keys. These hashes are used when
	 * creating the roles list to rapresent public keys.
	 *  
	 * @param hAlgo the new hashing algorithm to be used
	 */
	public void setHashAlgorithm( String hAlgo )
	{
		hashAlgorithm = hAlgo;
	}
	
	public void setValidationContextParameters( ValidationContextParamaters cInfo )
	{
		context = cInfo;
	}
	
	public ValidationContextParamaters getValidationContextParameters()
	{
		return context;
	}
	
}
