package it.unipr.ddelega.samldd.name;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorResult;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

/**
 * A rapresentation of all the roles that belog to a specific public key. It's also a specification of the result of the certificate path validation process. 
 * This class contains the list of names/roles associated to the public key of validated certificate path.
 * 
 * @author Thomas Florio
 *
 */
public class KeyRoles implements CertPathValidatorResult {

	/** The publick key that the validated certification path refers to */
	private PublicKey publicKey;
	/** All the roles that belongs to the public key */
	private List<String> roleList;
	
	/** Initialize this <code>ValidatorResult</code> */
	public KeyRoles( PublicKey key, List<String> otherList )
	{
		// Try to clone the key	
		try
		{
			String format = key.getFormat();
			EncodedKeySpec keySpec;		
			
			if( format.equals( "PKCS#8" ) )
				 keySpec = new PKCS8EncodedKeySpec( key.getEncoded()  );
			else
				if( format.equals( "X.509" ) )
					keySpec = new X509EncodedKeySpec( key.getEncoded() );
				else
					// Unknown key encoding format
					throw new Exception();

			// Generate a new public key with the spec of the given one
			publicKey = KeyFactory.getInstance( key.getAlgorithm() ).generatePublic( keySpec );
		}
		catch( Exception e )
		{
			// Just copy the key
			publicKey = key;
		}
		
		roleList = new ArrayList<String>();
		roleList.addAll( otherList );
	}

	/**
	 * Gets the role list associated to the certificate path validated.
	 * 
	 * @return the roles (or names) list. The names are fully qualified.
	 */
	public List<String> getRoleList()
	{
		return roleList;
	}
	
	/**
	 * Gets the public key this object refers to.
	 * 
	 * @return the public key of the holder of the roles.
	 */
	public PublicKey getKey()
	{
		return publicKey;
	}
	
	/**
	 * Clone this result.
	 * 
	 * @return a copy of this <code>ValidatorResult</code> object.
	 */
	@Override public Object clone()
	{
		return new KeyRoles( publicKey, roleList );
	}

}
