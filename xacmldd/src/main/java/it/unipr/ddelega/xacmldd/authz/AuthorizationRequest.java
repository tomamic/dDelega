package it.unipr.ddelega.xacmldd.authz;

import it.unipr.ddelega.samldd.name.KeyRoles;

import java.security.NoSuchAlgorithmException;

import com.sun.xacml.ctx.RequestCtx;


public interface AuthorizationRequest {

	/**
	 * Converts the authorization request into an <i>immutable</i> XACML request context.
	 *  
	 * @return the XACML request context equivalent to this request.
	 */
	public RequestCtx getXACMLRequest();

	/**
	 * Adds all the roles belonging to a principal as the subject of this request.
	 * 
	 * @param roles the roles belonging to a public key.
	 * @param algo the algoithm used to compute the key hash.
	 * @throws NoSuchAlgorithmException when the hashing algorithm is wrong or unknown.
	 */
	public void addSubject( KeyRoles roles, String string ) throws NoSuchAlgorithmException;
	
}
