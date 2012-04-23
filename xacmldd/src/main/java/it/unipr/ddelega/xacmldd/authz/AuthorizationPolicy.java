package it.unipr.ddelega.xacmldd.authz;

import com.sun.xacml.Policy;


public interface AuthorizationPolicy {
	
	/**
	 * Returns the XACML rapresentation of this role policy.
	 * 
	 * @return the SunXACML Policy object rapresenting this policy.
	 * @see Policy
	 */	
	public Policy getXACMLPolicy();

}
