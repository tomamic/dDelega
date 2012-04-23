package it.unipr.ddelega.xacmldd.authz;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.sun.xacml.AbstractPolicy;
import com.sun.xacml.EvaluationCtx;
import com.sun.xacml.MatchResult;
import com.sun.xacml.Policy;
import com.sun.xacml.PolicySet;
import com.sun.xacml.ctx.Status;
import com.sun.xacml.finder.PolicyFinder;
import com.sun.xacml.finder.PolicyFinderModule;
import com.sun.xacml.finder.PolicyFinderResult;

public class AuthzPolicyFinderModule extends PolicyFinderModule {

	/** All the Policy and PolicySet known by this module */
	private List<AbstractPolicy> modulePolicies;

	@SuppressWarnings("unused")
	private PolicyFinder finder;

	/**
	 * Constructor which retrieves the schema file to validate policies against from the POLICY_SCHEMA_PROPERTY. If the
	 * retrieved property is null, then no schema validation will occur.
	 */
	public AuthzPolicyFinderModule() {
		modulePolicies = new ArrayList<AbstractPolicy>();
	}

	/**
	 * Constructor that specifies a set of initial policy to use. No schema validation is performed.
	 * 
	 * @param policiesList a list of Policy and PolicySet.
	 */
	public AuthzPolicyFinderModule(List<? extends AbstractPolicy> policiesList) {
		this();

		if (policiesList != null) {
			modulePolicies.addAll(policiesList);
		}
	}

	/**
	 * Indicates whether this module supports finding policies based on a request (target matching). Since this module
	 * does support finding policies based on requests, it returns true.
	 * 
	 * @return true, since finding policies based on requests is supported
	 */
	@Override
	public boolean isRequestSupported() {
		return true;
	}

	/**
	 * Initializes the <code>RolePolicyFinder</code> by loading the policies contained in the collection associated
	 * with this module. This method also uses the specified <code>PolicyFinder</code> to help in instantiating
	 * PolicySets.
	 * 
	 * @param policyFinder a PolicyFinder used to help in instantiating PolicySets
	 */
	@Override
	public void init(PolicyFinder policyFinder) {
		finder = policyFinder;
	}

	/**
	 * Adds all the policy contained in the given SPKI role certificate.
	 * 
	 * @param cert the role certificate containing the policies to add.
	 * @return <code>true</code> if the policy was added, <code>false</code> otherwise
	 */
	public boolean addAuthzPolicy(XacmlddCertificate cert) {
		if (cert != null) {
			return modulePolicies.addAll(cert.getXACMLPolicies());
		}
		return false;

	}

	/**
	 * Adds an XACML Policy to this finder module.
	 * 
	 * @param policy the policy to be added to the module.
	 * @return <code>true</code> if the policy was added, <code>false</code> otherwise
	 */
	public boolean addPolicy(Policy policy) {
		if (policy != null) {
			return modulePolicies.add(policy);
		}
		return false;
	}

	/**
	 * Adds a XACML PolicySet to this finder module.
	 * 
	 * @param policySet the PolicySet to be added to the module.
	 * @return <code>true</code> if the policy was added, <code>false</code> otherwise
	 */
	public boolean addPolicySet(PolicySet policySet) {
		if (policySet != null) {
			return modulePolicies.add(policySet);
		}
		return true;
	}

	/**
	 * Adds all the XACML Policy and PolicySet objects in the give list to this finder module.
	 * 
	 * @param policies a list of policies to be added to the module.
	 * @return <code>true</code> if the policies were added, <code>false</code> otherwise
	 */
	public boolean addPolicies(List<? extends AbstractPolicy> policies) {
		if (policies != null) {
			return modulePolicies.addAll(policies);
		}
		return false;
	}

	/**
	 * Finds a policy based on a request's context. This may involve using the request data as indexing data to lookup a
	 * policy. This will always do a Target match to make sure that the given policy applies. If more than one
	 * applicable policy is found, this will return an error. NOTE: this is basically just a subset of the
	 * OnlyOneApplicable Policy Combining Alg that skips the evaluation step. See comments in there for details on this
	 * algorithm.
	 * 
	 * @param context the representation of the request data
	 * 
	 * @return the result of trying to find an applicable policy
	 */
	@Override
	public PolicyFinderResult findPolicy(EvaluationCtx context) {
		AbstractPolicy selectedPolicy = null;
		Iterator it = modulePolicies.iterator();

		while (it.hasNext()) {
			AbstractPolicy policy = (AbstractPolicy) it.next();

			// see if we match
			MatchResult match = policy.match(context);
			int result = match.getResult();

			// if there was an error, we stop right away
			if (result == MatchResult.INDETERMINATE) {
				return new PolicyFinderResult(match.getStatus());
			}

			if (result == MatchResult.MATCH) {
				// if we matched before, this is an error...
				if (selectedPolicy != null) {
					List<String> code = new ArrayList<String>();
					code.add(Status.STATUS_PROCESSING_ERROR);
					Status status = new Status(code, "too many applicable top-level policies");
					return new PolicyFinderResult(status);
				}

				// ...otherwise remember this policy
				selectedPolicy = policy;
			}
		}

		// if we found a policy, return it, otherwise we're N/A
		if (selectedPolicy != null) {
			return new PolicyFinderResult(selectedPolicy);
		}
		return new PolicyFinderResult();
	}

}
