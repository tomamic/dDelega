package it.unipr.ddelega.xacmldd.impl;

import it.unipr.ddelega.xacmldd.XacmlddStatement;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.opensaml.common.impl.AbstractSAMLObject;
import org.opensaml.xml.XMLObject;

import com.sun.xacml.AbstractPolicy;
import com.sun.xacml.Policy;
import com.sun.xacml.PolicySet;

/**
 * Concrete implementation of XACMLPolicyStatement. It uses SunXACML library to provide XACML functionality.
 *  
 * @author Thomas Florio
 */
public class XacmlddImpl extends AbstractSAMLObject implements XacmlddStatement {

	/** The list of policy inside this statement */
	private List<Policy> policies;

	/** The list of PolicySet inside this statement */
	private List<PolicySet> policySets;

	/** Base Constructor */
	protected XacmlddImpl(String namespaceURI,
			String elementLocalName, String namespacePrefix) {
		super(namespaceURI, elementLocalName, namespacePrefix);

		policies = new ArrayList<Policy>();
		policySets = new ArrayList<PolicySet>();
	}

	/** {@inheritDoc} */
	public List<Policy> getPolicies() {
		return policies;
	}

	/** {@inheritDoc} */
	public List<PolicySet> getPolicySets() {
		return policySets;
	}

	/** {@inheritDoc} */
	public List<XMLObject> getOrderedChildren() {
		return null;
	}

	/** {@inheritDoc} */
	public List<AbstractPolicy> getUniquePolicesList() {
		List<AbstractPolicy> apList = new ArrayList<AbstractPolicy>();

		apList.addAll(policies);
		apList.addAll(policySets);

		return Collections.unmodifiableList(apList);
	}

}
