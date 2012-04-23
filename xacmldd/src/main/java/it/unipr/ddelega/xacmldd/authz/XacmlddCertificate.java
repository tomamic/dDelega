package it.unipr.ddelega.xacmldd.authz;

import it.unipr.ddelega.samldd.SamlddCertificate;
import it.unipr.ddelega.xacmldd.XacmlddStatement;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.QName;

import com.sun.xacml.Policy;
import com.sun.xacml.Rule;
import com.sun.xacml.TargetMatch;
import com.sun.xacml.TargetMatchGroup;
import com.sun.xacml.TargetSection;
import com.sun.xacml.ctx.Result;

import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;

import org.w3c.dom.Element;

/**
 * 
 * @author Thomas Florio
 * 
 */
public class XacmlddCertificate extends SamlddCertificate {

	private static final long serialVersionUID = -2829170382858693087L;

	public static int DELEGATION_TRUSTED = 100;

	public static int DELEGATION_UNTRUSTED = 0;

	/** Default constructor */
	public XacmlddCertificate() {
		super("dDelega/Xacml");

		// Initialize the XACMLPolicyStatement and add it to the assertion
		XacmlddStatement policyStatement = (XacmlddStatement) buildSAMLObject(XacmlddStatement.DEFAULT_ELEMENT_NAME);
		assert(policyStatement != null);
		assertion.getStatements().add(policyStatement);
	}

	/**
	 * Builds the certificate from a DOM <code>{@link org.w3c.dom.Element}</code> rapresentation.
	 * 
	 * @param elem the root element of the SAML 2.0 xml document.
	 * @throws CertificateException when the umarshalling process fails.
	 */
	public XacmlddCertificate(Element elem) throws CertificateException {
		super("dDelega/Xacml");

		UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = factory.getUnmarshaller(elem);

		// Try to unmarshall the element
		try {
			assertion = (Assertion) unmarshaller.unmarshall(elem);
		} catch(UnmarshallingException e) {
			throw new CertificateException(e.getMessage(), e);
		}
	}

	/**
	 * Adds an authorization policy to this certificate.
	 * 
	 * @param rolePolicy the policy to be added
	 */
	public void addPolicy(AuthorizationPolicy policy) {
		// Get the first XACMLPolicyStatment from the list of statements
		XacmlddStatement pStatement = (XacmlddStatement) assertion.getStatements(
				XacmlddStatement.DEFAULT_ELEMENT_NAME).get(0);
		// Add the policy
		pStatement.getPolicies().add(policy.getXACMLPolicy());
	}

	/**
	 * Allow the subjects of the certificate to delegate given permissions.
	 * 
	 * @return <code>true</code> if the delegation status is changed, <code>false</code> if an error occours.
	 */
	public boolean allowDelegation() {
		return allowDelegation(-1);
	}

	/**
	 * Allow the subjects of the certificate to delegate given permissions specifying the level delegation.
	 * 
	 * @param level % level of trust (from 0 to 100)
	 * @return <code>true</code> if the delegation status is changed, <code>false</code> if an error occours.
	 */
	public boolean allowDelegation(int level) {
		// If the trust level is wrong leave it unmodified
		if (level > DELEGATION_TRUSTED || (level < DELEGATION_UNTRUSTED && level != -1)) {
			return false;
		}

		// Build the AttributeStatement element
		AttributeStatement attributeStatement = (AttributeStatement) buildSAMLObject(AttributeStatement.DEFAULT_ELEMENT_NAME);

		// Build the Attribute
		Attribute attribute = (Attribute) buildSAMLObject(Attribute.DEFAULT_ELEMENT_NAME);

		// Specify the name of the attribute
		attribute.setName("Delegate");
		// Add the trust attribute
		if (level != -1) {
			attribute.getUnknownAttributes().put(new QName("trust"), new Integer(level).toString());
		}

		// Add to the attribute statement
		attributeStatement.getAttributes().add(attribute);
		
		// Clear the old statement
		assertion.getAttributeStatements().clear();
		// Add the new statement
		assertion.getAttributeStatements().add(attributeStatement);

		return true;
	}

	/**
	 * Prevent the subject from granting to others the permissions stated in this certificate.
	 */
	public void denyDelegation() {
		// Remove the attribute statements
		assertion.getAttributeStatements().clear();
		// Hack to fix a list not cleared bug
		if (assertion.getAttributeStatements().size() != 0) {
			assertion.getAttributeStatements().clear();
			if (assertion.getAttributeStatements().size() != 0) {
				throw new RuntimeException(
						"Irrational Error!!!!! Unable to clear the list. After clear() size is still not 0!!!!!");
			}
		}
	}

	/**
	 * Gets the delegation status.
	 * 
	 * @return <code>true</code> if the subject can grant the given permission to others, <code>false</code>
	 *         otherwise.
	 */
	public boolean delegation() {
		return !assertion.getAttributeStatements().isEmpty();
	}

	/**
	 * Gets the level of trust of the subject when delegating permissions.
	 * 
	 * @return the % level of trust (from 0 to 100). <b>-1</b> if delegation is not allowed.
	 */
	public int delegationTrustLevel() {
		if (delegation()) {
			Attribute attr = assertion.getAttributeStatements().get(0).getAttributes().get(0);
			if (!attr.getName().equals("Delegate")) {
				return -1;
			}
			String strValue = attr.getUnknownAttributes().get(new QName("trust"));
			if (strValue == null) {
				return DELEGATION_TRUSTED;
			} else {
				return new Integer(strValue).intValue();
			}
		}
		return -1;
	}

	/**
	 * Gets the XACML rapresentation of all the policicy contained in this certificate.
	 * 
	 * @return a list of XACML Policy objects.
	 * @see Policy
	 */
	public List<Policy> getXACMLPolicies() {
		// Get the first XACMLPolicyStatment from the list of statemets
		XacmlddStatement pStatement = (XacmlddStatement) assertion.getStatements(
				XacmlddStatement.DEFAULT_ELEMENT_NAME).get(0);

		return Collections.unmodifiableList(pStatement.getPolicies());
	}

	/**
	 * Returns a printable string rapresentation of this certificate.
	 * 
	 * @return the string rapresentation of the object.
	 */
	@Override public String toString() {
		ByteArrayOutputStream byteArray = new ByteArrayOutputStream();
		PrintStream stream = new PrintStream(byteArray);

		stream.print("Role SPKI Assertion ID: " + getIdentifier());
		stream.println(" Issued on " + getIssueIstant());

		stream.println("  - Issuer:\t" + getIssuer());

		// Get the first XACMLPolicyStatment from the list of statemets
		XacmlddStatement pStatement = (XacmlddStatement) assertion.getStatements(
				XacmlddStatement.DEFAULT_ELEMENT_NAME).get(0);

		// Print out all the policies
		Iterator<Policy> iter = pStatement.getPolicies().iterator();
		while (iter.hasNext()) {
			printPolicy(stream, iter.next());
		}

		stream.close();

		return byteArray.toString();
	}

	/** {@inheritDoc} */
	@Override
	public boolean isNameCertificate() {
		return false;
	}

	/** {@inheritDoc} */
	@Override
	public boolean isAuthorizationCertificate() {
		return true;
	}

	/**
	 * Returns always <code>null</code> since no subject public key are available in authorization certificates.
	 * 
	 * @return always <code>null</code>.
	 */
	@Override
	public PublicKey getPublicKey() {
		return null;
	}

	/** 
	 * Print a string rapresentation of XACML policy in the give stream.
	 * @param stream the print stream
	 * @param policy the policy to be printed
	 */
	private void printPolicy(PrintStream stream, Policy policy) {
		stream.println("Policy: " + policy.getId().toString());

		if (policy.getTarget() != null) {
			// Print Subjects...
			printTarget(stream, policy.getTarget().getSubjectsSection(), "Subject");
			// ...resources...
			printTarget(stream, policy.getTarget().getResourcesSection(), "Resource");
			// ...and actions.
			printTarget(stream, policy.getTarget().getActionsSection(), "Action");
		}

		// If there is a rule, print the effect
		if (policy.getChildren() != null) {
			Rule rule = (Rule) policy.getChildren().get(0);
			if (rule.getDescription() != null) {
				stream.println("Rule: " + rule.getDescription());
			}

			if (rule.getEffect() == Result.DECISION_PERMIT) {
				stream.println("Effect: Deny");
			} else {
				stream.print("Effect: Allow");
			}
		}
	}

	/**
	 * Print one of the target type (Actions, Subjects or Resources) in the given stream
	 * 
	 * @param stream the output print stream
	 * @param target the list of target to be printed
	 * @param type the name of the element to be printed (Action, Subject or Resource). It's used as a title.
	 */
	private void printTarget(PrintStream stream, TargetSection target, String type) {
		if (!target.matchesAny()) {
			// Print the main element name (actions, resources or subjects)
			stream.println(type + "s");
			Iterator iter = target.getMatchGroups().iterator();
			for (int i = 1; iter.hasNext(); i++) {
				// Print the parent elem (action, resource or subject)
				stream.println("   " + type + " " + new Integer(i).toString() + "");
				TargetMatchGroup subject = (TargetMatchGroup) iter.next();

				// Print all the TargetMatch
				/*
				Iterator matchIterator = subject.getTargetMatches().iterator();
				while (matchIterator.hasNext()) {
					TargetMatch elem = (TargetMatch) iter.next();
					stream.println("      Match: " + elem.getMatchValue());
				}
				 */
			}
		} else {
			stream.println("All possibible" + type + "s");
		}
	}

}
