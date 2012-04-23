package it.unipr.ddelega.xacmldd;

import it.unipr.ddelega.xacmldd.authz.SimpleAuthorizationPolicy;
import it.unipr.ddelega.xacmldd.authz.XacmlddCertificate;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.List;

import junit.framework.JUnit4TestAdapter;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

import com.sun.xacml.Policy;
import com.sun.xacml.Rule;
import com.sun.xacml.TargetMatch;
import com.sun.xacml.TargetMatchGroup;
import com.sun.xacml.attr.StringAttribute;
import com.sun.xacml.cond.MatchFunction;

public class AuthorizationCertificateTest {

	private XacmlddCertificate cert;
	private KeyPair keys;

	@Before
	public void setUp() throws Exception {
		// Initialize the library
		XacmlddHelper.init();

		cert = new XacmlddCertificate();
		keys = KeyPairGenerator.getInstance("RSA").generateKeyPair();

		// NOTE: Test for generic methods from SPKICertificate are already done in NameCertificateTest

		// Set up basic fielids
		cert.setIdentifier(XacmlddHelper.getRandomIdentifier("RoleTest"));
		cert.setIssuer(XacmlddHelper.hashPublicKey(keys.getPublic(), "MD5"));
	}

	@Test
	public void testAddRolePolicy() throws Exception {
		SimpleAuthorizationPolicy rolePolicy = new SimpleAuthorizationPolicy();

		PublicKey subjectKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
		rolePolicy.addSubject(XacmlddHelper.hashPublicKey(subjectKey, "MD5"));
		rolePolicy.addResource("LPR1");
		rolePolicy.addAction("Print");
		rolePolicy.setEffect(SimpleAuthorizationPolicy.EFFECT_PERMIT);

		cert.addPolicy(rolePolicy);

		List<Policy> policies = cert.getXACMLPolicies();

		assertEquals(1, policies.size());
		Policy pol = policies.get(0);

		// Get the Targets and check their values
		TargetMatchGroup subjectGroup = (TargetMatchGroup) pol.getTarget().getSubjectsSection().getMatchGroups().get(0);
		List subjectList = SimpleAuthorizationPolicy.getMatches(subjectGroup);
		TargetMatch sbj = (TargetMatch) subjectList.get(0);
		
		TargetMatchGroup actionGroup = (TargetMatchGroup) pol.getTarget().getActionsSection().getMatchGroups().get(0);
		List actionList = SimpleAuthorizationPolicy.getMatches(actionGroup);
		TargetMatch act = (TargetMatch) actionList.get(0);

		TargetMatchGroup resourceGroup = (TargetMatchGroup) pol.getTarget().getResourcesSection().getMatchGroups().get(0);
		List resourceList = SimpleAuthorizationPolicy.getMatches(resourceGroup);
		TargetMatch rsc = (TargetMatch) resourceList.get(0);

		assertEquals(XacmlddHelper.hashPublicKey(subjectKey, "MD5"),  ((StringAttribute) sbj.getMatchValue()).getValue());
		assertEquals( "LPR1",  ((StringAttribute) rsc.getMatchValue()).getValue());
		assertEquals("Print",  ((StringAttribute) act.getMatchValue()).getValue());

		List rules = pol.getChildren();
		assertEquals(1, rules.size());
		Rule rule = (Rule) rules.get(0);
		assertEquals(SimpleAuthorizationPolicy.EFFECT_PERMIT, rule.getEffect());

		// Finally test the getRolePolicies() method
		assertEquals(1, cert.getXACMLPolicies().size());
		assertEquals(pol, cert.getXACMLPolicies().get(0));
	}

	@Test
	public void testDelegation() {
		assertTrue(cert.allowDelegation());
		assertTrue(cert.delegation());
		assertEquals(XacmlddCertificate.DELEGATION_TRUSTED, cert.delegationTrustLevel());

		cert.denyDelegation();
		cert.delegation();
		assertFalse("Delegation not denied", cert.delegation());
		assertEquals(-1, cert.delegationTrustLevel());

		assertTrue(cert.allowDelegation(XacmlddCertificate.DELEGATION_UNTRUSTED));
		assertTrue("Delegation not allowed", cert.delegation());
		assertEquals(XacmlddCertificate.DELEGATION_UNTRUSTED, cert.delegationTrustLevel());

		assertTrue(cert.allowDelegation(26));
		assertTrue("Delegation not allowed", cert.delegation());
		assertEquals(26, cert.delegationTrustLevel());

		assertFalse(cert.allowDelegation(139));
		assertTrue("Delegation not allowed", cert.delegation());
		assertEquals(26, cert.delegationTrustLevel());

		cert.denyDelegation();
		assertFalse("Delegation not denied", cert.delegation());

		assertFalse(cert.allowDelegation(-347));
		assertFalse("Delegation not denied", cert.delegation());
		assertEquals(-1, cert.delegationTrustLevel());

	}

	@Test
	public void testMarshallingNormal() throws Exception {
		SimpleAuthorizationPolicy rolePolicy = new SimpleAuthorizationPolicy();

		rolePolicy.addSubject(XacmlddHelper.hashPublicKey(keys.getPublic(), "MD5"), "colleghi");
		rolePolicy.addResource("/home/mackdk/Documenti/lavoro/*", MatchFunction.NAME_REGEXP_STRING_MATCH);
		rolePolicy.addAction("Read");
		rolePolicy.addAction("Write");
		rolePolicy.setEffect(SimpleAuthorizationPolicy.EFFECT_PERMIT, "Permette la lettura e la scrittura da parte dei miei colleghi nella cartella lavoro");

		cert.addPolicy(rolePolicy);
		// Delego i mei colleghi
		cert.allowDelegation();

		// Sign & encode
		cert.sign(keys);
		cert.getEncoded();
	}

	@Test
	public void testMarshallingThreshold() throws Exception {
		ThresholdSubject threshold = new ThresholdSubject();

		threshold.setThresholdType(ThresholdSubject.N_OVER_N);
		threshold.addSubject( XacmlddHelper.hashPublicKey(KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic(), "MD5"));
		threshold.addSubject(XacmlddHelper.hashPublicKey(keys.getPublic(), "MD5"), "amici");

		SimpleAuthorizationPolicy rolePolicy = new SimpleAuthorizationPolicy();

		rolePolicy.addSubject(threshold);
		rolePolicy.addResource("/home/mackdk/Documenti/Musica/*.m4a", MatchFunction.NAME_REGEXP_STRING_MATCH);
		rolePolicy.addResource("/home/mackdk/Documenti/Musica/*.mp3", MatchFunction.NAME_REGEXP_STRING_MATCH);
		rolePolicy.addResource("/home/mackdk/Documenti/Musica/*.ogg", MatchFunction.NAME_REGEXP_STRING_MATCH);
		rolePolicy.addAction("Download");
		rolePolicy.setEffect(SimpleAuthorizationPolicy.EFFECT_PERMIT);

		cert.addPolicy(rolePolicy);
		cert.allowDelegation(75);

		// Sign & encode
		cert.sign(keys);
		cert.getEncoded();
	}

	public static junit.framework.Test suite() {
		return new JUnit4TestAdapter(AuthorizationCertificateTest.class);
	}
}
