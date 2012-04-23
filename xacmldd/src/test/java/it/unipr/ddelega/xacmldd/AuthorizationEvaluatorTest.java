package it.unipr.ddelega.xacmldd;

import it.unipr.ddelega.xacmldd.authz.AuthorizationEvaluator;
import it.unipr.ddelega.xacmldd.authz.AuthorizationResponse;
import it.unipr.ddelega.xacmldd.authz.SimpleAuthorizationPolicy;
import it.unipr.ddelega.xacmldd.authz.SimpleAuthorizationRequest;
import it.unipr.ddelega.xacmldd.authz.XacmlddCertificate;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.List;

import junit.framework.JUnit4TestAdapter;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

import com.sun.xacml.ctx.Result;
import com.sun.xacml.cond.MatchFunction;

public class AuthorizationEvaluatorTest {

	KeyPair keys;

	@Before
	public void setUp() throws Exception {
		// Initialize the library
		XacmlddHelper.init();

		keys = KeyPairGenerator.getInstance("RSA").generateKeyPair();
	}

	@Test
	public void testSimpleHashValidation() throws Exception {
		SimpleAuthorizationPolicy rp = new SimpleAuthorizationPolicy();

		rp.addSubject("HASH:exampleofkeyhash");
		rp.addAction("Read");
		rp.addAction("Write");
		rp.addResource("/home/darkman/*", MatchFunction.NAME_REGEXP_STRING_MATCH);
		rp.setEffect(SimpleAuthorizationPolicy.EFFECT_PERMIT);

		// Build the auth certificate
		XacmlddCertificate cert = new XacmlddCertificate();
		cert.setIdentifier(XacmlddHelper.getRandomIdentifier("RoleValidatorTest"));
		cert.setIssuer(XacmlddHelper.hashPublicKey(keys.getPublic(), "MD5"));
		cert.addPolicy(rp);
		cert.sign(keys);

		System.out.println();

		// Build the request
		SimpleAuthorizationRequest request = new SimpleAuthorizationRequest("HASH:exampleofkeyhash", "/home/darkman/tesi.odt",  "Read", null);

		AuthorizationEvaluator rcv = new AuthorizationEvaluator();

		List<AuthorizationResponse> response = rcv.evaluate(cert, request, null);
		assertEquals(1, response.size());
		assertEquals(AuthorizationResponse.DECISION_PERMIT, response.get(0).getDecision());
	}

	@Test
	public void testSimpleNameValidation() throws Exception {
		SimpleAuthorizationPolicy rp = new SimpleAuthorizationPolicy();

		rp.addSubject(XacmlddHelper.createFullyQualifiedName(XacmlddHelper.hashPublicKey(keys.getPublic(), "MD5"), "amici"));
		rp.addAction("Read");
		rp.addResource("/home/darkman/*", MatchFunction.NAME_REGEXP_STRING_MATCH);
		rp.setEffect(SimpleAuthorizationPolicy.EFFECT_PERMIT);

		// Build the auth certificate
		XacmlddCertificate cert = new XacmlddCertificate();
		cert.setIdentifier(XacmlddHelper.getRandomIdentifier("AuthzValidatorTest"));
		cert.setIssuer(XacmlddHelper.hashPublicKey(keys.getPublic(), "MD5"));
		cert.addPolicy(rp);
		cert.sign(keys);

		// Build the request
		SimpleAuthorizationRequest request = new SimpleAuthorizationRequest();

		request.addSubject( "HASH:exampleofkeyhash");
		request.addSubject(XacmlddHelper.hashPublicKey(keys.getPublic(), "MD5"), "amici");
		request.addResource("/home/darkman/tesi.odt");
		request.addAction("Read");

		AuthorizationEvaluator rcv = new AuthorizationEvaluator();

		List<AuthorizationResponse> response = rcv.evaluate(cert, request, null);

		assertEquals(1, response.size());
		assertEquals(Result.DECISION_PERMIT, response.get(0).getDecision());
	}	

	@Test
	public void testSimpleThresholdValidation() throws Exception {
		SimpleAuthorizationPolicy rp = new SimpleAuthorizationPolicy();
		ThresholdSubject th = new ThresholdSubject();

		th.addSubject("HASH:firstpublickeyhash", "writers");
		th.addSubject("HASH:secondpublickeyhash", "readers");
		th.setThresholdType(ThresholdSubject.ONE_OVER_N);

		rp.addSubject(th);
		rp.addResource("/home/darkman/confidentials/*", MatchFunction.NAME_REGEXP_STRING_MATCH);
		rp.addAction("Edit");
		rp.setEffect(SimpleAuthorizationPolicy.EFFECT_PERMIT);

		// Build the auth certificate
		XacmlddCertificate cert = new XacmlddCertificate();
		cert.setIdentifier(XacmlddHelper.getRandomIdentifier("AuthzValidatorTest"));
		cert.setIssuer(XacmlddHelper.hashPublicKey(keys.getPublic(), "MD5"));
		cert.addPolicy(rp);
		cert.sign(keys);

		SimpleAuthorizationRequest request = new SimpleAuthorizationRequest();

		// Build the request	
		request.addSubject("HASH:secondpublickeyhash",  "readers");
		request.addSubject("HASH:firstpublickeyhash",  "writers");
		request.addResource("/home/darkman/confidentials/secrets.odt");
		request.addAction("Edit");

		AuthorizationEvaluator rcv = new AuthorizationEvaluator();

		List<AuthorizationResponse> response = rcv.evaluate(cert, request, null);

		assertEquals(1, response.size());
		assertEquals(Result.DECISION_PERMIT, response.get(0).getDecision());
	}

	@Test
	public void testSimpleDenyRolePolicy() throws Exception {
		SimpleAuthorizationPolicy rp = new SimpleAuthorizationPolicy();

		rp.addSubject("HASH:exampleofkeyhash");
		rp.addAction("Read");
		rp.addResource("/home/darkman/.+\\.odt", MatchFunction.NAME_REGEXP_STRING_MATCH);
		rp.setEffect(SimpleAuthorizationPolicy.EFFECT_PERMIT, "Allow my boss to read my documents");

		SimpleAuthorizationPolicy rp2 = new SimpleAuthorizationPolicy();
		rp2.addSubject(XacmlddHelper.createFullyQualifiedName(XacmlddHelper.hashPublicKey(keys.getPublic(), "MD5"), "colleghi"));
		rp2.addResource(".+\\.m4a", MatchFunction.NAME_REGEXP_STRING_MATCH);
		rp2.setEffect(SimpleAuthorizationPolicy.EFFECT_DENY, "Deny my collegues to do anything with my music" );

		// Build the role certificate
		XacmlddCertificate cert = new XacmlddCertificate();
		cert.setIdentifier(XacmlddHelper.getRandomIdentifier("RoleValidatorTest"));
		cert.setIssuer(XacmlddHelper.hashPublicKey(keys.getPublic(), "MD5"));
		cert.addPolicy(rp);
		cert.addPolicy(rp2);
		cert.sign(keys);

		// Build the request from a coleague to dowload my music
		SimpleAuthorizationRequest request1 = new SimpleAuthorizationRequest(XacmlddHelper.createFullyQualifiedName(XacmlddHelper.hashPublicKey(keys.getPublic(), "MD5"), "colleghi"), "/home/darkman/atmosferico.m4a", "Download", null);
		SimpleAuthorizationRequest request2 = new SimpleAuthorizationRequest("HASH:exampleofkeyhash", "/home/darkman/lavoro/documentazione.odt", "Read", null);


		AuthorizationEvaluator rcv = new AuthorizationEvaluator();

		List<AuthorizationResponse> response = rcv.evaluate(cert, request1, null);

		assertEquals(1, response.size());
		assertEquals(Result.DECISION_DENY, response.get(0).getDecision());

		response = rcv.evaluate(cert, request2, null);

		assertEquals(1, response.size());
		assertEquals(Result.DECISION_PERMIT, response.get(0).getDecision());
	}

	public static junit.framework.Test suite() {
		return new JUnit4TestAdapter(AuthorizationEvaluatorTest.class);
	}	
}
