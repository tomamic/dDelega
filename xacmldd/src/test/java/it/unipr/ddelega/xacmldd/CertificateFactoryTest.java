package it.unipr.ddelega.xacmldd;

import static org.junit.Assert.*;

import it.unipr.ddelega.xacmldd.authz.SimpleAuthorizationPolicy;
import it.unipr.ddelega.xacmldd.authz.XacmlddCertificate;

import java.io.InputStream;
import java.security.cert.CertificateFactory;

import junit.framework.JUnit4TestAdapter;

import org.junit.Before;
import org.junit.Test;


public class CertificateFactoryTest {

	CertificateFactory factory;

	@Before
public void setUp() throws Exception {
		// Initialize
		XacmlddHelper.init();

		// Create the certificate factory
		factory = CertificateFactory.getInstance("dDelega/Xacml");
	}

	@Test
public void testSingleMarshalling() throws Exception {
		// First certificate
		InputStream input = CertificateFactoryTest.class.getResourceAsStream("/data/it/unipr/ddelega/xacmldd/cert-one.xml");	
		assertNotNull(input);

		// Create the first certificate unmarshalling the input
		XacmlddCertificate cert = (XacmlddCertificate) factory.generateCertificate(input);

		// Check everything	
		assertEquals("MD5:K3yoOJGi/BtjD4zkOzd5GA==", cert.getIssuer());
		assertNotNull(cert.getIssuerKey());
		assertEquals("MD5:K3yoOJGi/BtjD4zkOzd5GA==", XacmlddHelper.hashPublicKey(cert.getIssuerKey(), "MD5" ));
		// Role policy
		assertTrue("Wrong role policies in marshalled certificate", cert.getXACMLPolicies().size() == 1 );
		SimpleAuthorizationPolicy rp = new SimpleAuthorizationPolicy(cert.getXACMLPolicies().get(0));
		// Subjects
		assertTrue("Wrong threshold subjects in marshalled role policy", rp.getThresholdSubjects().size() == 0);
		assertTrue("Wrong subjects in marshalled role policy", rp.getSubjects().size() == 1);
		assertEquals(XacmlddHelper.createFullyQualifiedName("MD5:K3yoOJGi/BtjD4zkOzd5GA==", "colleghi"), rp.getSubjects().get(0));
		// Resources
		assertTrue("Wrong resources in marshalled role policy", rp.getResources().size() == 1);
		assertEquals("/home/mackdk/Documenti/lavoro/*", rp.getResources().get(0));
		// Actions
		assertTrue("Wrong actions in marshalled role policy", rp.getActions().size() == 2);
		assertEquals("Read", rp.getActions().get(0));
		assertEquals("Write", rp.getActions().get(1));
		// Rule
		assertTrue("Wrong rule effect in marshalled role policy", rp.getEffect() == SimpleAuthorizationPolicy.EFFECT_PERMIT);
		// Delegation
		assertTrue(cert.delegation());
		assertEquals(XacmlddCertificate.DELEGATION_TRUSTED, cert.delegationTrustLevel());
		
		// Second certificate
		input = CertificateFactoryTest.class.getResourceAsStream("/data/it/unipr/ddelega/xacmldd/cert-two.xml");	
		assertNotNull(input);

		// Create the first certificate unmarshalling the input
		cert = (XacmlddCertificate) factory.generateCertificate(input);

		// Check everything	
		assertEquals("MD5:8jkUkNKKLQfw/iTX9TgtTg==", cert.getIssuer());
		assertNotNull(cert.getIssuerKey());
		assertEquals("MD5:8jkUkNKKLQfw/iTX9TgtTg==", XacmlddHelper.hashPublicKey(cert.getIssuerKey(), "MD5" ));
		// Role policy
		assertTrue("Wrong role policies in marshalled certificate", cert.getXACMLPolicies().size() == 1 );
		rp = new SimpleAuthorizationPolicy(cert.getXACMLPolicies().get(0));
		// Subjects
		assertTrue("Wrong subjects in marshalled role policy", rp.getSubjects().size() == 0 );
		assertTrue("Wrong threshold subjects in marshalled role policy", rp.getThresholdSubjects().size() == 1);
		ThresholdSubject th = new ThresholdSubject(ThresholdSubject.N_OVER_N);
		th.addSubject("MD5:Yy+Zo6q4OUCdjgxq5bQCAQ==");
		th.addSubject("MD5:8jkUkNKKLQfw/iTX9TgtTg==", "amici");
		assertEquals(th, rp.getThresholdSubjects().get(0));
		
		// Resources
		assertTrue("Wrong resources in marshalled role policy", rp.getResources().size() == 3);
		assertEquals("/home/mackdk/Documenti/Musica/*.m4a", rp.getResources().get(0));
		assertEquals("/home/mackdk/Documenti/Musica/*.mp3", rp.getResources().get(1));
		assertEquals("/home/mackdk/Documenti/Musica/*.ogg", rp.getResources().get(2));
		// Actions
		assertTrue("Wrong actions in marshalled role policy", rp.getActions().size() == 1);
		assertEquals("Download", rp.getActions().get(0));
		// Rule
		assertTrue("Wrong rule effect in marshalled role policy", rp.getEffect() == SimpleAuthorizationPolicy.EFFECT_PERMIT);
		// Delegation
		assertTrue(cert.delegation());
		assertEquals(75, cert.delegationTrustLevel());		
	}
	
   public static junit.framework.Test suite() {
      return new JUnit4TestAdapter(CertificateFactoryTest.class);
   }
}
