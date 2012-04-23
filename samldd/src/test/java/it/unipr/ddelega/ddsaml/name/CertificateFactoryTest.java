package it.unipr.ddelega.ddsaml.name;

import static org.junit.Assert.*;

import it.unipr.ddelega.samldd.SamlddHelper;
import it.unipr.ddelega.samldd.SamlddProvider;
import it.unipr.ddelega.samldd.name.SamlddNameCertificate;

import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Iterator;

import junit.framework.JUnit4TestAdapter;

import org.junit.Before;
import org.junit.Test;

public class CertificateFactoryTest {

	CertificateFactory factory;
	SamlddProvider securityProvider;

	@Before
	public void setUp() throws Exception {	
		SamlddHelper.init();

		// Create the certificate factory
		factory = CertificateFactory.getInstance("dDelega/Saml");	
	}

	// Test a single unmarshalling from an xml file
	@Test
	public void testUnmarshalling() throws Exception {
		// First Certificate
		InputStream input = CertificateFactoryTest.class.getResourceAsStream("/data/name-name.xml");
		assertNotNull(input);

		// Create the first certificate unmarshalling the input
		SamlddNameCertificate cert = (SamlddNameCertificate) factory.generateCertificate(input);

		// Check the values
		assertEquals(SamlddNameCertificate.NAME_NAME_CERT, cert.getCertificateType());
		assertEquals("OPENSAML-ID-_cb2b74dc598d4f6dfc12008836bc88b6", cert.getIdentifier());
		assertEquals("2006-08-13T12:06:14.796Z", cert.getIssueIstant().toString());
		assertEquals("DoG's Key", cert.getIssuer());
		assertEquals("mackdk", cert.getSubjectQualifier());
		assertEquals("r3vind", cert.getSubjectLocalName());
		assertEquals("Massimo", cert.getStatedName());
		cert.verify(cert.getIssuerKey());

		// Second certificate
		input = CertificateFactoryTest.class.getResourceAsStream("/data/key-name.xml");	
		assertNotNull(input);

		// Create the second certificate unmarshalling the input
		cert = (SamlddNameCertificate) factory.generateCertificate(input);

		// Check the values
		assertEquals(SamlddNameCertificate.KEY_NAME_CERT, cert.getCertificateType());
		assertEquals("OPENSAML-ID-_324ab6eeb993e28e42ac664ae651c17b", cert.getIdentifier());
		assertEquals("2006-08-13T12:06:15.578Z", cert.getIssueIstant().toString());
		assertEquals("DoG's Key", cert.getIssuer());
		assertNotNull(cert.getSubjectKey());
		assertEquals("Massimo", cert.getStatedName());
		cert.verify(cert.getIssuerKey());
	}

	// Test multiple certificate unmarshalling of more xml files merged into one
	@Test
	public void testMultipleUnmarshalling() throws Exception {
		// First Certificate
		InputStream input = CertificateFactoryTest.class.getResourceAsStream("/data/cert-collection.xml");
		assertNotNull(input);

		Collection<? extends Certificate> certList = factory.generateCertificates(input);

		assertEquals(2, certList.size());

		Iterator<? extends Certificate> iterator = certList.iterator();
		SamlddNameCertificate cert = (SamlddNameCertificate) iterator.next();
		assertEquals(SamlddNameCertificate.KEY_NAME_CERT, cert.getCertificateType());
		assertEquals("OPENSAML-ID-_324ab6eeb993e28e42ac664ae651c17b", cert.getIdentifier());
		assertEquals("2006-08-13T12:06:15.578Z", cert.getIssueIstant().toString());
		assertEquals("DoG's Key", cert.getIssuer());
		assertNotNull(cert.getSubjectKey());
		assertEquals("Massimo", cert.getStatedName());
		cert.verify(cert.getIssuerKey());

		cert = (SamlddNameCertificate) iterator.next();
		assertEquals(SamlddNameCertificate.NAME_NAME_CERT, cert.getCertificateType());
		assertEquals("OPENSAML-ID-_cb2b74dc598d4f6dfc12008836bc88b6", cert.getIdentifier());
		assertEquals("2006-08-13T12:06:14.796Z", cert.getIssueIstant().toString());
		assertEquals("DoG's Key", cert.getIssuer());
		assertEquals("mackdk", cert.getSubjectQualifier());
		assertEquals("r3vind", cert.getSubjectLocalName());
		assertEquals("Massimo", cert.getStatedName());
		cert.verify(cert.getIssuerKey());		
	}

	public static junit.framework.Test suite() {
		return new JUnit4TestAdapter(CertificateFactoryTest.class);
	}
}
