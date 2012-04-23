package it.unipr.ddelega.ddsaml.name;

import static org.junit.Assert.*;

import it.unipr.ddelega.samldd.SamlddHelper;
import it.unipr.ddelega.samldd.name.SamlddNameCertificate;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;

import junit.framework.JUnit4TestAdapter;

import org.junit.Before;
import org.junit.Test;

public class NameCertificateTest {

	private SamlddNameCertificate cert;
	private KeyPair keys;

	@Before public void setUp() throws Exception
	{
		SamlddHelper.init();
		
		cert = new SamlddNameCertificate();
		keys = KeyPairGenerator.getInstance( "RSA" ).generateKeyPair();
	}

	@Test public void testIdentifier()
	{
		cert.setIdentifier( "SAML-ID-0" );
		assertEquals( "SAML-ID-0", cert.getIdentifier() );

		cert.setIdentifier( null );
		assertNull( "Identifer do not reset correctly", cert.getIdentifier() );
		
		cert.setIdentifier(  SamlddHelper.getRandomIdentifier() );
		assertNotNull( cert.getIdentifier() );

		cert.setIdentifier( SamlddHelper.getRandomIdentifier( "Test" ) );
		String result = cert.getIdentifier();
		assertTrue( result != null & result.matches( "Test-.*" ) );
	}

	@Test public void testIssueIstant()
	{
		org.joda.time.DateTime date = new org.joda.time.DateTime( System.currentTimeMillis() );
		cert.setIssueIstant( date );
		int result = org.joda.time.DateTimeComparator.getInstance().compare( date, cert.getIssueIstant() ); 
		assertTrue( result == 0 );
	}
	
	@Test public void testIssuer()
	{
		cert.setIssuer( "EXAMPLE:Tester1" );
		assertEquals( "EXAMPLE:Tester1", cert.getIssuer() );
		
		cert.setIssuer( "EXAMPLE:Tester2" );
		assertEquals( "EXAMPLE:Tester2", cert.getIssuer() );
	}

	@Test public void testSubjectName() throws CertificateParsingException
	{
		// Test subject with separated local and qualifier
		cert.setSubject( "jessKeyHash", "mack" );		
		assertEquals( "jessKeyHash", cert.getSubjectQualifier() );
		assertEquals( "mack", cert.getSubjectLocalName() );		
		assertEquals( "jessKeyHash mack", cert.getSubjectFullName() );
	}
	
	@Test public void testSubjectKey() throws Exception
	{
		cert.setSubject( keys.getPublic() );
		assertEquals( keys.getPublic(), cert.getSubjectKey() );
		assertEquals( SamlddHelper.hashPublicKey( keys.getPublic(), "MD5" ), cert.getSubjectKeyHash() );
	}
	
	@Test public void testSubjectComplete() throws Exception
	{
		assertEquals( SamlddNameCertificate.UNDEF_CERT, cert.getCertificateType() );
		
		cert.setSubject( "mackKeyHask", "nick" );
		assertNull( cert.getSubjectKey() );
		assertEquals( SamlddNameCertificate.NAME_NAME_CERT, cert.getCertificateType() );
		
		cert.setSubject( keys.getPublic() );
		assertNull( cert.getSubjectLocalName() );
		assertNull( cert.getSubjectQualifier() );
		assertNull( cert.getSubjectFullName() );
		assertEquals( SamlddNameCertificate.KEY_NAME_CERT, cert.getCertificateType() );
		
		cert.setSubject( SamlddHelper.hashPublicKey( keys.getPublic(), "MD5" ) );
		assertNull( cert.getSubjectKey() );
		assertEquals( SamlddHelper.hashPublicKey( keys.getPublic(), "MD5" ), cert.getSubjectKeyHash() );
		assertEquals( SamlddNameCertificate.KEY_NAME_CERT, cert.getCertificateType() );
	}
	
	 @Test public void testStatedName() throws Exception
	 {
		 cert.setStatedName( "nick" );
		 assertEquals( "nick", cert.getStatedName() );
	 }
	 
	 @Test public void testMarshalling() throws Exception
	 {
		 // Initialize the cert
		 cert.setIdentifier( SamlddHelper.getRandomIdentifier( "TEST" ) );
		 cert.setIssueIstant( new org.joda.time.DateTime( System.currentTimeMillis() ) );
		 cert.setIssuer( "mackKeyHash" );
		 cert.setSubject( "jessKeyHash", "Nick" );

		 // Certificate is not signed: must generate an exception
		 try {
			 cert.getEncoded();
			 fail( "No excepected exception given" );
		 }
		 catch( CertificateEncodingException e )
		 {
			 assertEquals( "Assertion not signed", e.getMessage() );
		 }
	
		 // Now sign the cert and test the correct marshalling
		 cert.sign( keys );
		 String first = new String( cert.getEncoded() );
		 // Encode again to check the remarshalling problem
		 String second = new String( cert.getEncoded() );
		 
		 assertEquals( first, second );
	 }
		
	 @Test public void testSigning() throws Exception
	 {
		 // Initialize the cert
		 cert.setIdentifier( SamlddHelper.getRandomIdentifier( "TEST" ) );
		 cert.setIssueIstant( new org.joda.time.DateTime( System.currentTimeMillis() ) );
		 cert.setIssuer( "HASH:mackKeyHash" );
		 cert.setSubject( "HASH:jessKeyHash", "Nick" );

		 // Sign and check the signature
		 cert.sign( keys );
		 java.security.PublicKey keyFromCert = cert.getIssuerKey();
		 assertNotNull( keyFromCert );
		 cert.verify( keyFromCert );		 
	 }	 
	 
	 @Test public void testMultipleSigning() throws Exception
	 {
		 // Initialize the cert
		 cert.setIdentifier( SamlddHelper.getRandomIdentifier( "TEST" ) );
		 cert.setIssueIstant( new org.joda.time.DateTime( System.currentTimeMillis() ) );
		 cert.setIssuer( "HASH:mackKeyHash" );
		 cert.setSubject( "HASHjessKeyHash", "Nick" );
 
		 // Sign and check the signature
		 cert.sign( keys );
		 java.security.PublicKey keyFromCert = cert.getIssuerKey();
		 assertNotNull( keyFromCert );
		 cert.verify( keyFromCert );
		 
		 // Sign it again with another pair of keys
		 java.security.KeyPair newKeys = KeyPairGenerator.getInstance( "RSA" ).generateKeyPair();
		 cert.sign( newKeys );
		 keyFromCert =  cert.getIssuerKey();
		 assertNotNull( keyFromCert );
		 cert.verify( keyFromCert );
	 }
	 
    public static junit.framework.Test suite() {
       return new JUnit4TestAdapter( NameCertificateTest.class );
    }
}
