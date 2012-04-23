package it.unipr.ddelega.ddsaml.name;

import static org.junit.Assert.*;

import it.unipr.ddelega.samldd.SamlddHelper;
import it.unipr.ddelega.samldd.cond.TimeValidityCondition;
import it.unipr.ddelega.samldd.name.SamlddNameCertificate;
import it.unipr.ddelega.samldd.name.KeyRoles;
import it.unipr.ddelega.samldd.name.PathBuilderParameters;
import it.unipr.ddelega.samldd.name.PathBuilderResult;
import it.unipr.ddelega.samldd.name.ValidatorParameters;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;

import junit.framework.JUnit4TestAdapter;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;


public class CertPathValidatorTest {

	private Collection<PublicKey> keyRing;

	@Before public void setUp() throws Exception
	{
		SamlddHelper.init();

		// Create a keyring with some random keys without the first key in the CertPath
		keyRing = new LinkedList<PublicKey>();
		keyRing.add( KeyPairGenerator.getInstance( "RSA" ).generateKeyPair().getPublic() );
		keyRing.add( KeyPairGenerator.getInstance( "RSA" ).generateKeyPair().getPublic() );
		keyRing.add( KeyPairGenerator.getInstance( "RSA" ).generateKeyPair().getPublic() );
	}
	
	// Test a correct validation
	@Test public void testValidation() throws Exception
	{
		// Load a correct certification path
		InputStream input = this.getClass().getResourceAsStream("/data/cert-path.xml");
		assertNotNull(input);

		CertificateFactory cf = CertificateFactory.getInstance( "dDelega/Saml" );
		Collection<? extends Certificate> certs = cf.generateCertificates( input );

		CertPathBuilder pb = CertPathBuilder.getInstance( "dDelega/Saml" );
		PathBuilderResult pbResult = (PathBuilderResult) pb.build( new PathBuilderParameters( certs ) );

		// Add the correct key for the first cert
		Iterator<? extends Certificate> iter = certs.iterator();
		SamlddNameCertificate c = (SamlddNameCertificate) iter.next();
		keyRing.add( c.getIssuerKey() );

		CertPathValidator cpv = CertPathValidator.getInstance("dDelega/Saml");
		KeyRoles vResult;
		vResult = (KeyRoles) cpv.validate( pbResult.getCertPath(), new ValidatorParameters(keyRing));
		
		// Check if the role list is correct
		iter = certs.iterator(); 
		while (iter.hasNext()) {
			c = (SamlddNameCertificate) iter.next();
			assertTrue(vResult.getRoleList().contains(SamlddHelper.hashPublicKey(c.getIssuerKey(), "MD5") + " " + c.getStatedName()));
		}

		assertEquals(vResult.getKey(), pbResult.getCertPath().getCertificates().get(2).getPublicKey());
	}
	
	@Test public void testWrongCondition() throws Exception
	{
		// Load a correct certification path
		InputStream input = CertificateFactoryTest.class.getResourceAsStream( "/data/cert-path.xml" );
		assertNotNull( input );
		
		CertificateFactory cf = CertificateFactory.getInstance( "dDelega/Saml" );
		Collection<? extends Certificate> certs = cf.generateCertificates( input );

		CertPathBuilder pb = CertPathBuilder.getInstance( "dDelega/Saml" );
		PathBuilderResult pbResult = (PathBuilderResult) pb.build( new PathBuilderParameters( certs ) );

		// Add the correct key for the first cert
		Iterator<? extends Certificate> iter = certs.iterator();
		SamlddNameCertificate c = (SamlddNameCertificate) iter.next();
		keyRing.add( c.getIssuerKey() );

		// Add a wrong time condition to the 2nd cert and resign the cert
		c = (SamlddNameCertificate) iter.next();
		c.addCondition( new TimeValidityCondition( new DateTime( 2100, 1, 1, 12, 00, 00, 00 ), null ) );
		KeyPair kp = KeyPairGenerator.getInstance( "RSA" ).generateKeyPair();
		c.sign( kp );
		
		CertPathValidator cpv = CertPathValidator.getInstance( "dDelega/Saml" );
		try
		{
			cpv.validate( pbResult.getCertPath(), new ValidatorParameters( keyRing ) );
			fail( "Expected exception not thrown" );
		}
		catch( CertPathValidatorException e )
		{
			// Check if the exception is correct
			assertTrue( e.getMessage().startsWith( "Condition not valid in certificate #" ) );
		}
	}
	

	// The the validator when the first key in the certificate path is unknown.
	@Test public void testUnknownKey() throws Exception
	{
		// Load a correct cert path
		InputStream input = CertificateFactoryTest.class.getResourceAsStream( "/data/cert-path.xml" );
		assertNotNull( input );

		CertificateFactory cf = CertificateFactory.getInstance( "dDelega/Saml" );
		Collection<? extends Certificate> certs = cf.generateCertificates( input );
		
		CertPathBuilder pb = CertPathBuilder.getInstance( "dDelega/Saml" );
		PathBuilderResult pbResult = (PathBuilderResult) pb.build( new PathBuilderParameters( certs ) );

		CertPathValidator cpv = CertPathValidator.getInstance( "dDelega/Saml" );
		try
		{
			cpv.validate( pbResult.getCertPath(), new ValidatorParameters( keyRing ) );
			fail( "Expected exception not thrown" );
		}
		catch( CertPathValidatorException e )
		{
			// Check if the exception is correct
			assertTrue( e.getMessage().startsWith( "Unknown public key from certificate #" ) );
		}
	}
	
	// Test the validator when the path is wrong (the names don't math between two certificates) 
	@Test public void testWrongPath() throws Exception
	{
		// Create first cert
		InputStream input = CertificateFactoryTest.class.getResourceAsStream( "/data/cert-three.xml" );
		assertNotNull( input );
		
		CertificateFactory cf = CertificateFactory.getInstance( "dDelega/Saml" );
		SamlddNameCertificate cert = (SamlddNameCertificate) cf.generateCertificate( input );
		
		PathBuilderParameters pbParams = new PathBuilderParameters();
		pbParams.addCertificate( cert );
		
		// Add the correct Key to the keyRing
		keyRing.add( cert.getIssuerKey() );
		
		// Create the second cert: a certificate is missing and the names do not match.
		input = CertificateFactoryTest.class.getResourceAsStream( "/data/cert-one.xml" );
		assertNotNull( input );
		cert = (SamlddNameCertificate) cf.generateCertificate( input );
		pbParams.addCertificate( cert );

		CertPathBuilder pb = CertPathBuilder.getInstance( "dDelega/Saml" );
		PathBuilderResult pbResult = (PathBuilderResult) pb.build( pbParams );

		CertPathValidator cpv = CertPathValidator.getInstance( "dDelega/Saml" );
		try
		{
			cpv.validate( pbResult.getCertPath(), new ValidatorParameters( keyRing ) );
			fail( "Expected exception not thrown" );
		}
		catch( CertPathValidatorException e )
		{
			assertTrue( e.getMessage().startsWith( "Wrong certificate #" ) );
		}
	}
	
	// Test the validator when the certificates are not in the correct order  
	@Test public void testMallformedPath() throws Exception
	{
		// Create first cert
		InputStream input = CertificateFactoryTest.class.getResourceAsStream( "/data/cert-one.xml" );
		assertNotNull( input );
		
		CertificateFactory cf = CertificateFactory.getInstance( "dDelega/Saml" );
		SamlddNameCertificate cert = (SamlddNameCertificate) cf.generateCertificate( input );
		
		PathBuilderParameters pbParams = new PathBuilderParameters();
		pbParams.addCertificate( cert );
		
		// Add the correct Key to the keyRing
		keyRing.add( cert.getIssuerKey() );
		
		input = CertificateFactoryTest.class.getResourceAsStream( "/data/cert-two.xml" );
		assertNotNull( input );
		cert = (SamlddNameCertificate) cf.generateCertificate( input );
		pbParams.addCertificate( cert );

		CertPathBuilder pb = CertPathBuilder.getInstance( "dDelega/Saml" );
		PathBuilderResult pbResult = (PathBuilderResult) pb.build( pbParams );

		CertPathValidator cpv = CertPathValidator.getInstance( "dDelega/Saml" );
		try
		{
			cpv.validate( pbResult.getCertPath(), new ValidatorParameters( keyRing ) );
			fail( "Expected exception not thrown" );
		}
		catch( CertPathValidatorException e )
		{
			assertEquals( "Malformed certification path", e.getMessage() );
		}
	}
	
	// Test the validator when there isn't a (Key, name) certificate in the path
	@Test public void testNoPublicKey() throws Exception
	{
		// Create first cert
		InputStream input = CertificateFactoryTest.class.getResourceAsStream( "/data/cert-three.xml" );
		assertNotNull( input );
		
		CertificateFactory cf = CertificateFactory.getInstance( "dDelega/Saml" );
		SamlddNameCertificate cert = (SamlddNameCertificate) cf.generateCertificate( input );
		
		PathBuilderParameters pbParams = new PathBuilderParameters();
		pbParams.addCertificate( cert );
		
		// Add the correct Key to the keyRing
		keyRing.add( cert.getIssuerKey() );
		
		input = CertificateFactoryTest.class.getResourceAsStream( "/data/cert-two.xml" );
		assertNotNull( input );
		cert = (SamlddNameCertificate) cf.generateCertificate( input );
		pbParams.addCertificate( cert );

		CertPathBuilder pb = CertPathBuilder.getInstance( "dDelega/Saml" );
		PathBuilderResult pbResult = (PathBuilderResult) pb.build( pbParams );

		CertPathValidator cpv = CertPathValidator.getInstance( "dDelega/Saml" );
		try
		{
			cpv.validate( pbResult.getCertPath(), new ValidatorParameters( keyRing ) );
			fail( "Expected exception not thrown" );
		}
		catch( CertPathValidatorException e )
		{
			assertEquals( "Certification path doesn't end in a public key", e.getMessage() );
		}
	}
	 
   public static junit.framework.Test suite() {
      return new JUnit4TestAdapter( CertPathValidatorTest.class );
   }
   
}
