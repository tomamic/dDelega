package it.unipr.ddelega.ddsaml.name;

import static org.junit.Assert.*;

import it.unipr.ddelega.samldd.SamlddHelper;
import it.unipr.ddelega.samldd.SamlddProvider;
import it.unipr.ddelega.samldd.name.SamlddCertPath;
import it.unipr.ddelega.samldd.name.SamlddNameCertificate;
import it.unipr.ddelega.samldd.name.PathBuilderParameters;
import it.unipr.ddelega.samldd.name.PathBuilderResult;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertPathBuilder;
import java.util.LinkedList;
import java.util.List;

import junit.framework.JUnit4TestAdapter;

import org.joda.time.DateTime;
import org.joda.time.DateTimeComparator;
import org.junit.Before;
import org.junit.Test;

public class CertPathTest {

	SamlddProvider securityProvider;

	@Before public void setUp()
	{
		SamlddHelper.init();
	}

	@Test public void testCertPath() throws Exception
	{
		// Creating the keys
		KeyPair[] keys = new KeyPair[ 4 ];
		String[] keyHashes = new String[ 4 ];
		for( int i = 0; i < 4; i++ )
		{
			keys[ i ] = KeyPairGenerator.getInstance( "RSA" ).generateKeyPair();
			keyHashes[ i ] = SamlddHelper.hashPublicKey( keys[ i ].getPublic(), "MD5" );
		}

		DateTime[] issueTime = new DateTime[ 3 ];
		issueTime[ 0 ] = new DateTime( 2006, 11, 20, 18, 0, 0, 0 );
		issueTime[ 1 ] = new DateTime( 2006, 11, 10, 12, 0, 0, 0 );
		issueTime[ 2 ] = new DateTime( 2006, 10, 31, 15, 33, 15, 0 );

		// Creting three certificates
		List<SamlddNameCertificate> certs = createCertificates( keys, keyHashes, issueTime );
		// Get the CertPathBuilder from the provider
		CertPathBuilder pb = CertPathBuilder.getInstance( "dDelega/Saml" );
		PathBuilderParameters params = new PathBuilderParameters( certs );

		// Build the certification path
		PathBuilderResult result = (PathBuilderResult) pb.build( params );
		SamlddCertPath certPath = (SamlddCertPath) result.getCertPath();

		// Extract the certificates from the certification path and verify them
		List<SamlddNameCertificate> certsFromPath = certPath.getCertificates();

		verifyCertificates( certsFromPath, keys, keyHashes, issueTime );
	}
	
	// Creates from scratch a list of certificates
	private List<SamlddNameCertificate> createCertificates( KeyPair[] keys, String[] hashes, DateTime[] issueTime )
		throws Exception
	{
		SamlddNameCertificate cert;
		List<SamlddNameCertificate> certList = new LinkedList<SamlddNameCertificate>();

		cert = new SamlddNameCertificate();
		cert.setIdentifier( SamlddHelper.getRandomIdentifier( "Test" ) );
		cert.setIssueIstant( issueTime[ 2 ] );
		cert.setIssuer( hashes[ 3 ] );
		cert.setSubject( hashes[ 2 ], "Collega" );
		cert.setStatedName( "Dipendente" );
		cert.sign( keys[ 3 ] );
		certList.add( cert );

		cert = new SamlddNameCertificate();
		cert.setIdentifier( SamlddHelper.getRandomIdentifier( "Test" ) );
		cert.setIssueIstant( issueTime[ 1 ] );
		cert.setIssuer( hashes[ 2 ] );
		cert.setSubject( hashes[ 1 ], "Ricercatore" );
		cert.setStatedName( "Collega" );
		cert.sign( keys[ 2 ] );
		certList.add( cert );

		cert = new SamlddNameCertificate();
		cert.setIdentifier( SamlddHelper.getRandomIdentifier( "Test" ) );
		cert.setIssueIstant( issueTime[ 0 ] );
		cert.setIssuer( hashes[ 1 ] );
		cert.setSubject( keys[ 0 ].getPublic() );
		cert.setStatedName( "Ricercatore" );
		cert.sign( keys[ 1 ] );
		certList.add( cert );

		return certList;
	}
	
	// Verifies that the certificate in the path equals the original one.
	private void verifyCertificates( List<SamlddNameCertificate> certsFromPath, KeyPair[] keys, String[] keyHashes,
				DateTime[] issueTime ) throws Exception
	{
		// First
		SamlddNameCertificate cert = (SamlddNameCertificate) certsFromPath.get( 2 );
		cert.verify( keys[ 1 ].getPublic() );
		assertEquals( keyHashes[ 1 ], cert.getIssuer() );
		assertTrue( DateTimeComparator.getInstance().compare( issueTime[ 0 ], cert.getIssueIstant() ) == 0 );
		assertEquals( keys[ 0 ].getPublic(), cert.getSubjectKey() );
		assertEquals( "Ricercatore", cert.getStatedName() );

		// Second
		cert = (SamlddNameCertificate) certsFromPath.get( 1 );
		cert.verify( keys[ 2 ].getPublic() );
		assertEquals( keyHashes[ 2 ], cert.getIssuer() );
		assertTrue( DateTimeComparator.getInstance().compare( issueTime[ 1 ], cert.getIssueIstant() ) == 0 );
		assertEquals( keyHashes[ 1 ], cert.getSubjectQualifier() );
		assertEquals( "Ricercatore", cert.getSubjectLocalName() );
		assertEquals( "Collega", cert.getStatedName() );

		// Third
		cert = (SamlddNameCertificate) certsFromPath.get( 0 );
		cert.verify( keys[ 3 ].getPublic() );
		assertEquals( keyHashes[ 3 ], cert.getIssuer() );
		assertTrue( DateTimeComparator.getInstance().compare( issueTime[ 2 ], cert.getIssueIstant() ) == 0 );
		assertEquals( keyHashes[ 2 ], cert.getSubjectQualifier() );
		assertEquals( "Collega", cert.getSubjectLocalName() );
		assertEquals( "Dipendente", cert.getStatedName() );
	}
	
   public static junit.framework.Test suite() {
      return new JUnit4TestAdapter( CertPathTest.class );
   }
}
