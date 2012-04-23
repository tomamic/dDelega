package it.unipr.ddelega.samldd.name;

import it.unipr.ddelega.samldd.SamlddCertificate;
import it.unipr.ddelega.samldd.SamlddHelper;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.Iterator;

import javax.xml.namespace.QName;

import org.w3c.dom.Element;

import org.opensaml.Configuration;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.signature.KeyInfo;
/* CODE FOR NEW OPENSAML VERSIONS
import org.opensaml.xml.signature.KeyInfoHelper;
//*/
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;

/**
 * 
 * @author Thomas Florio
 *
 */
public class SamlddNameCertificate extends SamlddCertificate {
	
	private static final long serialVersionUID = 6191029537961842490L;

	/** (Key, name) certificate type */
	public static final int KEY_NAME_CERT = 1;

	/** (Name, name) certificate type */
	public static final int NAME_NAME_CERT = 2;

	/** Certificate type not defined */
	public static final int UNDEF_CERT = 0;

	/** Can be KEY_NAME, NAME_NAME or UNDEF */
	private int certificateType;

	/* URN of the holder of key confirmation method */
	private static final String URN_HOLDER_OF_KEY = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";

	/** Base costructor. Initializes the main fields of the certificate. */
	public SamlddNameCertificate()
	{
		super( "SPKI" );
		
		// The certificate type is not defined
		certificateType = UNDEF_CERT;
	}

	/**
	 * Builds the certificate from a DOM <code>{@link org.w3c.dom.Element}</code> rapresentation.
	 * 
	 * @param elem the root element of the SAML 2.0 xml document.
	 * @throws CertificateException when the umarshalling process fails.
	 */
	public SamlddNameCertificate( Element elem ) throws CertificateException
	{
		super( "SPKI" );

		UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = factory.getUnmarshaller(new QName("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion"));

		try
		{
			assertion = (Assertion) unmarshaller.unmarshall( elem );
		}
		catch( UnmarshallingException e )
		{
			throw new CertificateException( e.getMessage(), e );
		}

		// Check the type of certificate
		Subject subject = assertion.getSubject();
		if( subject == null )
			// Subject not present: certificate still undefined
			certificateType = UNDEF_CERT;
		else
			// if the NameId element is not present...
			if( subject.getNameID() == null )
				if( subject.getSubjectConfirmations().isEmpty() )
					// also the SubjectConfirmation is empty: cert is undefined...
					certificateType = UNDEF_CERT;
				else
					// ...otherwise the cert is (key, name)
					certificateType = KEY_NAME_CERT;
			else
				// The NameId is present so...
				if( subject.getSubjectConfirmations().isEmpty() )
					// if SubjectConfirmation is empty the cert is (name, name)
					certificateType = NAME_NAME_CERT;
				else
					// ERROR: Both SubjectConfirmation and NameID are present!
					throw new CertificateException(
								"Wrong certificate type: both <NameID> and <SubjectConfirmation> present in <Subject>" );

		// Initialize the signature and the marshalling assertion
		if(!assertion.isSigned()) throw new CertificateEncodingException( "Assertion not signed" );

		marshalledAssertion = null;
	}
	
	/** 
	 * Returns the subject public key.
	 * 
	 * @return the public key of the subject enveloped int the certificate. <code>null</null> if there is no subject key in the certificate.
	 * @throws CertificateParsingException when the certificate format is wrong.
	 */
	public PublicKey getSubjectKey() throws CertificateParsingException
	{
		if( certificateType != KEY_NAME_CERT )
			// Wrong cert type or still not defined
			return null;

		Subject subject = assertion.getSubject();

		if( subject.getSubjectConfirmations().isEmpty() )
			return null;

		// Get the subjectConfirmation element and obtain from SubjectConfirmationData the key
		SubjectConfirmation subjectConfirm = subject.getSubjectConfirmations().get( 0 );

		KeyInfo keyInfo = (KeyInfo) subjectConfirm.getSubjectConfirmationData().getUnknownXMLObjects().get( 0 );

  		try {
			return KeyInfoHelper.getPublicKeys( keyInfo ).get( 0 );
		} catch( Exception e ) {
			throw new CertificateParsingException( "Unable to extract public key from KeyInfo", e ); 
		}
	}

	/**
	 * Gets the subject of the certificate when it's the hash of a public key.
	 * 
	 * @return the hash of the subject's public key
	 * 
	 * @throws CertificateParsingException when the certificate format is wrong and the hash is not correct.
	 */
	public String getSubjectKeyHash() throws CertificateParsingException
	{
		if( certificateType != KEY_NAME_CERT )
			// Wrong cert type or still not defined
			return null;

		Subject subject = assertion.getSubject();

		// If no name-id is present we directly hash the subject public key and return it
		if( subject.getNameID() == null )
		{
			PublicKey key = getSubjectKey();
			if( key == null ) throw new CertificateParsingException( "No hash and no subject public key found" );
			
			try { return SamlddHelper.hashPublicKey( key, "MD5" ); }
			catch( NoSuchAlgorithmException e ) 
			{ 
				// Should not happen but manage it anyway
				throw new CertificateParsingException( "Error creating MD5 key hash" );
			}
		}
			
			
		// Let's check if it is a valid hash
		String hash = subject.getNameID().getValue();
		if( SamlddHelper.isKeyHash( hash ) )
			return hash;
		else
			throw new CertificateParsingException( "Wrong hash format" );
	}

	/**
	 * Gets the local name of the subject.
	 * 
	 * @return the local name of the subject
	 * @throws CertificateParsingException when the certificate format is wrong.
	 * @see #getSubjectQualifier()
	 */
	public String getSubjectLocalName() throws CertificateParsingException
	{
		if( certificateType != NAME_NAME_CERT )
		// Wrong cert type or still not defined
			return null;

		Subject subject = assertion.getSubject();

		// Wrong cert format
		if( subject.getNameID() == null ) throw new CertificateParsingException( "<NameID> element not found" );

		return subject.getNameID().getValue();
	}

	/** 
	 * Gets the subject qualfier part of the subject's name.
	 * 
	 * @return the namespace qualifier of the subject
	 * @throws CertificateParsingException when the certificate format is wrong
	 * @see #getSubjectLocalName()
	 */
	public String getSubjectQualifier() throws CertificateParsingException
	{
		if( certificateType != NAME_NAME_CERT )
			// Wrong cert type or still not defined
			return null;

		Subject subject = assertion.getSubject();

		// Wrong cert format
		if( subject.getNameID() == null ) throw new CertificateParsingException( "<NameID> element not found" );

		return subject.getNameID().getNameQualifier();
	}

	/**
	 * Gets the fully qualified name of the subject. Returns a string with the namespace qualifier, a whitespace
	 * and the local name. 
	 * 
	 * @return the full name of the subject.
	 * @throws CertificateParsingException when the certificate format is wrong.
	 */
	public String getSubjectFullName() throws CertificateParsingException
	{	
		// Get the local name
		String local = getSubjectLocalName();
		// Get the namespace qualifier
		String qualifier = getSubjectQualifier();
		
		if( local != null && qualifier != null)
			return SamlddHelper.createFullyQualifiedName( qualifier, local );
		
		return null;
	}
	
	/** 
	 * Sets the subject of the certificate when it's a name. The name must be specified using the name qualfier and the local
	 * name.  
	 * 
	 * @param nameQualifier the namespaces of the name
	 * @param localName the local name.
	 */
	public void setSubject( String nameQualifier, String localName )
	{
		// Build the subject
		Subject subject = (Subject) buildSAMLObject( Subject.DEFAULT_ELEMENT_NAME );

		// Build the NameID used to store the name and the qualifier
		NameID nameId = (NameID) buildSAMLObject( NameID.DEFAULT_ELEMENT_NAME );

		// Setting up the Name ID element
		nameId.setNameQualifier( nameQualifier );
		nameId.setValue( localName );

		// Updating subject and assertion
		subject.setNameID( nameId );
		assertion.setSubject( subject );

		// Update the certificate type
		certificateType = NAME_NAME_CERT;
	}
	
	 /**
	  * Sets the subject of the certificate when it's a the hash of a public key.
	  *   
	  * @param keyHash the hash of the subject's public key.
	  */
	public void setSubject( String keyHash )
	{
		// Build the subject
		Subject subject = (Subject) buildSAMLObject( Subject.DEFAULT_ELEMENT_NAME );

		// Build the NameID used to store the name and the qualifier
		NameID nameId = (NameID) buildSAMLObject( NameID.DEFAULT_ELEMENT_NAME );

		// Setting up the Name ID element
		nameId.setValue( keyHash );

		// Updating subject and assertion
		subject.setNameID( nameId );
		assertion.setSubject( subject );

		// Update the certificate type
		certificateType = KEY_NAME_CERT;
	}

	/**
	 * Sets the subject of the certificate when it's a public key. The given key will be enveloped in the certificate.
	 * 
	 * @param subjectKey the subject's public key
	 */
	public void setSubject( PublicKey subjectKey )
	{
		// Build the subject
		Subject subject = (Subject) buildSAMLObject( Subject.DEFAULT_ELEMENT_NAME );

		// Build the SubjectConfirmation
		SubjectConfirmation subjectConfirmation = (SubjectConfirmation) buildSAMLObject( SubjectConfirmation.DEFAULT_ELEMENT_NAME );
		subjectConfirmation.setMethod( URN_HOLDER_OF_KEY );

		// Build the SubjectConfirmationData object specifying the KeyInfoConfirmationDataType
		SubjectConfirmationDataBuilder scdBuilder = (SubjectConfirmationDataBuilder) Configuration.getBuilderFactory()
					.getBuilder( SubjectConfirmationData.DEFAULT_ELEMENT_NAME );

		SubjectConfirmationData subjectConfirmationData = scdBuilder.buildObject(
					SubjectConfirmationData.DEFAULT_ELEMENT_NAME, new QName( SAMLConstants.SAML20_NS,
								"KeyInfoConfirmationDataType", SAMLConstants.SAML20_PREFIX ) );

		// Finally build the KeyInfo element to store the key
		KeyInfo keyInfo = (KeyInfo) buildSAMLObject( KeyInfo.DEFAULT_ELEMENT_NAME );

		// Let's put everything togheter

		// Add the name of the key to the list
		KeyInfoHelper.addPublicKey( keyInfo, subjectKey );
		
		// Add the keyInfo to the SubjectConfirmationData
		subjectConfirmationData.getUnknownXMLObjects().add( keyInfo );
		subjectConfirmation.setSubjectConfirmationData( subjectConfirmationData );

		// Add the subjectConfirmation to the subject list
		subject.getSubjectConfirmations().add( subjectConfirmation );

		// Finally, update subject and assertion
		assertion.setSubject( subject );

		// Update the certificate type
		certificateType = KEY_NAME_CERT;
	}

	/**
	 * Sets the local name for the subject specified in this certificate. The name is local to the namespace of the
	 * issuer.
	 * 
	 * @param name string containing the <i>local</i> name specified by this certificate.
	 */
	public void setStatedName( String name )
	{
		// Build the AttributeStatement element
		AttributeStatement attributeStatement = (AttributeStatement) buildSAMLObject( AttributeStatement.DEFAULT_ELEMENT_NAME );

		// Build the Attribute
		Attribute attribute =  (Attribute) buildSAMLObject( Attribute.DEFAULT_ELEMENT_NAME );

		// Specify the name of the attribute
		attribute.setName( "NameID" );

		// Build the AttributeValue
		XSStringBuilder xssBuilder = (XSStringBuilder) Configuration.getBuilderFactory().getBuilder( XSString.TYPE_NAME );
		XSString newName = xssBuilder.buildObject( AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME );
		newName.setValue( name );

		// Fill in
		attribute.getAttributeValues().add( newName );
		attributeStatement.getAttributes().add( attribute );

		// Clear the old statement
/* CODE FOR NEW OPENSAML VERSIONS
		// Clear the old statement
		assertion.getAttributeStatements().clear();
		// Add the new statement
		assertion.getAttributeStatements().add( attributeStatement );
/*/		
		// Clear the old statement
		assertion.getAttributeStatements().clear();
		// Add the new statement
		assertion.getAttributeStatements().add( attributeStatement );
//*/
	}

	/**
	 * Returns the <i>local</i> name for the subject stated by this certificate. The name is local to the issuer
	 * namespace.
	 * 
	 * @return the local name for the subject stated in the assertion. <code>null</code> when the cert is not
	 *         complete.
	 * 
	 * @throws CertificateParsingException when the certificate is not well formed.
	 * 
	 */
	public String getStatedName() throws CertificateParsingException
	{
		AttributeStatement attributeStatement = assertion.getAttributeStatements().get( 0 );

		// If the attribute is not present the cert is incomplete
		if( attributeStatement == null ) return null;

		// If the attribute list is empty the cert is wrong
		if( attributeStatement.getAttributes().isEmpty() )
			throw new CertificateParsingException( "<Attribute> element not found" );

		// Seek the attribute named NameID inside the Attribute list
		Iterator<Attribute> iterator = attributeStatement.getAttributes().iterator();

		Attribute attribute;
		boolean found = false;

		do
		{
			attribute = iterator.next();
			found = attribute.getName().equals( "NameID" );
		}
		while( iterator.hasNext() && !found );

		// If no attribute has name NameID the cert is wrong
		if( !found ) throw new CertificateParsingException( "NameID attribute not found" );

		// Let's read the attribute value (a simple xs:string) and return its
		// value
		XSString attributeValue = (XSString) attribute.getAttributeValues().get( 0 );

		// If no attribute value is present the cert is wrong
		if( attributeValue == null ) throw new CertificateParsingException( "NameID attribute empty" );

		// Return finally tthe attribute value
		return attributeValue.getValue();
	}
	

	/** {@inheritDoc} */
	@Override public String toString()
	{
		ByteArrayOutputStream byteArray = new ByteArrayOutputStream();
		PrintStream stream = new PrintStream( byteArray );

		stream.print( "Name SPKI Assertion ID: " + getIdentifier() );
		stream.println( " Issued on " + getIssueIstant() );

		stream.println( "  - Issuer:\t" + getIssuer() );
		stream.print( "  - Subject:\t" );

		try
		{
			if( certificateType == KEY_NAME_CERT )
			{
				stream.println( getSubjectKey().toString() );
			}
			else
				if( certificateType == NAME_NAME_CERT )
					stream.println( getSubjectQualifier() + " " + getSubjectLocalName()  );
				else
					throw new Exception();
		}
		catch( Exception e )
		{
			stream.println( "(Invalid subject)" );
		}

		stream.print( "  - Statement:\t" );
		try
		{
			stream.println( getStatedName() );
		}
		catch( Exception e )
		{
			stream.println( "(invalid statement)" );
		}

		stream.close();

		return byteArray.toString();
	}

	/**
	 * Gets the public key from this certificate.
	 * 
	 * @return the subject's public key. <code>null</code> if an error occours
	 * @see #getSubjectKey()
	 */
	@Override public PublicKey getPublicKey()
	{
		PublicKey key;

		try {	key = getSubjectKey(); }
		catch( Exception e )	{ key = null; }

		return key;
	}		
	
	/**
	 * Returns the type of certificate. It's value is one of the *_CERT constant values.
	 * 
	 * @return The certificate type
	 */
	public int getCertificateType()
	{
		return certificateType;
	}

	/** {@inheritDoc} */
	@Override public boolean isNameCertificate()
	{
		return true;
	}

	/** {@inheritDoc} */
	@Override public boolean isAuthorizationCertificate()
	{
		return false;
	}
}
