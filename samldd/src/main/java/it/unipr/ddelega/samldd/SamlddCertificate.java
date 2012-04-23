package it.unipr.ddelega.samldd;

import it.unipr.ddelega.samldd.cond.ConditionManager;
import it.unipr.ddelega.samldd.cond.ValidityCondition;

import java.io.ByteArrayOutputStream;

import java.util.Collections;
import java.util.List;

import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;

import javax.xml.namespace.QName;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.opensaml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.signature.KeyInfo;

import org.opensaml.xml.signature.Signature;
/* CODE FOR NEW OPENSAML VERSIONS
import org.opensaml.xml.security.InlineX509KeyInfoResolver;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.WrapperKeyInfoSource;
import org.opensaml.xml.signature.BasicX509SignatureTrustEngine;
import org.opensaml.xml.signature.KeyInfoHelper;
/*/ 
import org.opensaml.xml.signature.SignatureValidator;
//*/ 
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.ValidatorSuite;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;

/**
 * 
 * @author Thomas Florio
 *
 */
public abstract class SamlddCertificate extends Certificate {

	/** The SAML assertion object that rapresent the certificate */
	protected Assertion assertion;

	/** The marshalled form of the assertion */
	protected Element marshalledAssertion;

	/**
	 * Initialize the certificate. The issue istant of the certificate is automatically initialized
	 * to the current time.
	 * 
	 * @param cert_type the name of the certificate type.
	 * 
	 */
	protected SamlddCertificate(String cert_type) {
		super(cert_type);

		assertion = (Assertion) buildSAMLObject(Assertion.DEFAULT_ELEMENT_NAME);

		// Set up the SAML Version
		assertion.setVersion(org.opensaml.common.SAMLVersion.VERSION_20);
		// Set the issue istant to now
		assertion.setIssueInstant(new DateTime(DateTimeUtils.currentTimeMillis()));

		marshalledAssertion = null;	}

	/**
	 * Sets the unique identifier of the certificate. The probability of having two identical identifier
	 * <b>must</b> be less than 2<sup>128</sup>. <code>{@link SamlddHelper}</code> provides simple methods to
	 * generate random identifiers.
	 * 
	 * @param id the identifier value
	 */
	public void setIdentifier(String id) {
		assertion.setID(id);
	}

	/**
	 * Returns the certificate unique identifier.
	 * 
	 * @return the string rapresenting the unique identifier of this certificate.
	 */
	public String getIdentifier() {
		return assertion.getID();
	}

	/**
	 * Sets the certificate issue instant to the given time. Note that the issue time is automatically
	 * set to the current time upon initialization. 
	 * 
	 * @param time when this certificate has been issued
	 * 
	 * @see SamlddCertificate#SPKICertificate(String)
	 * @see org.joda.time.DateTime
	 */
	public void setIssueIstant(org.joda.time.DateTime time) {
		assertion.setIssueInstant(time);
	}

	/**
	 * Returns the time on which the certificate was issued.
	 * 
	 * @return the issue istant as a <code>{@link org.joda.time.DateTime}</code>.
	 */
	public org.joda.time.DateTime getIssueIstant() {
		return assertion.getIssueInstant();
	}

	/**
	 * Sets the hash of the key of the issuer. The actual key that issues the certificate can be embedded in the 
	 * signature element.
	 * 
	 * @param keyHash the hash of the issuer's key obtained through the {@link SamlddHelper} 
	 */
	public void setIssuer(String keyHash) {
		if (SamlddHelper.isKeyHash(keyHash)) {
			// Let's create the issuer
			Issuer issuer = (Issuer) buildSAMLObject(Issuer.DEFAULT_ELEMENT_NAME);

			// Setting the new issuer
			issuer.setValue(keyHash);

			// Updatiting assertione
			assertion.setIssuer(issuer);
		}
	}

	/**
	 * Returns the hash of the issuer key. The hash is referd to the public key corrispondig to the key that
	 * issued the certificate. 
	 * 
	 * @return the string rapresenting the name of the issuer's key.
	 */
	public String getIssuer() {
		Issuer issuer = assertion.getIssuer();
		return issuer.getValue();
	}

	/**
	 * Gets the issuer's public key, corrusponding to the key used to sign this certificate
	 * 
	 * @return The issuer's public key. <code>null</code> when the public key is not embedded in the certificate.
	 * @throws CertificateParsingException when the certificate is not signed.
	 */
	public PublicKey getIssuerKey() throws CertificateParsingException {
		// If the cert is signed
		Signature sign = assertion.getSignature();
		if (sign == null) {
			throw new CertificateParsingException("Certificate not signed");
		}

		// Retreive the public key from the signature
		KeyInfo keyInfo = assertion.getSignature().getKeyInfo();
		if (keyInfo != null) {
			try {
				return KeyInfoHelper.getPublicKeys(keyInfo).get(0);
			} catch (KeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		// No key embedded in the signature
		return null;
	}

	/**
	 * Adds a validity condition to the certificate.
	 * 
	 * @param cond the {@link ValidityCondition} to be added.
	 */
	public void addCondition(ValidityCondition cond) {
		if (cond != null) {
			// Get the conditions SAML object
			Conditions conditions = assertion.getConditions();
			if (conditions == null) {
				conditions = (Conditions) buildSAMLObject(Conditions.DEFAULT_ELEMENT_NAME);
			}

			// Add the condition
			cond.toSAMLCondition(conditions);
			assertion.setConditions(conditions);
		}
	}

	/**
	 * Gets the unmutable list of  {@link ValidityCondition} that are present in the certificate.
	 * 
	 * @return the list of {@link ValidityCondition} present in the document. 
	 */
	public List<ValidityCondition> getConditions() {
		Conditions conds = assertion.getConditions();
		return Collections.unmodifiableList(ConditionManager.createConditionsFrom(conds));	
	}

	public Element getMarshalledAssertion() throws CertificateEncodingException {
		// If the document wasn't already marshalled...
		if (marshalledAssertion == null) {
			// Check if the signuature is present
			Signature sign = assertion.getSignature();
			if (sign == null) throw new CertificateEncodingException("Assertion not signed");

			// Get the marshaller for the assertion
			MarshallerFactory marshallerFactory = org.opensaml.Configuration.getMarshallerFactory();
			Marshaller marshaller = marshallerFactory.getMarshaller(assertion);

			try{
				marshalledAssertion = marshaller.marshall(assertion);
			} catch(MarshallingException e) {
				throw new CertificateEncodingException(e.getMessage(), e);
			}

			// Now sign the marshalled object
			try {
				Signer.signObject(sign);
			} catch (org.opensaml.xml.signature.SignatureException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return marshalledAssertion;
	}
	
	/**
	 * Returns the encoded form of this certificate. The encoding format is a plain text XML document.
	 * 
	 * @return the bytes rapresenting the XML document.
	 * 
	 * @throws CertificateEncodingException when the marshalling process fails.
	 */
	@Override
	public byte[] getEncoded() throws CertificateEncodingException {
		getMarshalledAssertion();

		// Now transform the element into a byte stream
		Document doc = marshalledAssertion.getOwnerDocument();

		// Prepare the source for the transformation...
		Source source = new DOMSource(doc);

		// ...and the byte array result
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		Result result = new StreamResult(byteStream);

		try {
			// Transform the DOM document into an XML byte stream
			Transformer xformer = TransformerFactory.newInstance().newTransformer();
			xformer.transform(source, result);
		} catch (Exception e) {
			// Something Wrong... Rethrow the exception...
			throw new CertificateEncodingException(e.getMessage(), e);
		}

		return byteStream.toByteArray();
	}

	/**
	 * Verify the validity of the certificate and if it was signed with the private key corrisponding to the given
	 * public key.
	 * 
	 * @param key the public key to perform the verification.
	 * 
	 * @throws CertificateException when the certificate is not well formed.
	 * @throws InvalidKeyException when the key is not the same type as the one used to sign the document.
	 * @throws SignatureException when the signature is wrong.
	 */
	@Override
	public void verify(PublicKey key)
			throws CertificateException,
			InvalidKeyException, SignatureException {

		// Get the signature from the assertion
		Signature sign = assertion.getSignature();
		if (sign == null) {
			throw new CertificateException("Signature not found");
		}

		// If the assertion is not signed but the signature is not null we need to marshall the object
		if (!assertion.isSigned()) {
			// Create the encoded form
			getEncoded();
		}

		// Get the suite of validator to check the validity of SAML code
		ValidatorSuite vSuite = Configuration.getValidatorSuite("saml2-core-schema-validator");
		try {
			vSuite.validate(assertion);
		} catch (ValidationException e) {
			throw new CertificateException(e.getMessage(), e);
		}
		/* CODE FOR NEW OPENSAML VERSIONS
		BasicX509SignatureTrustEngine engine = new BasicX509SignatureTrustEngine();
		WrapperKeyInfoSource wrapper = new WrapperKeyInfoSource("CertKeyInfos", sign.getKeyInfo());
		InlineX509KeyInfoResolver resolver = new InlineX509KeyInfoResolver();
		try
		{
			if(! engine.validate(sign, wrapper, resolver))
				throw new SignatureException("Validation process failed");
		}
		catch(SecurityException e)
		{
			throw new SignatureException(e.getMessage(), e);
		}
/*/

		BasicCredential credential = new BasicCredential();
		credential.setPublicKey(key);
		SignatureValidator signValidator = new SignatureValidator(credential);
		try {
			// Now validate the sign
			signValidator.validate(sign);
		} catch (ValidationException e) {
			// Validation Exception!
			// NOTE Gestire eccezione InvalidKeyException
			throw new SignatureException(e.getMessage(), e);
		}
	}

	/**
	 * Verify the validity of the certificate and if it was signed with the private key corrisponding to the given
	 * public key. Only the SAMLSPKI provider can be used to perform the check due to the structure of the xml
	 * signature.
	 * 
	 * @param key the public key to perform the verification.
	 * @param sigProvider the name of the signature provider. Only "SPKI" is allowed.
	 * 
	 * @throws NoSuchProviderException when the provider is incorrect.
	 * @throws CertificateException when the certificate is not well formed.
	 * @throws InvalidKeyException when the key is not the same type as the one used to sign the document.
	 * @throws SignatureException when the signature is wrong.
	 */
	@Override
	public void verify(PublicKey key, String sigProvider)
			throws CertificateException, InvalidKeyException,
			NoSuchProviderException, SignatureException {
		if (!sigProvider.equalsIgnoreCase("SPKI")) {
			throw new NoSuchProviderException("Only SPKI provider can be used on SPKI certificate");
		}

		verify(key);
	}

	/**
	 * Signs the certificate using the default signing and envelope the public key in the certificate.
	 * 
	 * @param keys The private key to sign the certificate and the public key to evelope in it.
	 * 
	 * @see SignatureParameters#SignatureParameters()
	 */
	public void sign(KeyPair keys) {
		sign(keys, new SignatureParameters());
	}

	/**
	 * Signs the certificate using the specified signing parameteres and envelope the public key in the certificate.
	 * 
	 * @param keys The private key to sign the certificate and the public key to evelope in it.
	 * @param params the alogorithm paramaters. Refer to {@link SignatureParameters} to see what parameters can be
	 *           specified.
	 * 
	 * @see SignatureParameters
	 */
	public void sign(KeyPair keys, SignatureParameters params) {
		// Create the SignatureBuilder and build the signature
		Signature sign = (Signature) buildSAMLObject(Signature.DEFAULT_ELEMENT_NAME);

		// Set up signature parameters
		BasicCredential credential = new BasicCredential();
		credential.setPrivateKey(keys.getPrivate());
		sign.setSigningCredential(credential);
		sign.setSignatureAlgorithm(params.getAlgorithm());
		sign.setCanonicalizationAlgorithm(params.getCanonicalization());

		// Add the public key to the signature
		KeyInfo keyInfo = (KeyInfo) buildSAMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);

		KeyInfoHelper.addPublicKey(keyInfo, keys.getPublic());
		sign.setKeyInfo(keyInfo);

		// Link the signature and the assertion togheter
		SAMLObjectContentReference contentReference = new SAMLObjectContentReference(assertion);
		sign.getContentReferences().add(contentReference);
		assertion.setSignature(sign);

		// Delete del old marshalled assertion
		marshalledAssertion = null;
	}

	/** 
	 * Checks if it is a name SPKI certificate
	 * 
	 *  @return <code>true</code> if this istance is a name certificate.
	 */ 
	public abstract boolean isNameCertificate();

	/**
	 * Checks if it's a role SPKI certificate.
	 * 
	 * @return <code>true</code> if this istance is a role certificate.
	 */
	public abstract boolean isAuthorizationCertificate();
	/** 
	 * Creates the requested SAML object. The object type must be specified using it's QName
	 * 
	 * @param objectQName the {@link QName} of the object to build
	 * 
	 * @return the requested object. <tt>null</tt> if the building fails.
	 */
	protected XMLObject buildSAMLObject(QName objectQName) {
		XMLObjectBuilder builder = Configuration
				.getBuilderFactory().getBuilder(objectQName);
		if (builder != null) {
			return builder.buildObject(objectQName);
		}
		System.err.println("cannot build " + objectQName);
		return null;
	}

}
