package it.unipr.ddelega.samldd.name;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertPath;
import java.security.cert.CertificateEncodingException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * An immutable series of certificate that rapresent a certification path. The path
 * starts with a (name, name) certificate and ends in a (key, name) certificate.
 * 
 * @author Thomas Florio
 */
public class SamlddCertPath extends CertPath implements Cloneable {

	/** The certficate separator in the CertPath encoding format */
	public static final String XML_CERTIFICATE_SEPARATOR = "<!-- dDelega/Saml name certificate -->";

	private static final long serialVersionUID = 5223645247309095562L;

	/** List of certificates */
	private List<SamlddNameCertificate> certPath;

	/** Base constructor */
	public SamlddCertPath() {
		super("dDelega/Saml");
		certPath = new ArrayList<SamlddNameCertificate>();
	}

	/**
	 * Initialize the certification path with the given list of certificates.
	 * 
	 * @param list the certificates to be added (in order) to the path
	 */
	public SamlddCertPath(List<SamlddNameCertificate> list) {
		super("dDelega/Saml");
		certPath = new ArrayList<SamlddNameCertificate>();
		certPath.addAll(list);
	}

	/**
	 * Returns the list of certificates in this certification path. The List 
	 * returned is immutable and thread-safe.
	 * 
	 *  @return an immutable List of Certificates (may be empty, but not null)
	 */
	@Override
	public List<SamlddNameCertificate> getCertificates() {
		return Collections.unmodifiableList( 
				Collections.synchronizedList(certPath));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] getEncoded() throws CertificateEncodingException {
		// Iter over the certification path.
		Iterator<SamlddNameCertificate> iterator = certPath.iterator();
		ByteArrayOutputStream stream = new ByteArrayOutputStream();

		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		XMLObjectBuilder pathBuilder = builderFactory.getBuilder(new QName("CertPath"));
		Element pathElement = pathBuilder.buildObject(new QName("CertPath")).getDOM();
		
		while (iterator.hasNext()) {
			SamlddNameCertificate cert = iterator.next();
			pathElement.appendChild(cert.getMarshalledAssertion());
		}
		
		// Now transform the element into a byte stream
		Document doc = pathElement.getOwnerDocument();

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

	/** Returns the encoded form of this certification path, using the specified
	 * encoding. The only encoding format available is "text/xml". 
	 * 
	 * @param encoding must be "text/xml"
	 * 
	 * @return the encoded bytes
	 * 
	 * @throws CertifcateEncodingException if the encoding is not supported or an
	 * encoding error occours.
	 */
	@Override
	public byte[] getEncoded( String encoding )
			throws CertificateEncodingException {
		// Only "text/xml" encoding is supported
		if (!encoding.equalsIgnoreCase("text/xml")) {
			throw new CertificateEncodingException(
					"Unsupported encoding: " + encoding);
		}
		// Use the standard getEncoded() method
		return getEncoded();
	}

	/**
	 * {@inheritDoc} 
	 */
	@Override
	public Iterator<String> getEncodings() {
		return Collections.singletonList("text/xml").iterator();
	}

	/**
	 * Clone this certification path.
	 * 
	 * @return a copy of this <code>SPKICertPath<code>.
	 */
	@Override
	public Object clone() {
		SamlddCertPath result = new SamlddCertPath();

		// Add directly all cert from the current certPath
		result.certPath.addAll(certPath);
		return result;
	}

}
