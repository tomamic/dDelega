package it.unipr.ddelega.samldd.name;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactorySpi;
import java.security.cert.CertificateParsingException;

import java.util.Collection;

import java.util.ArrayList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Factory class to build <code>SPKINameCertificate</code>s
 * 
 * @see java.security.cert.CertificateFactory
 * @see java.security.cert.CertificateFactorySpi
 * 
 * @author Thomas Florio
 */
public class CertificateFactory extends CertificateFactorySpi {

	/** Default constructor. */
	public CertificateFactory() {
	}

	/**
	 * <b>CRL Not Supported</b>
	 */
	@Override
	public CRL engineGenerateCRL(InputStream inStream) throws CRLException {
		throw new UnsupportedOperationException();
	}

	/**
	 * <b>CRL Not Supported</b>
	 */
	@Override
	public Collection<? extends CRL> engineGenerateCRLs(InputStream inStream)
			throws CRLException {
		throw new UnsupportedOperationException();
	}

	/**
	 * Generate a certificate unmarshalling the XML from the given input stream.
	 * The certificate is specified by the SAML element 'assertion'.
	 * 
	 * @param inStream the input stream with the certificate data
	 * 
	 * @return a certificate initialized with the XML from the input stream.
	 * 
	 * @throws CertificateException when the parsing process fails.
	 */
	@Override
	public SamlddNameCertificate engineGenerateCertificate(InputStream inStream)
			throws CertificateException {
		// Get a parser
		BasicParserPool ppMgr = new BasicParserPool();
		Document doc = null;

		try {
			// Parse the input form the stream into a w3c DOM
			doc = ppMgr.parse(inStream);
			// Validate the document
			ppMgr.isDTDValidating();
		} catch(XMLParserException e) {
			if (!e.getCause().toString().startsWith("java.net.UnknownHostException")) {
				throw new CertificateException(e.getMessage(), e);
			}
		}

		// Build a new certificate unmarshalling the DOM document
		return new SamlddNameCertificate(doc.getDocumentElement());
	}

	/**
	 * Returns a collection view of the certificates obtained from the 
	 * unmarshalling of the given XML input stream.
	 * 
	 * Note that if the given input stream does not support mark and reset, this 
	 * method will consume the entire input stream.
	 * 
	 * @param inStream the XML input stream containing the certificates.
	 * 
	 * @return a collection of SPKINameCertificate parsed from the input stream.
	 * 
	 * @throws CertificateException when an error occours.
	 */
	@Override
	public Collection<SamlddNameCertificate> engineGenerateCertificates(InputStream inStream)
			throws CertificateException {
		Collection<SamlddNameCertificate> collection = new ArrayList<SamlddNameCertificate>();

		BasicParserPool ppMgr = new BasicParserPool();
		Document doc = null;

		try {
			// Parse the input form the stream into a w3c DOM
			doc = ppMgr.parse(inStream);
			// Validate the document
			ppMgr.isDTDValidating();
		} catch(XMLParserException e) {
			if (!e.getCause().toString().startsWith("java.net.UnknownHostException")) {
				throw new CertificateException(e.getMessage(), e);
			}
		}

		NodeList nodes = doc.getElementsByTagName("saml:Assertion");
		for (int i = 0; i < nodes.getLength(); i++) {
			Node node = nodes.item(i);
			if (node.getNodeType() == Node.ELEMENT_NODE) {
				Element element = (Element) node;
				SamlddNameCertificate certificate = new SamlddNameCertificate(element);
				collection.add(certificate);
			}
		}

		/*BufferedReader br = new BufferedReader(new InputStreamReader(inStream));
		String buffer = new String();

		try {
			String line = br.readLine();
			while (br.ready()) {
				// If the line is the certificate separator... 
				if (line.equals(DdsamlCertPath.XML_CERTIFICATE_SEPARATOR)) {
					// ...parse all input from the string buffer
					ByteArrayInputStream certStream = new ByteArrayInputStream(buffer.getBytes());				
					DdsamlNameCertificate cert = (DdsamlNameCertificate) engineGenerateCertificate(certStream);
					collection.add(cert);

					// Reset the buffer
					buffer = "";
				} else {
					// Add the line
					buffer = buffer + line + "\n"; 	
				}

				line = br.readLine();
			}

			// Add last line to buffer
			buffer = buffer + line + "\n";
		} catch(IOException e) {
			throw new CertificateParsingException("I/O Error in input stream", e);
		}

		// Parse the last certificate
		ByteArrayInputStream certStream = new ByteArrayInputStream(buffer.getBytes());
		DdsamlNameCertificate cert = (DdsamlNameCertificate) engineGenerateCertificate(certStream);
		collection.add(cert);*/

		return collection;
	}

}
