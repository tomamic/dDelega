/**
 * 
 */
package it.unipr.ddelega;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

/**
 * @author mic
 *
 */
public class BasicSamlAssertion {

	/**
	 * @throws java.lang.Exception
	 */
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void test() {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();		        
		SAMLObjectBuilder<Assertion> builder = (SAMLObjectBuilder<Assertion>) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
		Assertion assertion = builder.buildObject();
		
		XSStringBuilder stringBuilder = (XSStringBuilder)builderFactory.getBuilder(XSString.TYPE_NAME);
		XSString attributeValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        attributeValue.setValue("member");
            
		SAMLObjectBuilder<Attribute> attributeBuilder = (SAMLObjectBuilder<Attribute>)
                builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
		if (attributeBuilder == null) System.out.println("urka\n");
        Attribute attribute = attributeBuilder.buildObject();
        attribute.setName("role");        
        attribute.setFriendlyName("role");
        attribute.setNameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
        attribute.getAttributeValues().add(attributeValue);
		
        SAMLObjectBuilder<AttributeStatement> statementBuilder = (SAMLObjectBuilder<AttributeStatement>) 
                builderFactory.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
        AttributeStatement attributeStatement = statementBuilder.buildObject();
        attributeStatement.getAttributes().add(attribute);
        
        assertion.getAttributeStatements().add(attributeStatement);
		
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(assertion);
        try {
			Element assertionElement = marshaller.marshall(assertion);
			System.out.println(XMLHelper.prettyPrintXML(assertionElement));
		} catch (MarshallingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		

	}

}
