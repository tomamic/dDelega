package it.unipr.ddelega.xacmldd;

import it.unipr.ddelega.samldd.SamlddHelper;
import it.unipr.ddelega.xacmldd.impl.XacmlddBuilder;
import it.unipr.ddelega.xacmldd.impl.XacmlddMarshaller;
import it.unipr.ddelega.xacmldd.impl.XacmlddSchemaValidator;
import it.unipr.ddelega.xacmldd.impl.XacmlddUnmarshaller;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.util.encoders.Base64;
import org.opensaml.Configuration;
/* CODE FOR NEW OPENSAML VERSIONS
import org.opensaml.DefaultBootstrap;
//*/
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.xml.validation.ValidatorSuite;

/**
 * Helper class to provide a simple implementation of common operations needed to build SPKI certificates.
 * 
 * @author Thomas Florio
 */
public class XacmlddHelper extends SamlddHelper {

	public static void init() {
		if (! initialized) {
			try{
				SamlddHelper.init();

				Configuration.registerObjectProvider( XacmlddStatement.DEFAULT_ELEMENT_NAME, new XacmlddBuilder(), new XacmlddMarshaller(), new XacmlddUnmarshaller(), null );
				ValidatorSuite suite = new ValidatorSuite( "xacml-saml" );
				suite.registerValidator( XacmlddStatement.DEFAULT_ELEMENT_NAME, new XacmlddSchemaValidator() );
				Configuration.registerValidatorSuite( "xacml-saml", suite, null );
				
				// Add the security provider
				Provider provider = new XacmlddProvider();
				Security.addProvider(provider);
			} catch( Exception e ) {
				throw new RuntimeException( "FATAL: Unable to initialize SPKI library", e );
			}
		}
	}
	
}
