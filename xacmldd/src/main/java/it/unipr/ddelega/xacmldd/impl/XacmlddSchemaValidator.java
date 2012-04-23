package it.unipr.ddelega.xacmldd.impl;

import it.unipr.ddelega.xacmldd.XacmlddStatement;

import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.Validator;

/**
 * Checks {@link org.opensaml.samlext.xacml.XACMLPolicyStatement} for schema compliance.
 * 
 * Note that due to limitations in the SunXACML library, validation is not complete.
 *   
 * @author Thomas Florio
 *
 */
public class XacmlddSchemaValidator implements Validator<XacmlddStatement> {

	/** Constructor */
	public XacmlddSchemaValidator() { }

	/** {@inheritDoc} */
	@Override
	public void validate(XacmlddStatement xmlObject) throws ValidationException {
		validateContent(xmlObject);
	}

	/** Check if at list one Policy or PolicySet is present.
	 * 
	 * @param xmlObject the XACMLPolicyStatement to examine.
	 * 
	 * @throws ValidationException when no Policy or PolicySet are found.
	 */
	private void validateContent(XacmlddStatement xmlObject) throws ValidationException {
		if (xmlObject.getUniquePolicesList() == null
				|| xmlObject.getUniquePolicesList().size() == 0) {
			throw new ValidationException("Must contain at list one Policy or one PolicySet");
		}
	}
}
