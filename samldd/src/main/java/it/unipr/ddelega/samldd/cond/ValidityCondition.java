package it.unipr.ddelega.samldd.cond;

import it.unipr.ddelega.samldd.ValidationContext;

import java.security.cert.CertificateException;

import org.opensaml.saml2.core.Conditions;


/** Interface that rapresents a SPKI condition. */
public interface ValidityCondition {

	/**
	 * Sets the rapresented condition into the given SAML conditions object. The condition must be added without
	 * changing other fields (unrelated to this condition implementation).
	 * 
	 * @param samlConditions the SAML condition object to be modified.
	 */
	public abstract void toSAMLCondition( Conditions samlConditions );

	/**
	 * Checks if this condition is valid or not.
	 * 
	 * @throws CertificateException when the condition is not valid.
	 */
	public abstract void validate( ValidationContext context ) throws ConditionNotValidException;

	/**
	 * Creates the ValidityCondition object from the given SAML conditions.
	 * 
	 * @param samlCondition the object from wich build the condition object.
	 */
	public abstract void fromSAMLCondition( Conditions samlCondition ) throws ConditionNotPresentException;

}
