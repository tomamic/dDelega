package it.unipr.ddelega.samldd.cond;

import it.unipr.ddelega.samldd.ValidationContext;

import java.util.Date;

import org.joda.time.DateTime;
import org.joda.time.DateTimeComparator;
import org.opensaml.saml2.core.Conditions;


public class TimeValidityCondition implements ValidityCondition {

	/** The time before which the certificate is not yet valid. */
	private DateTime notBefore;

	/** The time on or after which the certifcate is expired */
	private DateTime notOnOrAfter;

	/** Default constructor */
	public TimeValidityCondition()
	{
		notBefore = null;
		notOnOrAfter = null;
	}

	/**
	 * Builds the object with given dates.
	 * 
	 * @param newNotBefore the time instant before which the certificate is not valid
	 * @param newNotOnOrAfter the time instant on or after which the certificate is not valid
	 */
	public TimeValidityCondition( DateTime newNotBefore, DateTime newNotOnOrAfter )
	{
		notBefore = new DateTime( newNotBefore );
		notOnOrAfter = new DateTime( newNotOnOrAfter );
	}

	/**
	 * Build the object with the given dates in java format.
	 * 
	 * @param newNotBefore the time instant before which the certificate is not valid
	 * @param newNotOnOrAfter the time instant on or after which the certificate is not valid
	 */
	public TimeValidityCondition( Date newNotBefore, Date newNotOnOrAfter )
	{
		notBefore = new DateTime( newNotBefore.getTime() );
		notOnOrAfter = new DateTime( newNotOnOrAfter.getTime() );
	}
	
	/**
	 * Returns the date/time before which the certificate is not valid.
	 * 
	 * @return the {@link DateTime} object rapresenting the time instant.
	 */

	public DateTime getNotBefore()
	{
		return notBefore;
	}

	/**
	 * Sets the date/time before which the certificate is not yet valid.
	 * 
	 * @param newNotBefore the new time instant.
	 */
	public void setNotBefore( DateTime newNotBefore )
	{
		notBefore = newNotBefore;
	}

	/**
	 * Returns the date/time on or after which the certificate is not valid.
	 * 
	 * @return the {@link DateTime} object rapresenting the time istant.
	 */
	public DateTime getNotOnOrAfter()
	{
		return notOnOrAfter;
	}

	/**
	 * Sets the date/time on or after which the certificate is expired.
	 * 
	 * @param newNotOnOrAfter the new time instant.
	 */
	public void setNotOnOrAfter( DateTime newNotOnOrAfter )
	{
		notOnOrAfter = newNotOnOrAfter;
	}

	/** {@inheritDoc} */
	public void toSAMLCondition( Conditions samlCondition )
	{
		samlCondition.setNotBefore( notBefore );
		samlCondition.setNotOnOrAfter( notOnOrAfter );
	}

	/** {@inheritDoc} */
	public void validate( ValidationContext context ) throws ConditionNotValidException
	{
		DateTimeComparator comparator = DateTimeComparator.getInstance();

		if( comparator.compare( context.getValidationInstant(), notBefore ) < 0 )
			throw new ConditionNotValidException( "Valid from " + notBefore.toString() );

		if( comparator.compare( context.getValidationInstant(), notOnOrAfter ) > 0 )
			throw new ConditionNotValidException( "Expired on " + notOnOrAfter.toString() );
	}

	/** {@inheritDoc} */
	public void fromSAMLCondition( Conditions samlCondition ) throws ConditionNotPresentException
	{
		if( samlCondition.getNotBefore() == null && samlCondition.getNotOnOrAfter() == null )
			throw new ConditionNotPresentException( "Both NotBefore and NotOnOrAfter not present in the certificate" );
		
		notBefore = samlCondition.getNotBefore();
		notOnOrAfter = samlCondition.getNotOnOrAfter();
	}

	/** {@inheritDoc} */
	@Override public String toString()
	{
		String buf = new String();
		
		if( notBefore != null )
			buf.concat( "Not valid before: "  + notBefore.toString() + " " );
		
		if( notOnOrAfter != null )
			buf.concat( "Expires on: " + notOnOrAfter.toString() );

		if( buf.length() > 0 )
			return buf;
		else
			return "Always valid";
	}

}
