package it.unipr.ddelega.ddsaml.cond;

import it.unipr.ddelega.samldd.SamlddHelper;
import it.unipr.ddelega.samldd.ValidationContext;
import it.unipr.ddelega.samldd.cond.ConditionNotValidException;
import it.unipr.ddelega.samldd.cond.TimeValidityCondition;
import junit.framework.JUnit4TestAdapter;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

import org.joda.time.DateTime;
import org.joda.time.DateTimeComparator;

import org.opensaml.Configuration;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.impl.ConditionsBuilder;


public class TimeValidityConditionTest {
	
	DateTime notOnOrAfterDate;	
	DateTime notBeforeDate;	
	
	Conditions samlConditions;
	
	TimeValidityCondition tvCond;
	
	@Before public void setUp()
	{
		SamlddHelper.init();
		
		ConditionsBuilder cBuilder = (ConditionsBuilder) Configuration.getBuilderFactory().getBuilder( Conditions.DEFAULT_ELEMENT_NAME );
		samlConditions = cBuilder.buildObject();
		
		notBeforeDate = new DateTime( 2006, 6, 1, 12, 00, 00, 00 );
		notOnOrAfterDate = new DateTime( 2007, 6, 1, 12, 00, 00, 00 );
	
		tvCond = new TimeValidityCondition();
	}
	
	@Test public void testReadFromConditions() throws Exception
	{
		// Set up the conditions
		samlConditions.setNotBefore( notBeforeDate );
		samlConditions.setNotOnOrAfter( notOnOrAfterDate );
		
		// Read from the SAML object
		tvCond.fromSAMLCondition( samlConditions );
		
		// Test
		DateTimeComparator comparator = DateTimeComparator.getInstance();
		assertTrue( "NotBefore not equal", comparator.compare( samlConditions.getNotBefore(), tvCond.getNotBefore() ) == 0 );
		assertTrue( "NotOnOrAfter not equal", comparator.compare( samlConditions.getNotOnOrAfter(), tvCond.getNotOnOrAfter() ) == 0 );
	}
	
	@Test public void testWriteToConditions()
	{
		// Set up
		tvCond.setNotBefore( notBeforeDate );
		tvCond.setNotOnOrAfter( notOnOrAfterDate );
		
		// Write into the SAML object
		tvCond.toSAMLCondition( samlConditions );
		
		// Test
		DateTimeComparator comparator = DateTimeComparator.getInstance();
		assertTrue( "NotBefore not equal", comparator.compare( samlConditions.getNotBefore(), tvCond.getNotBefore() ) == 0 );
		assertTrue( "NotOnOrAfter not equal", comparator.compare( samlConditions.getNotOnOrAfter(), tvCond.getNotOnOrAfter() ) == 0 );
	}
	
	@Test public void testSuccessfulValidation() throws Exception
	{
		// Set up
		tvCond.setNotBefore( notBeforeDate );
		tvCond.setNotOnOrAfter( notOnOrAfterDate );	
		
		DateTime validationDate = new DateTime( 2007, 1, 1, 12, 0, 0, 0 );
		ValidationContext vContext = new ValidationContext( validationDate, null, null );
		
		tvCond.validate( vContext );
	}
	
	@Test public void testNotYetValid()
	{
		// Set up
		tvCond.setNotBefore( notBeforeDate );
		tvCond.setNotOnOrAfter( notOnOrAfterDate );	
		
		DateTime validationDate = new DateTime( 2006, 1, 1, 12, 0, 0, 0 );
		ValidationContext vContext = new ValidationContext( validationDate, null, null );
		
		try {
			tvCond.validate( vContext );
			fail( "Exception not thrown" );
		}
		catch( ConditionNotValidException e )
		{
			assertEquals( "CondtionNotValidException message not as expected", e.getMessage(), "Valid from " + notBeforeDate.toString() );
		}
	}
	
	@Test public void testExpired()
	{
		// Set up
		tvCond.setNotBefore( notBeforeDate );
		tvCond.setNotOnOrAfter( notOnOrAfterDate );	
		
		DateTime validationDate = new DateTime( 2008, 1, 1, 12, 0, 0, 0 );
		ValidationContext vContext = new ValidationContext( validationDate, null, null );
		
		try {
			tvCond.validate( vContext );
			fail( "Exception not thrown" );
		}
		catch( ConditionNotValidException e )
		{
			assertEquals( "CondtionNotValidException message not as expected", e.getMessage(), "Expired on " + notOnOrAfterDate.toString() );
		}
	}
	
   public static junit.framework.Test suite() {
      return new JUnit4TestAdapter( TimeValidityConditionTest.class );
   }
}
