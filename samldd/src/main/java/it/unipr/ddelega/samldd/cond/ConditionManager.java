package it.unipr.ddelega.samldd.cond;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;

import org.opensaml.saml2.core.Conditions;

/** 
 * Manager class for {@link ValidityCondition} objects. Every newly created conditions <b>must be</b> registered at this manager using the {@link #registerCondition(Class)} method.
 *
 * @author Thomas Florio
 *
 */
public class ConditionManager {
	
	/** List of known conditions */
	static private final List<Class> knownConditions = new ArrayList<Class>();
	
	/** Registers the default ValidityConditions */
	static {
		knownConditions.add( TimeValidityCondition.class );
	}
	
	/**
	 * Register a new {@link ValidityCondition} implementation.
	 * 
	 * @param condClass a class that implements the {@link ValidityCondition} interface.
	 */
	public static void registerCondition( Class<? extends ValidityCondition> condClass )
	{
		// Check if the class as a default Constructor
		try { condClass.getConstructor(); }
		catch( SecurityException e ) { throw new Error( "Securty error", e ); }
		catch( NoSuchMethodException e ) { throw new Error( condClass.toString() + " has not a default constructor", e ); } 
		
		// Add to the list if it's not already present
		if( ! knownConditions.contains( condClass ) )
			knownConditions.add( condClass );
	}

	/** 
	 * Delete a {@link ValidityCondition} implementatation from the list of known conditions. Once
	 * removed from the list the condition will not be taken in consideration anymore while unmarshalling
	 * the conditions from the XML certificate. 
	 * 
	 * @param condClass the {@link ValidityCondition} implementation to be removed
	 */
	public static void deregisterCondition( Class<? extends ValidityCondition> condClass )
	{
		knownConditions.remove( condClass );
	}
	
	/**
	 * Gets the unmutable list of known conditions. The list contains the string rapresentation obtained from the 
	 * {@link Class#toString()} method.
	 * 
	 * @return the names of the known {@link ValidityCondition} implementations.
	 * 
	 */
	public static List<String> getKnownConditions()
	{
		List<String> result = new ArrayList<String>();
		
		Iterator<Class> iter = knownConditions.iterator();
		while( iter.hasNext() )
			result.add( iter.next().toString() );
		
		
		return Collections.unmodifiableList( result );
	}
	
	/**
	 * Creates all the {@link ValidityCondition} objects that are contained in the given
	 * SAML {@link Conditions}. This process will try to build every known condition (using
	 * the {@link ValidityCondition#fromSAMLCondition(Conditions)} mehtod). If the building
	 * is successful, the created {@link ValidityCondition} will be present in the returned
	 * list.  
	 * 
	 * @param samlConditions the SAML object rapresenting the conditions.
	 *  
	 * @return a list of the {@link ValidityCondition} found in the SAML object.
	 */
	public static List<ValidityCondition> createConditionsFrom( Conditions samlConditions )
	{
		// List of ValidityConditions that are available in the given condition object
		List<ValidityCondition> availableCond = new ArrayList<ValidityCondition>();		
		
		if( samlConditions == null )
			return availableCond;

		Iterator<Class> iter = knownConditions.iterator();
		
		// Loop over the known conditions and try to build an object
		while( iter.hasNext() )
		{
			try {
				ValidityCondition obj = (ValidityCondition) iter.next().newInstance();
				obj.fromSAMLCondition( samlConditions );
				availableCond.add( obj );
			}
			catch( Exception e ) { /* Something wrog here, but nothing to do */ }

		}
		
		return availableCond;
	}
}
