package it.unipr.ddelega.ddsaml.cond;

import it.unipr.ddelega.samldd.cond.ConditionManager;
import it.unipr.ddelega.samldd.cond.TimeValidityCondition;

import java.util.List;

import junit.framework.JUnit4TestAdapter;

import org.junit.Test;
import static org.junit.Assert.*;

public class ConditionManagerTest {
	
	@Test public void testConditionsManager()
	{
		List<String> list = ConditionManager.getKnownConditions();
		int size = list.size();
		assertTrue( "0 known conditions", size != 0 );
		
		ConditionManager.registerCondition( TimeValidityCondition.class );
		list = ConditionManager.getKnownConditions();
		assertTrue( "Size changed after adding a known condition", list.size() == size );
		
		ConditionManager.deregisterCondition( TimeValidityCondition.class );
		list = ConditionManager.getKnownConditions();
		assertTrue( "Size not decreased after removing a known condition", list.size() == size - 1 );
		
		ConditionManager.registerCondition( TimeValidityCondition.class );
		list = ConditionManager.getKnownConditions();
		assertTrue( "Size not increased after adding a unknown condition", list.size() == size );	
	}
		
   public static junit.framework.Test suite() {
      return new JUnit4TestAdapter( ConditionManagerTest.class );
   }

}
