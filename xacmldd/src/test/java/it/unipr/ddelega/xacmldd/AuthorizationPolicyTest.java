package it.unipr.ddelega.xacmldd;


import static org.junit.Assert.*;

import it.unipr.ddelega.xacmldd.authz.SimpleAuthorizationPolicy;

import java.util.List;

import junit.framework.JUnit4TestAdapter;

import org.junit.Before;
import org.junit.Test;
import com.sun.xacml.Policy;
import com.sun.xacml.Rule;
import com.sun.xacml.TargetMatch;
import com.sun.xacml.TargetMatchGroup;
import com.sun.xacml.attr.StringAttribute;
import com.sun.xacml.cond.MatchFunction;

@SuppressWarnings("unchecked")
public class AuthorizationPolicyTest {

	SimpleAuthorizationPolicy rp;

	@Before
	public void setUp() {
		rp = new SimpleAuthorizationPolicy();
	}

	@Test
	public void testEmptyPolicy() {
		assertNull(rp.getXACMLPolicy());
		rp.setEffect(SimpleAuthorizationPolicy.EFFECT_DENY);
		assertNotNull(rp.getXACMLPolicy());
	}

	@Test
	public void testAddSubjects() {
		rp.addSubject("TestAdd", "Subject1");
		rp.addSubject("TestAdd", "Subject2");

		rp.addSubject("HASH:TestKeyHash");

		ThresholdSubject th1 = new ThresholdSubject(ThresholdSubject.N_OVER_N);
		th1.addSubject("Threshold1", "Name1");
		th1.addSubject("HASH:ThresholdNameHash2=");
		rp.addSubject(th1);

		ThresholdSubject th2 = new ThresholdSubject(ThresholdSubject.ONE_OVER_N);
		th2.addSubject("Threshold2", "Name3");
		th2.addSubject("HASH:ThresholdNameHash4==");
		rp.addSubject(th2);

		// Now check directly in the XACML code  the result
		Policy p = rp.getXACMLPolicy();
		// Should be null because we didn't set an effect
		assertNull(p);

		// Now add a effect and check again
		rp.setEffect(SimpleAuthorizationPolicy.EFFECT_DENY);
		p = rp.getXACMLPolicy();
		assertNotNull(p);

		assertNotNull(p.getTarget());
		assertNotNull(p.getTarget().getSubjectsSection());
		assertTrue(p.getTarget().getSubjectsSection().getMatchGroups().size() > 0);

		List<TargetMatchGroup> subjects = p.getTarget().getSubjectsSection().getMatchGroups();
		assertEquals(6, subjects.size());
		assertEquals(XacmlddHelper.createFullyQualifiedName("TestAdd", "Subject1"), getMatchValue(subjects.get(0), 0));
		assertEquals(XacmlddHelper.createFullyQualifiedName("TestAdd", "Subject2"), getMatchValue(subjects.get(1), 0));
		assertEquals("HASH:TestKeyHash", getMatchValue(subjects.get(2), 0));
		// First Threshold is N_OVER_N so with multiple <targetmatch>
		assertEquals(XacmlddHelper.createFullyQualifiedName("Threshold1", "Name1"), getMatchValue(subjects.get(3), 0));
		assertEquals("HASH:ThresholdNameHash2=", getMatchValue(subjects.get(3), 1));
		// Second threshold is ONE_OVER_N so multiple <subject>
		assertEquals(XacmlddHelper.createFullyQualifiedName("Threshold2", "Name3"), getMatchValue(subjects.get(4), 0));
		assertEquals("HASH:ThresholdNameHash4==", getMatchValue(subjects.get(5), 0));

		// Now test the getSubject() and getThresholdSubject() methods
		List<String> singleSubjects = rp.getSubjects();
		assertTrue(singleSubjects.contains(XacmlddHelper.createFullyQualifiedName("TestAdd", "Subject1")));
		assertTrue(singleSubjects.contains(XacmlddHelper.createFullyQualifiedName("TestAdd", "Subject2")));
		assertTrue(singleSubjects.contains(XacmlddHelper.createFullyQualifiedName("Threshold2", "Name3")));
		assertTrue(singleSubjects.contains("HASH:ThresholdNameHash4=="));


		List<ThresholdSubject> thresholdSubjects = rp.getThresholdSubjects();
		assertTrue(thresholdSubjects.contains(th1));
	}

	@Test
	public void testAddResources() throws Exception {
		rp.addResource("LaserPrinter");
		rp.addResource("database.mdb");
		rp.addResource("C:\\Myfiles\\*.txt", MatchFunction.NAME_REGEXP_STRING_MATCH);

		Policy p = rp.getXACMLPolicy();
		// Shold be null because we didn't add an effect 
		assertNull(p);

		// Now add a effect and check again
		rp.setEffect(SimpleAuthorizationPolicy.EFFECT_DENY);
		p = rp.getXACMLPolicy();
		assertNotNull(p);

		assertNotNull( p.getTarget());
		assertNotNull(p.getTarget().getResourcesSection());
		assertTrue(p.getTarget().getResourcesSection().getMatchGroups().size() > 0);

		List<TargetMatchGroup> res = p.getTarget().getResourcesSection().getMatchGroups();
		assertEquals(3, res.size());
		assertEquals("LaserPrinter", getMatchValue(res.get(0), 0));
		assertEquals("database.mdb", getMatchValue(res.get(1), 0 ));
		assertEquals("C:\\Myfiles\\*.txt", getMatchValue(res.get(2), 0));

		// Check the getResources() method
		List<String> resList = rp.getResources();
		assertTrue(resList.contains("LaserPrinter"));
		assertTrue(resList.contains("database.mdb"));
		assertTrue(resList.contains("C:\\Myfiles\\*.txt"));

	}

	@Test
	public void testAddActions() {
		rp.addAction("Read");
		rp.addAction("Write");
		rp.addAction("Print");

		Policy p = rp.getXACMLPolicy();
		// Should be null because we didn't add an effect 
		assertNull(p);

		// Now add a effect and check again
		rp.setEffect(SimpleAuthorizationPolicy.EFFECT_DENY);
		p = rp.getXACMLPolicy();
		assertNotNull(p);

		assertNotNull(p.getTarget());
		assertNotNull(p.getTarget().getActionsSection());
		assertTrue(p.getTarget().getActionsSection().getMatchGroups().size() > 0);

		List<TargetMatchGroup> act = p.getTarget().getActionsSection().getMatchGroups();
		assertEquals(3, act.size());
		assertEquals("Read", getMatchValue(act.get(0), 0));
		assertEquals("Write", getMatchValue(act.get(1), 0));
		assertEquals("Print", getMatchValue(act.get(2), 0));

		// Check the getActions() method
		List<String> actList = rp.getActions();
		assertTrue(actList.contains("Read"));
		assertTrue(actList.contains("Write"));
		assertTrue(actList.contains("Print"));
	}

	@Test
	public void testSetEffect() throws Exception {
		Rule rule;

		rp.setEffect(SimpleAuthorizationPolicy.EFFECT_DENY);
		assertEquals("Unexpected elements in rule list", 1, rp.getXACMLPolicy().getChildren().size());
		rule = (Rule) rp.getXACMLPolicy().getChildren().get(0);
		assertEquals(SimpleAuthorizationPolicy.EFFECT_DENY, rule.getEffect());
		assertNull(rule.getDescription());

		rp.setEffect(SimpleAuthorizationPolicy.EFFECT_DENY, "Test di regola con descrizione e id", "org:spki:role:test:identifier:user-defined");
		assertEquals("Unexpected elements in rule list", 1, rp.getXACMLPolicy().getChildren().size());
		rule = (Rule) rp.getXACMLPolicy().getChildren().get(0);
		assertEquals(SimpleAuthorizationPolicy.EFFECT_DENY, rule.getEffect());
		assertEquals("Test di regola con descrizione e id", rule.getDescription());
		assertEquals("org:spki:role:test:identifier:user-defined", rule.getId().toString());

		rp.setEffect(SimpleAuthorizationPolicy.EFFECT_PERMIT);
		assertEquals("Unexpected elements in rule list", 1, rp.getXACMLPolicy().getChildren().size());
		rule = (Rule) rp.getXACMLPolicy().getChildren().get(0);
		assertEquals(SimpleAuthorizationPolicy.EFFECT_PERMIT, rule.getEffect());
		assertNull(rule.getDescription());

		rp.setEffect(SimpleAuthorizationPolicy.EFFECT_PERMIT, "Test di regola con descrizione");
		assertEquals("Unexpected elements in rule list", 1, rp.getXACMLPolicy().getChildren().size());
		rule = (Rule) rp.getXACMLPolicy().getChildren().get(0);
		assertEquals(SimpleAuthorizationPolicy.EFFECT_PERMIT, rule.getEffect());
		assertEquals("Test di regola con descrizione", rule.getDescription());
	}

	@Test
	public void testAllPolicyElements() throws Exception {
		rp.addSubject("TestPolicy", "Subject");

		ThresholdSubject th1 = new ThresholdSubject(ThresholdSubject.N_OVER_N);
		th1.addSubject("TestPolicy",	"Threshold");
		th1.addSubject("HASH:ThresholdNameHash");
		rp.addSubject(th1);

		rp.addResource("C:\\Myfiles\\*.txt", MatchFunction.NAME_REGEXP_STRING_MATCH);
		rp.addAction("Read");

		rp.setEffect(SimpleAuthorizationPolicy.EFFECT_PERMIT);

		Policy p = rp.getXACMLPolicy();

		assertNotNull(p.getTarget());

		List<TargetMatchGroup> act = p.getTarget().getActionsSection().getMatchGroups();
		List<TargetMatchGroup> res = p.getTarget().getResourcesSection().getMatchGroups();
		List<TargetMatchGroup> sbj  = p.getTarget().getSubjectsSection().getMatchGroups();

		assertEquals(1, act.size());
		assertEquals(1, res.size());
		assertEquals(2, sbj.size());

		assertEquals("Read", getMatchValue(act.get(0), 0));
		assertEquals("C:\\Myfiles\\*.txt", getMatchValue(res.get(0), 0));
		assertEquals(XacmlddHelper.createFullyQualifiedName("TestPolicy", "Subject"), getMatchValue(sbj.get(0), 0));

		assertEquals(XacmlddHelper.createFullyQualifiedName("TestPolicy", "Threshold"), getMatchValue(sbj.get(1), 0));
		assertEquals("HASH:ThresholdNameHash", getMatchValue(sbj.get(1), 1));

		List rules = p.getChildren();
		assertNotNull(rules);
		assertEquals(1, rules.size());

		Rule rule = (Rule) rules.get(0);
		assertEquals(SimpleAuthorizationPolicy.EFFECT_PERMIT, rule.getEffect());
	}

	private static String getMatchValue(TargetMatchGroup matchList, int index) {
		List matches = SimpleAuthorizationPolicy.getMatches(matchList);
		TargetMatch tm = (TargetMatch) matches.get(index);
		StringAttribute attr = (StringAttribute) tm.getMatchValue();
		return attr.getValue();
	}

	public static junit.framework.Test suite() {
		return new JUnit4TestAdapter(AuthorizationPolicyTest.class);
	}
}
