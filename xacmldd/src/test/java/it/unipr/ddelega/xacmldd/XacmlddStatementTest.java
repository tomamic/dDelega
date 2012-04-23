package it.unipr.ddelega.xacmldd;

import java.net.URI;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.xml.namespace.QName;

import junit.framework.JUnit4TestAdapter;

import static org.junit.Assert.*;

import org.custommonkey.xmlunit.Diff;
import org.custommonkey.xmlunit.XMLUnit;
import org.junit.Before;
import org.junit.Test;

import org.opensaml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.parse.BasicParserPool;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import com.sun.xacml.Policy;
import com.sun.xacml.PolicyMetaData;
import com.sun.xacml.PolicySet;
import com.sun.xacml.Rule;
import com.sun.xacml.Target;
import com.sun.xacml.TargetMatch;
import com.sun.xacml.TargetMatchGroup;
import com.sun.xacml.TargetSection;
import com.sun.xacml.attr.AttributeDesignator;
import com.sun.xacml.attr.StringAttribute;
import com.sun.xacml.combine.DenyOverridesRuleAlg;
import com.sun.xacml.combine.FirstApplicablePolicyAlg;
import com.sun.xacml.combine.PolicyCombiningAlgorithm;
import com.sun.xacml.combine.RuleCombiningAlgorithm;
import com.sun.xacml.cond.Condition;
import com.sun.xacml.cond.EqualFunction;
import com.sun.xacml.cond.MatchFunction;
import com.sun.xacml.ctx.Result;

public class XacmlddStatementTest {

	static final String SINGLE_ELEMENT_FILE = "/data/it/unipr/ddelega/xacmldd/singleElement.xml";
	static final String CHILD_ELEMENTE_FILE = "/data/it/unipr/ddelega/xacmldd/childElement.xml";
	static final String COMPLEX_ELEMENT_FILE = "/data/it/unipr/ddelega/xacmldd/complexElement.xml";
	
	@Before
public void setUp() {
		XacmlddHelper.init();
		XMLUnit.setIgnoreWhitespace(true);
	}
	
	@Test
public void testSingleElementMarshall() throws Exception {
		XacmlddStatement pStatement = (XacmlddStatement) buildObject(XacmlddStatement.DEFAULT_ELEMENT_NAME);
		Document expectedDOM = getDOMFromFile(SINGLE_ELEMENT_FILE);
		
      Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(XacmlddStatement.DEFAULT_ELEMENT_NAME);
		assertNotNull("Unable to retrieve marshaller for " + XacmlddStatement.DEFAULT_ELEMENT_LOCAL_NAME.toString(), marshaller);
      
      Diff diff = XMLUnit.compareXML(expectedDOM, marshaller.marshall(pStatement).getOwnerDocument());
      assertTrue(diff.toString(), diff.identical());
	}
	
	@Test
public void testSingleElementUnmarshall() throws Exception {
		Document readedDoc = getDOMFromFile(SINGLE_ELEMENT_FILE);
		
		Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(XacmlddStatement.DEFAULT_ELEMENT_NAME);
		assertNotNull("Unable to retreive unmarshaller " + XacmlddStatement.DEFAULT_ELEMENT_LOCAL_NAME, unmarshaller);
		
		XacmlddStatement upStatement = (XacmlddStatement) unmarshaller.unmarshall(readedDoc.getDocumentElement());
		
		assertNotNull("Error umarshalling object", upStatement);
	
		if (upStatement.getPolicies() == null || upStatement.getPolicies().size() != 0) {
			fail("Policy list must be not null and empty");
		}
		
		if (upStatement.getPolicySets() == null || upStatement.getPolicySets().size() != 0) {
			fail("PolicySet list must be not null and empty");
		}
		
		if (upStatement.getUniquePolicesList() == null || upStatement.getUniquePolicesList().size() != 0) {
			fail("Union of Policy and PolicySet list must be not null and empty");
		}
	}

	@Test
public void testChildElementMarshall() throws Exception {
		XacmlddStatement pStatement = (XacmlddStatement) buildObject(XacmlddStatement.DEFAULT_ELEMENT_NAME);
		pStatement.getPolicies().add(buildPolicy());
		Document expectedDOM = getDOMFromFile(CHILD_ELEMENTE_FILE);
		
      Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(XacmlddStatement.DEFAULT_ELEMENT_NAME);
		assertNotNull("Unable to retrieve marshaller for " + XacmlddStatement.DEFAULT_ELEMENT_LOCAL_NAME, marshaller);
		
		Diff diff = XMLUnit.compareXML(expectedDOM,  marshaller.marshall(pStatement).getOwnerDocument());
		assertTrue(diff.toString(), diff.identical());
	}
	
	@Test
public void testChildElementUnmarshall() throws Exception {
		Document readedDoc = getDOMFromFile(CHILD_ELEMENTE_FILE);
		
		Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(XacmlddStatement.DEFAULT_ELEMENT_NAME);
		assertNotNull("Unable to retreive unmarshaller " + XacmlddStatement.DEFAULT_ELEMENT_LOCAL_NAME, unmarshaller);
		
		XacmlddStatement upStatement = (XacmlddStatement) unmarshaller.unmarshall(readedDoc.getDocumentElement());
		assertNotNull("Error umarshalling object", upStatement);
		
		if (upStatement.getPolicies() == null || upStatement.getPolicies().size() != 1) {
			fail("Policy list must not be null and must contain one element");
		}
		
		if (upStatement.getPolicySets() == null || upStatement.getPolicySets().size() != 0) {
			fail("PolicySet list must not be  null and must be empty");
		}
		
		if (upStatement.getUniquePolicesList() == null || upStatement.getUniquePolicesList().size() != 1) {
			fail("Union of Policy and PolicySet list must not be null and must contain one element");
		}
		
	}
	
	@Test
public void testComplexElementMarshall() throws Exception {
		XacmlddStatement pStatement = (XacmlddStatement) buildObject(XacmlddStatement.DEFAULT_ELEMENT_NAME);

		pStatement.getPolicies().add(buildPolicy());
		pStatement.getPolicySets().add(buildPolicySet());
		
		Document expectedDOM = getDOMFromFile(COMPLEX_ELEMENT_FILE);
		
      Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(XacmlddStatement.DEFAULT_ELEMENT_NAME);
		assertNotNull("Unable to retrieve marshaller for " + XacmlddStatement.DEFAULT_ELEMENT_LOCAL_NAME, marshaller);
		
		Diff diff = XMLUnit.compareXML(expectedDOM, marshaller.marshall(pStatement).getOwnerDocument());
		assertTrue(diff.toString(), diff.identical());
	}
	
	@Test public void testComplexElementUnmarshall() throws Exception {
		Document readedDoc = getDOMFromFile(COMPLEX_ELEMENT_FILE);
		
		Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(XacmlddStatement.DEFAULT_ELEMENT_NAME);
		assertNotNull("Unable to retreive unmarshaller " + XacmlddStatement.DEFAULT_ELEMENT_LOCAL_NAME, unmarshaller);
		
		XacmlddStatement upStatement = (XacmlddStatement) unmarshaller.unmarshall(readedDoc.getDocumentElement());
		assertNotNull("Error umarshalling object", upStatement);
		
		if (upStatement.getPolicies() == null || upStatement.getPolicies().size() != 1) {
			fail("Policy list must not be null and must contain one element");
		}
		
		if (upStatement.getPolicySets() == null || upStatement.getPolicySets().size() != 1) {
			fail("PolicySet list must not be  null and must be empty");
		}
		
		if (upStatement.getUniquePolicesList() == null || upStatement.getUniquePolicesList().size() != 2) {
			fail("Union of Policy and PolicySet list must not be null and must contain one element");
		}
	}
	
	private Policy buildPolicy() throws Exception {
		URI id = new URI("XACMLTest-0001");
		RuleCombiningAlgorithm rca = new DenyOverridesRuleAlg();

		EqualFunction ef = new EqualFunction(EqualFunction.NAME_STRING_EQUAL);
		URI sbjAttributeID = new URI("urn:oasis:names:tc:xacml:subject:subject-id");
		URI rscAttributeID = new URI("urn:oasis:names:tc:xacml:resource:resource-id");
		URI strAttributeID = new URI(StringAttribute.identifier);
		
		AttributeDesignator sad = new AttributeDesignator(AttributeDesignator.SUBJECT_TARGET, strAttributeID , sbjAttributeID, true);
		AttributeDesignator rad = new AttributeDesignator(AttributeDesignator.RESOURCE_TARGET, strAttributeID, rscAttributeID, true);

		StringAttribute sbjValue = new StringAttribute("MD5:key-hash-made-by-md5-algorithm");
		StringAttribute rscValue = new StringAttribute("UpLaserPrinter"); 
		
		TargetMatch sbjMatch = new TargetMatch(TargetMatch.SUBJECT, ef, sad, sbjValue); 
		TargetMatch rscMatch = new TargetMatch(TargetMatch.RESOURCE, ef, rad, rscValue);
		
		TargetMatchGroup subject = new TargetMatchGroup(Collections.singletonList(sbjMatch), TargetMatch.SUBJECT);
		TargetMatchGroup resource = new TargetMatchGroup(Collections.singletonList(rscMatch), TargetMatch.RESOURCE);
	
		TargetSection subjects = new TargetSection(Collections.singletonList(subject), TargetMatch.SUBJECT, PolicyMetaData.XACML_VERSION_2_0);
		TargetSection resources = new TargetSection(Collections.singletonList(resource), TargetMatch.RESOURCE, PolicyMetaData.XACML_VERSION_2_0);
		
		TargetSection emptyActions = new TargetSection(null, TargetMatch.ACTION, PolicyMetaData.XACML_VERSION_2_0);
		TargetSection emptyEnvironment = new TargetSection(null, TargetMatch.ENVIRONMENT, PolicyMetaData.XACML_VERSION_2_0);
		
		Target t = new Target(subjects, resources, emptyActions, emptyEnvironment);
	
		Rule rule = new Rule(new URI("RULE-0001"), Result.DECISION_PERMIT, null, null, (Condition) null);
				
		List<Rule> rules = new LinkedList<Rule>();
		rules.add(rule);
		
		return new Policy(id, rca, t, rules);
	}
	
	private PolicySet buildPolicySet() throws Exception {
		URI idSet = new URI("XACMLTest-0002");
		URI idPolicy = new URI("XACMLTest-0003");
		
		RuleCombiningAlgorithm rca = new DenyOverridesRuleAlg();
		PolicyCombiningAlgorithm pca = new FirstApplicablePolicyAlg();

		EqualFunction ef = new EqualFunction(EqualFunction.NAME_STRING_EQUAL);
		MatchFunction mf = new MatchFunction(MatchFunction.NAME_REGEXP_STRING_MATCH);
		
		URI sbjAttributeID = new URI("urn:oasis:names:tc:xacml:subject:subject-id");
		URI rscAttributeID = new URI("urn:oasis:names:tc:xacml:resource:file-id");
		URI actAttributeID = new URI("urn:oasis:names:tc:xacml:action:action-id");
		
		URI strAttributeID = new URI(StringAttribute.identifier);
		
		AttributeDesignator sad = new AttributeDesignator(AttributeDesignator.SUBJECT_TARGET, strAttributeID , sbjAttributeID, true);
		AttributeDesignator rad = new AttributeDesignator(AttributeDesignator.RESOURCE_TARGET, strAttributeID, rscAttributeID, true);
		AttributeDesignator aad = new AttributeDesignator(AttributeDesignator.ACTION_TARGET, strAttributeID, actAttributeID, true);

		StringAttribute sbjFirstValue = new StringAttribute("MD5:key-hash-made-by-md5-algorithm");
		StringAttribute sbjSecondValue = new StringAttribute("SHA1:key-hash-made-by-sha1-algorithm");
		
		StringAttribute actValue = new StringAttribute("Read");
		
		StringAttribute rscValue = new StringAttribute("C:\\\\File Condivisi\\\\Lavoro\\\\*"); 
		
		TargetMatch rscMatch = new TargetMatch(TargetMatch.RESOURCE, mf, rad, rscValue);
		
		TargetMatch sbjFirstMatch = new TargetMatch(TargetMatch.SUBJECT, ef, sad, sbjFirstValue); 
		TargetMatch sbjSecondMatch = new TargetMatch(TargetMatch.SUBJECT, ef, sad, sbjSecondValue); 
		
		TargetMatch actMatch = new TargetMatch(TargetMatch.ACTION, ef, aad, actValue);

		List<TargetMatch> subjectMatches = new ArrayList<TargetMatch>();
		subjectMatches.add(sbjFirstMatch);
		subjectMatches.add(sbjSecondMatch);
		
		TargetMatchGroup subject = new TargetMatchGroup(subjectMatches, TargetMatch.SUBJECT); 
		TargetSection subjects = new TargetSection(Collections.singletonList(subject), TargetMatch.SUBJECT, PolicyMetaData.XACML_VERSION_2_0);
		
		TargetMatchGroup action = new TargetMatchGroup(Collections.singletonList(actMatch), TargetMatch.ACTION);
		TargetSection actions = new TargetSection(Collections.singletonList(action), TargetMatch.ACTION, PolicyMetaData.XACML_VERSION_2_0);

		TargetSection emptyResources = new TargetSection(null, TargetMatch.RESOURCE, PolicyMetaData.XACML_VERSION_2_0);
		TargetSection emptyEnvironment = new TargetSection(null, TargetMatch.ENVIRONMENT, PolicyMetaData.XACML_VERSION_2_0);
	
		Rule rule = new Rule(new URI("RULE-0002"), Result.DECISION_PERMIT, null, null, (Condition) null);
				
		List<Rule> rules = new ArrayList<Rule>();
		rules.add(rule);

		Policy psPolicy = new Policy(idPolicy, rca, new Target(subjects, emptyResources, actions, emptyResources), rules );
		
		TargetMatchGroup resource = new TargetMatchGroup(Collections.singletonList(rscMatch), TargetMatch.RESOURCE );
		TargetSection resources = new TargetSection(Collections.singletonList(resource), TargetMatch.RESOURCE, PolicyMetaData.XACML_VERSION_2_0);

		TargetSection emptySubjects = new TargetSection(null, TargetMatch.SUBJECT, PolicyMetaData.XACML_VERSION_2_0);
	   TargetSection emptyActions = new TargetSection(null, TargetMatch.ACTION, PolicyMetaData.XACML_VERSION_2_0);

		List<Policy> policies = new ArrayList<Policy>();
		policies.add(psPolicy);

		return new PolicySet(idSet, pca, new Target(emptySubjects, resources, emptyActions, emptyEnvironment), policies);
	}
	
	private XMLObject buildObject(QName objName) {
		XMLObjectBuilder builder = Configuration.getBuilderFactory().getBuilder(objName);
		assertNotNull("Unable to retrive builder for " + objName.toString(), builder);
		
		XMLObject obj = builder.buildObject(objName);
		assertNotNull("Unable to build object " + objName.toString(), obj);
		
		return obj;
	}
	
	private Document getDOMFromFile(String fileName) throws Exception {
        BasicParserPool ppMgr = new BasicParserPool();
        return ppMgr.parse(XacmlddStatementTest.class.getResourceAsStream(fileName));
	}
	
   public static junit.framework.Test suite() {
      return new JUnit4TestAdapter(XacmlddStatementTest.class);
   }
}
