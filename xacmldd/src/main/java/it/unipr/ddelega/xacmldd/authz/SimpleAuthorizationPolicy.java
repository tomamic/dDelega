package it.unipr.ddelega.xacmldd.authz;

import it.unipr.ddelega.xacmldd.ThresholdSubject;
import it.unipr.ddelega.xacmldd.XacmlddHelper;

import java.lang.reflect.Field;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.sun.xacml.Policy;
import com.sun.xacml.PolicyMetaData;
import com.sun.xacml.Rule;
import com.sun.xacml.Target;
import com.sun.xacml.TargetMatch;
import com.sun.xacml.TargetMatchGroup;
import com.sun.xacml.TargetSection;
import com.sun.xacml.UnknownIdentifierException;
import com.sun.xacml.attr.AttributeDesignator;
import com.sun.xacml.attr.AttributeValue;
import com.sun.xacml.attr.StringAttribute;
import com.sun.xacml.combine.DenyOverridesRuleAlg;
import com.sun.xacml.combine.RuleCombiningAlgorithm;
import com.sun.xacml.cond.Condition;
import com.sun.xacml.cond.EqualFunction;
import com.sun.xacml.cond.Evaluatable;
import com.sun.xacml.cond.Function;
import com.sun.xacml.cond.FunctionFactory;
import com.sun.xacml.cond.FunctionTypeException;
import com.sun.xacml.cond.StandardFunctionFactory;


public class SimpleAuthorizationPolicy implements AuthorizationPolicy {

	/** The attribute id looked for the subjects */
	public static String SUBJECT_ATTR_ID = "urn:oasis:names:tc:xacml:1.0:subject:subject-id"; 
	/** The attribute id looked for resources */
	public static String RESOURCE_ATTR_ID = "urn:oasis:names:tc:xacml:1.0:resource:resource-id";
	/** The attribute id looked for actions */
	public static String ACTION_ATTR_ID = "urn:oasis:names:tc:xacml:1.0:action:action-id";
	/** The attribute id looked for environment */
	public static final String ENVIRONMENT_ATTR_ID = "urn:oasis:names:tc:xacml:1.0:environment:environment-id";


	/** The default subject group for Role Policy subjects */
	public static String ROLE_SUBJECT_GROUP = "org:spki:role:subject-group";

	private static TargetSection emptySubjects = new TargetSection(null, TargetMatch.SUBJECT, PolicyMetaData.XACML_VERSION_2_0);
	private static TargetSection emptyResources = new TargetSection(null, TargetMatch.RESOURCE, PolicyMetaData.XACML_VERSION_2_0);
	private static TargetSection emptyActions = new TargetSection(null, TargetMatch.ACTION, PolicyMetaData.XACML_VERSION_2_0);
	private static TargetSection emptyEnvironment = new TargetSection(null, TargetMatch.ENVIRONMENT, PolicyMetaData.XACML_VERSION_2_0);

	/** Permit the execution of the specified <i>action</i> on a given <i>resource</i> by the <i>subject</i> */
	public static int EFFECT_PERMIT = 0;

	/** Deny the execution of the specified <i>action</i> on a given <i>resource</i> by the <i>subject</i> */
	public static int EFFECT_DENY = 1;

	private Policy xPolicy;
	private String policyID;

	/** Default constructor. */
	public SimpleAuthorizationPolicy() {
		// Get a random identifier
		policyID = XacmlddHelper.getRandomIdentifier();

		// Create an empty policy
		rebuildCurrentPolicy(null, null, null);
	}

	/**
	 * Creates an empty policy with the given identifier.
	 * 
	 * @param identifier the identifier of this policy
	 */
	public SimpleAuthorizationPolicy(String identifier) {
		// Set the identfier
		policyID = identifier;

		// Create an empty policy
		rebuildCurrentPolicy(null, null, null);
	}

	/**
	 * Creates the role policy from an XACML Policy.
	 * @param policy the SunXACML Policy object.
	 */
	public SimpleAuthorizationPolicy(Policy policy) {
		xPolicy = policy;
	}

	/**
	 * Add a subject to this authorization policy. The subject must be a fulli qualified name.
	 * 
	 * @param nameQualifier the namespace qualifier.
	 * @param localName the local part of the name.
	 * @throws URISyntaxException 
	 */
	public void addSubject(String nameQualifier, String localName) {
		// Create the function
		Function equalFunc = new EqualFunction(EqualFunction.NAME_STRING_EQUAL);

		// Create the evaluetor
		AttributeDesignator eval;
		try {
			eval = new AttributeDesignator(AttributeDesignator.SUBJECT_TARGET, new URI(StringAttribute.identifier), new URI(SUBJECT_ATTR_ID), false);
			eval.setSubjectCategory(new URI(ROLE_SUBJECT_GROUP));
		} catch(URISyntaxException e) {
			// Should not happen
			throw new RuntimeException("Unable to build AttributeDesignator URI");
		}

		// Create the attribute value
		String qname = XacmlddHelper.createFullyQualifiedName(nameQualifier, localName);
		AttributeValue value = new StringAttribute(qname);

		TargetMatch subjMatch = new TargetMatch(TargetMatch.SUBJECT, equalFunc, eval, value );

		TargetMatchGroup subject = new TargetMatchGroup(Collections.singletonList(subjMatch), TargetMatch.SUBJECT);

		TargetSection subjects = new TargetSection(Collections.singletonList(subject), TargetMatch.SUBJECT, PolicyMetaData.XACML_VERSION_2_0);

		// Finally build the target...
		Target target = new Target(subjects, emptyResources, emptyActions, emptyEnvironment );
		// ...and rebuild the policy.
		rebuildCurrentPolicy(null, target, null);
	}

	/**
	 * Adds a key hash subject to the policy. The key hash must be generated using {@link XacmlddHelper}.
	 * 
	 * @param subjectKeyHash the hash of the subject's public key.
	 */
	public void addSubject(String subjectKeyHash ) {
		// Create the function
		Function equalFunc = new EqualFunction(EqualFunction.NAME_STRING_EQUAL);

		// Create the evaluetor
		AttributeDesignator eval;
		try {
			eval = new AttributeDesignator(AttributeDesignator.SUBJECT_TARGET, new URI(StringAttribute.identifier), new URI(SUBJECT_ATTR_ID), false);
			eval.setSubjectCategory(new URI(ROLE_SUBJECT_GROUP));
		} catch(URISyntaxException e) {
			// Should not happen
			throw new RuntimeException("Unable to build AttributeDesignator URI");
		}

		// Create the attribute value
		AttributeValue value = new StringAttribute(subjectKeyHash);
		TargetMatch subjMatch = new TargetMatch(TargetMatch.SUBJECT, equalFunc, eval, value );

		TargetMatchGroup subject = new TargetMatchGroup(Collections.singletonList(subjMatch), TargetMatch.SUBJECT);

		TargetSection subjects = new TargetSection(Collections.singletonList(subject), TargetMatch.SUBJECT, PolicyMetaData.XACML_VERSION_2_0);

		// Finally build the target...
		Target target = new Target(subjects, emptyResources, emptyActions, emptyEnvironment );
		// ...and rebuild the policy.
		rebuildCurrentPolicy(null, target, null);

	}

	/**
	 * Adds a threshold subject to this autorization policy. 
	 * 
	 * @param thSubject the threshold subject to be added
	 * @see ThresholdSubject
	 */
	public void addSubject(ThresholdSubject thSubject) {
		// Create the new subjects list
		TargetSection subjects;

		// Create the basic objects to build a TargetMatch
		Function equalFunc = new EqualFunction(EqualFunction.NAME_STRING_EQUAL);
		AttributeDesignator eval;
		try { 
			eval = new AttributeDesignator(AttributeDesignator.SUBJECT_TARGET, new URI(StringAttribute.identifier), new URI(SUBJECT_ATTR_ID), false);
			eval.setSubjectCategory(new URI(ROLE_SUBJECT_GROUP));
		} catch(URISyntaxException e) {
			// Should never happen
			throw new RuntimeException("Unable to build URI");
		}		

		// Check the threshold type...
		if (thSubject.getThresholdType() == ThresholdSubject.N_OVER_N) {
			// We need to create one subject with n <SubjectMatch>
			List<TargetMatch> matches = new ArrayList<TargetMatch>();

			Iterator<String> iter = thSubject.getSubjects().iterator();
			while (iter.hasNext()) {
				// Get the subject from the list
				String stringValue = iter.next();
				AttributeValue value = new StringAttribute(stringValue);
				// Create a new YargetMatch
				matches.add(new TargetMatch(TargetMatch.SUBJECT, equalFunc, eval, value ));
			}

			TargetMatchGroup subject = new TargetMatchGroup(matches, TargetMatch.SUBJECT);
			// Add the <Subject> to the <Subjects>
			subjects = new TargetSection(Collections.singletonList(subject), TargetMatch.SUBJECT, PolicyMetaData.XACML_VERSION_2_0);
		} else {
			// We need to create n subjects that contains one SubjectMatch
			List<TargetMatchGroup> subject = new ArrayList<TargetMatchGroup>();  
			Iterator<String> iter = thSubject.getSubjects().iterator();
			while (iter.hasNext()) {
				// Get the subject from the list
				String stringValue = iter.next();
				AttributeValue value = new StringAttribute(stringValue);
				// Create a new YargetMatch
				TargetMatch subjMatch = new TargetMatch(TargetMatch.SUBJECT, equalFunc, eval, value );
				// And add it to the list of subjects
				subject.add(new TargetMatchGroup(Collections.singletonList(subjMatch), TargetMatch.SUBJECT));
			}

			// Finally add this subject to the subjects section
			subjects = new TargetSection(subject, TargetMatch.SUBJECT, PolicyMetaData.XACML_VERSION_2_0);

		}

		// Now build the target and rebuild the policy
		Target target = new Target(subjects, emptyResources, emptyActions, emptyEnvironment);
		rebuildCurrentPolicy(null, target, null);

	}

	/**
	 * Returns all the single subjects in this policy. Threshold subject <b>are not included</b> in this list. 
	 * 
	 * @return an <b>immutable</b> list of subjects of this policy.
	 * @see SimpleAuthorizationPolicy#getThresholdSubjects()
	 */
	public List<String> getSubjects() {
		List<String> subjects = new ArrayList<String>();

		// Get the list of <Subjects> objects
		List sbj = xPolicy.getTarget().getSubjectsSection().getMatchGroups();

		Iterator iter = sbj.iterator();
		while (iter.hasNext()) {
			TargetMatchGroup targets = (TargetMatchGroup) iter.next();

			// If there are more than one targetmatches it's a threshold subject
			List matches = getMatches(targets);
			if (matches.size() == 1) {
				// Extract the string value from this <Subject> object
				TargetMatch sbjMatch = (TargetMatch) matches.get(0);
				StringAttribute strAttr = (StringAttribute) sbjMatch.getMatchValue();
				subjects.add(strAttr.getValue());
			}
		}

		return Collections.unmodifiableList(subjects);
	}

	/**
	 * Returns all the threshold subjects in this policy. Single subject <b>are not included</b> in this list. 
	 * 
	 * @return an <b>immutable</b> list of threshold subjects of this policy.
	 * @see SimpleAuthorizationPolicy#getSubjects()
	 */
	public List<ThresholdSubject> getThresholdSubjects() {
		List<ThresholdSubject> subjects = new ArrayList<ThresholdSubject>();

		// Get the list of <Subject> objects
		List sbj = xPolicy.getTarget().getSubjectsSection().getMatchGroups();

		Iterator iter = sbj.iterator();
		while (iter.hasNext()) {
			TargetMatchGroup targets = (TargetMatchGroup) iter.next();
			// If size it's only one it's a single subject and so ignore it
			List matches = getMatches(targets);
			if (matches.size() > 1) {
				Iterator matchIterator = matches.iterator();
				// Extract all the matches from this <Subject> object
				List<String> strSubjects = new ArrayList<String>(); 
				while (matchIterator.hasNext()) {
					TargetMatch sbjMatch = (TargetMatch) matchIterator.next();
					StringAttribute strAttr = (StringAttribute) sbjMatch.getMatchValue();
					strSubjects.add(strAttr.getValue());
				}

				// Add the threshold subject to the return list
				subjects.add(new ThresholdSubject(strSubjects, ThresholdSubject.N_OVER_N));
			}
		}

		return Collections.unmodifiableList(subjects);
	}

	/**
	 * Adds a resource target to this policy.
	 * 
	 * @param resourceName a string rapresenting the resource.
	 * @throws FunctionTypeException when the requested function is abstract.
	 * @throws UnknownIdentifierException when the identifier is wrong or unknown.
	 */
	public void addResource(String resourceName)
			throws UnknownIdentifierException, FunctionTypeException {
		addResource(resourceName, EqualFunction.NAME_STRING_EQUAL, RESOURCE_ATTR_ID);
	}

	/**
	 * Adds a resource target to this policy specifying the function for the match. 
	 * 
	 * @param resourceName a string rapresenting the resource.
	 * @param functionName the URN identifier of the function to be used to match the resource value.
	 * @throws FunctionTypeException when the requested function is abstract.
	 * @throws UnknownIdentifierException when the identifier is wrong or unknown.
	 */
	public void addResource(String resourceName, String functionName)
			throws UnknownIdentifierException, FunctionTypeException {
		addResource(resourceName, functionName, RESOURCE_ATTR_ID);
	}

	/**
	 * Adds a resource target to this policy specifying the function for the match and the resource identifier in the request. 
	 * 
	 * @param resourceName a string rapresenting the resource.
	 * @param functionName the URN identifier of the function to be used to match the resource value.
	 * @param resourceID the URI that identifies the resource in the request 
	 * @throws FunctionTypeException when the requested function is abstract.
	 * @throws UnknownIdentifierException when the identifier is wrong or unknown.
	 */
	public void addResource(String resourceName, String functionName, String resourceID)
			throws UnknownIdentifierException, FunctionTypeException {
		// Get the function factory
		FunctionFactory factory = StandardFunctionFactory.getTargetInstance();
		// Create the function
		Function func = factory.createFunction(functionName);

		// Create the evaluetor
		Evaluatable eval;
		try {
			eval = new AttributeDesignator(AttributeDesignator.RESOURCE_TARGET, new URI(StringAttribute.identifier), new URI(resourceID), false);
		} catch(URISyntaxException e) {
			// Should not happen
			throw new RuntimeException("Unable to build Attribute designator URI");
		}

		// Create the attribute value
		AttributeValue value = new StringAttribute(resourceName);
		TargetMatch rscMatch = new TargetMatch(TargetMatch.RESOURCE, func, eval, value );

		// Create the <Resource> object.
		TargetMatchGroup resource = new TargetMatchGroup(Collections.singletonList(rscMatch), TargetMatch.RESOURCE );

		// Create the <Resources> object.
		TargetSection resources = new TargetSection(Collections.singletonList(resource), TargetMatch.RESOURCE, PolicyMetaData.XACML_VERSION_2_0);

		// Finally build the target...
		Target target = new Target(emptySubjects, resources, emptyActions, emptyResources);
		// ...and rebuild the policy.
		rebuildCurrentPolicy(null, target, null);
	}

	/** 
	 * Gets all the resources in this policy.
	 * 
	 * @return the <b>immutable</b> list of actions.
	 */
	public List<String> getResources() {
		List<String> resources = new ArrayList<String>();

		// Get the list of <Resources> objects
		List target = xPolicy.getTarget().getResourcesSection().getMatchGroups();

		Iterator iter = target.iterator();
		while (iter.hasNext()) {
			// Extract the string value from this <Resource> object
			TargetMatchGroup rsc = (TargetMatchGroup) iter.next();
			TargetMatch rscMatch = (TargetMatch) getMatches(rsc).get(0);
			StringAttribute strAttr = (StringAttribute) rscMatch.getMatchValue();
			resources.add(strAttr.getValue());
		}

		return Collections.unmodifiableList(resources);
	}

	/**
	 * Adds an action target to the policy.
	 * 
	 * @param actionName a strin rapresenting the action.
	 * @throws CertificateException when an error occours adding the action.
	 */
	public void addAction(String actionName) {
		// Create the function
		Function equalFunc = new EqualFunction(EqualFunction.NAME_STRING_EQUAL);

		// Create the evaluetor
		Evaluatable eval;
		try {
			eval = new AttributeDesignator(AttributeDesignator.ACTION_TARGET, new URI(StringAttribute.identifier), new URI(ACTION_ATTR_ID), false);
		} catch(URISyntaxException e) {
			// Should not happen
			throw new RuntimeException("Unable to build Attribute designator URI");
		}


		// Create the attribute value
		AttributeValue value = new StringAttribute(actionName);
		TargetMatch actMatch = new TargetMatch(TargetMatch.ACTION, equalFunc, eval, value );

		// Create the <Subject> object.
		TargetMatchGroup action = new TargetMatchGroup(Collections.singletonList(actMatch), TargetMatch.ACTION );

		// Create the <Subjects> object.
		TargetSection actions = new TargetSection(Collections.singletonList(action), TargetMatch.ACTION, PolicyMetaData.XACML_VERSION_2_0 );

		// Finally build the target...
		Target target = new Target(emptySubjects, emptyResources, actions, emptyEnvironment);
		// ...and rebuild the policy.
		rebuildCurrentPolicy(null, target, null);
	}

	/** 
	 * Gets all the actions in this policy.
	 * 
	 * @return the <b>immutable</b> list of actions.
	 */
	public List<String> getActions() {
		List<String> actions = new ArrayList<String>();

		// Get the list of <Actions> objects
		List action = xPolicy.getTarget().getActionsSection().getMatchGroups();

		Iterator iter = action.iterator();
		while (iter.hasNext()) {
			// Extract the string value from this <Action> object
			TargetMatchGroup act = (TargetMatchGroup) iter.next();
			TargetMatch actMatch = (TargetMatch) getMatches(act).get(0);
			StringAttribute strAttr = (StringAttribute) actMatch.getMatchValue();
			actions.add(strAttr.getValue());
		}

		return Collections.unmodifiableList(actions);
	}

	/**
	 * Set the effect (allow or deny) of this role policy. 
	 * 
	 * @param effect it can be {@link #EFFECT_PERMIT} or  {@link #EFFECT_DENY}
	 */
	public void setEffect(int effect ) {
		try {
			setEffect(effect, null, "policy:rule:" + XacmlddHelper.getRandomIdentifier());
		} catch (URISyntaxException e) {
			// Should not happen
			throw new RuntimeException("Unable to build random effect rule URI");
		}
	}

	/**
	 * Set the effect (allow or deny) of this role policy adding a descriptive text. 
	 *  
	 * @param effect it can be {@link #EFFECT_PERMIT} or  {@link #EFFECT_DENY}
	 * @param description a freeform string description of this rule
	 * @throws URISyntaxException when the identifier is wrong
	 */
	public void setEffect(int effect, String description) {
		try {
			setEffect(effect, description, "policy:rule:" + XacmlddHelper.getRandomIdentifier());
		} catch(URISyntaxException e) {
			// Should not happen
			throw new RuntimeException("Unable to build random effect rule URI");
		}
	}

	/**
	 * Set the effect (allow or deny) of this role policy adding a descriptive text and a specific rule identifier. 
	 *  
	 * @param effect it can be {@link #EFFECT_PERMIT} or  {@link #EFFECT_DENY}
	 * @param description a freeform string description of this rule
	 * @param ruleID the identifier of this policy rule.
	 * @throws URISyntaxException when the identifier is wrong
	 */
	public void setEffect(int effect, String description, String ruleID)
			throws URISyntaxException {
		URI rId = new URI(ruleID );

		// Create the <rule> and the <rules> list
		Rule newRule = new Rule(rId, effect, description, null, (Condition) null );
		List<Rule> rules = new ArrayList<Rule>();
		rules.add(newRule);

		// Rebuild the policy and merge the new rule
		rebuildCurrentPolicy(null, null, rules);
	}

	/**
	 * Return the effect of this role policy.
	 * 
	 * @return {@link #EFFECT_PERMIT} if the specified actions are allowed, {@link #EFFECT_DENY} if not.
	 * @throws CertificateException when no rule is found inside the policy.
	 */
	public int getEffect() throws CertificateException {
		List rules = xPolicy.getChildren();
		if ( rules.size() != 1 ) {
			// Something wrong
			throw new CertificateException("No rule found in certificate");
		}

		Rule r = (Rule) rules.get(0);
		return r.getEffect();
	}

	/** {@inheritDoc} */
	public Policy getXACMLPolicy() {
		if (xPolicy.getChildren() != null && xPolicy.getChildren().size() > 0) {
			return xPolicy;
		}
		return null;
	}

	/**
	 * Rebuild the policy that is currently on editing adding the given parameters. This is needed because SunXACML objects are 
	 * immutable. If some of the given parameters are <code>null</code> the previous (or the default) vales are used. 
	 * 
	 * @param combiningAlgo the new combining algorithm
	 * @param target the new target
	 * @param rules the new rules
	 */
	private void rebuildCurrentPolicy(RuleCombiningAlgorithm combiningAlgo, Target target, List<Rule>  rules) {
		URI nID;
		RuleCombiningAlgorithm nAlgo;
		Target nTarget;
		List<Rule> nRules;

		// Create the identifier
		try {
			nID = new URI("policy:" + policyID );
		} catch(URISyntaxException e) {
			// Should not happen
			throw new RuntimeException("Unable to create URI");
		}

		// Fill the combining algorithm
		if(combiningAlgo != null) {
			nAlgo = combiningAlgo;
		} else if(xPolicy != null) {
			nAlgo = (RuleCombiningAlgorithm) xPolicy.getCombiningAlg();
		} else {
			nAlgo = new DenyOverridesRuleAlg();
		}

		// Merge the new targets with the ones in the policy
		if (xPolicy != null) {
			nTarget = mergeTargets(target, xPolicy.getTarget());
		} else {
			nTarget = target;
		}

		// Set the new rule
		nRules = rules;

		// Create the new policy
		Policy nPolicy;
		if (nRules != null) {
			nPolicy = new Policy(nID, nAlgo, nTarget, nRules);
		} else {
			nPolicy = new Policy(nID, nAlgo, nTarget);
		}


		// Set the new policy
		xPolicy = nPolicy;
	}

	/** 
	 * Merge two <code>Target</code> objects into a new one.
	 * 
	 * @param one the first target.
	 * @param two the second target.
	 * @return the new merged <code>Target</code>.
	 */
	@SuppressWarnings("unchecked")
	private Target mergeTargets(Target one, Target two) {
		if (one == null && two == null) {
			return new Target(emptySubjects, emptyResources, emptyActions, emptyEnvironment);
		}

		TargetSection sbjOne = null, sbjTwo = null;
		TargetSection rscOne = null, rscTwo = null;
		TargetSection actOne = null, actTwo = null;
		TargetSection envOne = null, envTwo = null;

		// Get All component from the two target, if they are present.
		if (one != null) {
			sbjOne = one.getSubjectsSection();
			rscOne = one.getResourcesSection();
			actOne = one.getActionsSection();
			envOne = one.getEnvironmentsSection();
		}

		if (two != null) {
			sbjTwo = two.getSubjectsSection();
			rscTwo = two.getResourcesSection();
			actTwo = two.getActionsSection();
			envTwo = two.getEnvironmentsSection();
		}

		// Merge the list of subjects
		List<TargetMatchGroup> subjects = new ArrayList<TargetMatchGroup>();
		if (sbjTwo != null) {
			subjects.addAll(sbjTwo.getMatchGroups());
		}
		if (sbjOne != null) {
			subjects.addAll(sbjOne.getMatchGroups());
		}

		TargetSection mergedSubject;
		// If the size is zero, set the list to empySubejct
		if (subjects.size() > 0) {
			mergedSubject = new TargetSection(subjects, TargetMatch.SUBJECT, PolicyMetaData.XACML_VERSION_2_0);
		} else {
			mergedSubject = emptySubjects;
		}

		// Merge the list of resources
		List<TargetMatchGroup> resources = new ArrayList<TargetMatchGroup>();
		if (rscTwo != null) {
			resources.addAll(rscTwo.getMatchGroups());
		}
		if (rscOne != null) {
			resources.addAll(rscOne.getMatchGroups());
		}

		TargetSection mergedResources;
		// If the size is zero, set it to empyResources
		if (resources.size() > 0) {
			mergedResources = new TargetSection(resources,  TargetMatch.RESOURCE, PolicyMetaData.XACML_VERSION_2_0);
		} else {
			mergedResources = emptyResources;
		}

		// Merge the list of actions
		List<TargetMatchGroup> actions = new ArrayList();
		if (actTwo != null) {
			actions.addAll(actTwo.getMatchGroups());
		}
		if (actOne != null) {
			actions.addAll(actOne.getMatchGroups());
		}

		TargetSection mergedActions;
		// If the size is zero, put it to emptyActions
		if (actions.size() > 0) {
			mergedActions = new TargetSection(actions, TargetMatch.ACTION, PolicyMetaData.XACML_VERSION_2_0);
		} else {
			mergedActions = emptyActions;
		}

		// Merge the list of enviroments
		List<TargetMatchGroup> enviroments = new ArrayList<TargetMatchGroup>();
		if (envOne != null) {
			enviroments.addAll(envOne.getMatchGroups());
		}
		if (envTwo != null) {
			enviroments.addAll(envTwo.getMatchGroups());
		}

		TargetSection mergedEnvironments;
		// If the size is zero, put it to emptyEnvironment
		if (enviroments.size() > 0) {
			mergedEnvironments = new TargetSection(enviroments, TargetMatch.ENVIRONMENT, PolicyMetaData.XACML_VERSION_2_0);
		} else {
			mergedEnvironments = emptyEnvironment;
		}

		// Build and return the new object
		return new Target(mergedSubject, mergedResources, mergedActions, mergedEnvironments);
	}

	public static List getMatches(TargetMatchGroup matchList) {
		List matches = null;
		try {
			Field fields[] = TargetMatchGroup.class.getDeclaredFields();
			for (int i = 0; i < fields.length; i++) {
				if (fields[i].getName().equals("matches")) {
					fields[i].setAccessible(true);
					matches = (List) fields[i].get(matchList);
				}
			}
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		} catch (SecurityException e) {
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		}/* catch (NoSuchFieldException e) {
			e.printStackTrace();
		}*/
		return matches;
	}


}
