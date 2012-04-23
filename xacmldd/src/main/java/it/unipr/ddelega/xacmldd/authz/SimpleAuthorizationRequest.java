package it.unipr.ddelega.xacmldd.authz;

import it.unipr.ddelega.samldd.ThresholdSubject;
import it.unipr.ddelega.samldd.name.KeyRoles;
import it.unipr.ddelega.xacmldd.XacmlddHelper;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import com.sun.xacml.attr.StringAttribute;
import com.sun.xacml.ctx.Attribute;
import com.sun.xacml.ctx.RequestCtx;
import com.sun.xacml.ctx.Subject;


/**
 * A class rapresenting an access request performed by a principal.
 * 
 * @author darkman
 */
public class SimpleAuthorizationRequest  implements AuthorizationRequest {

	/**
	 * A class specifing the resource name and identifier
	 * @author darkman
	 *
	 */
	private class ResourceT {

		/** Default Constructor */
		ResourceT(String n, String id) {
			name = n;
			ID = id;
		}

		/** The resource name */
		public String name;
		/** The URI identifing the resource in the request */
		public String ID;
	}

	/** The subjects of the request */
	private List<String> subjects;
	/** The requested resources */ 
	private List<ResourceT> resources;
	/** The access level requested */
	private List<String> actions;
	/** The environment attributes */
	private List<String> environments;

	/** Default constructor. Builds an empty request */
	public SimpleAuthorizationRequest() {
		// Simple empty object
		subjects = new ArrayList<String>();
		resources = new ArrayList<ResourceT>();
		actions = new ArrayList<String>();
		environments = new ArrayList<String>();
	}

	/**
	 * Builds a new object with the given fields. All the parameters can be <code>null</code>. 
	 * 
	 * @param subject the principal requesting the access
	 * @param resource a resource on which the subject want to gain access
	 * @param action a type of access requested by the subject
	 * @param environment the environment of the request
	 */
	public SimpleAuthorizationRequest(String subject,
			String resource, String action, String environment) {
		// Create an empty request
		subjects = new ArrayList<String>();
		resources = new ArrayList<ResourceT>();
		actions = new ArrayList<String>();
		environments= new ArrayList<String>();

		// If the parameters are not null add them
		if (subject != null) {
			subjects.add(subject);
		}

		if (resource != null) {
			resources.add(new ResourceT(resource, SimpleAuthorizationPolicy.RESOURCE_ATTR_ID));
		}

		if (action != null) {			
			actions.add(action);
		}

		if (environment != null) {
			environments.add(environment);
		}
	}

	/**
	 * 
	 * @param roles all the roles possesed by a principal
	 * @param algo the hashing algorithm to rapresent the key
	 * @param resource the resource 
	 * @param action
	 * @param environment
	 * @throws NoSuchAlgorithmException
	 */
	public SimpleAuthorizationRequest(KeyRoles roles, String algo,
			String resource, String action, String environment)
					throws NoSuchAlgorithmException {
		subjects = new ArrayList<String>();
		resources = new ArrayList<ResourceT>();
		actions = new ArrayList<String>();

		subjects.add(XacmlddHelper.hashPublicKey(roles.getKey(), algo));
		subjects.addAll(roles.getRoleList());

		if (resource != null) {
			resources.add(new ResourceT(resource, SimpleAuthorizationPolicy.RESOURCE_ATTR_ID));
		}

		if (action != null) {			
			actions.add(action);
		}

		if (environment != null) {
			environments.add(environment);
		}
	}

	/**
	 * Adds the hash of a public key as the subject making this request. 
	 * 
	 * @param keyHash the hash of the public key of the principal.
	 * @return <code>true</code> if the subject was added. <code>false</code> if the given string is not a valid hash.
	 */
	public boolean addSubject(String keyHash) {
		if (XacmlddHelper.isKeyHash(keyHash)) {
			subjects.add(keyHash);
			return true;
		}
		return false;
	}

	/**
	 * Adds a qualified name as the subject making this request. 
	 * 
	 * @param qualifier the namespace qualifier.
	 * @param localName the local part of the name.
	 */
	public void addSubject(String qualifier, String localName) {
		subjects.add(XacmlddHelper.createFullyQualifiedName(qualifier, localName));
	}

	/**
	 *  Adds a threshold subject as the subject making this request.
	 * 
	 * @param th the threshold subject.
	 */
	public void addSubject(ThresholdSubject th) {
		subjects.addAll(th.getSubjects());
	}

	/**
	 * Adds all the roles belonging to a principal as the subject of this request.
	 * 
	 * @param roles the roles belonging to a public key.
	 * @param algo the algoithm used to compute the key hash.
	 * @throws NoSuchAlgorithmException when the hashing algorithm is wrong or unknown.
	 */
	public void addSubject(KeyRoles roles, String algo)
			throws NoSuchAlgorithmException {
		subjects.add(XacmlddHelper.hashPublicKey(roles.getKey(), algo));
		subjects.addAll(roles.getRoleList());
	}

	/**
	 * Adds a resource to this request.
	 * 
	 * @param resource the requested resources.
	 */
	public void addResource(String resource) {
		addResource(resource, SimpleAuthorizationPolicy.RESOURCE_ATTR_ID);
	}

	/**
	 * Adds a resource to this request.
	 * 
	 * @param resource the requested resources.
	 * @param identifier the URI that idenitifies the resource.
	 */
	public void addResource(String resource, String identifier) {
		resources.add(new ResourceT(resource, identifier));
	}

	/** 
	 * Adds the requested action to this object.
	 * 
	 * @param action the action the subject want to perform on the resource.
	 */
	public void addAction(String action) {
		actions.add(action);
	}

	public void addEnvironment(String environment) {
		environments.add(environment);
	}

	/** {@inheritDoc} */
	public RequestCtx getXACMLRequest() {
		try {
			// Build the subject with its attribute
			Set<Attribute> subjectAttributes = new HashSet<Attribute>();

			Iterator<String> iter = subjects.iterator();
			while (iter.hasNext()) {
				String sbj = iter.next();
				subjectAttributes.add(new Attribute(new URI(SimpleAuthorizationPolicy.SUBJECT_ATTR_ID), null, null, new StringAttribute(sbj))); 
			}

			Subject subject = new Subject(new URI(SimpleAuthorizationPolicy.ROLE_SUBJECT_GROUP), subjectAttributes);

			// Now build the resources attribute
			Set<Attribute> resourceAttributes = new HashSet<Attribute>();

			Iterator<ResourceT> rIter = resources.iterator();
			while (rIter.hasNext()) {
				ResourceT rsc = rIter.next();
				resourceAttributes.add(new Attribute(new URI(rsc.ID), null, null, new StringAttribute(rsc.name))); 		
			}

			// Add the actions
			Set<Attribute> actionAttributes = new HashSet<Attribute>();

			iter = actions.iterator();
			while (iter.hasNext()) {
				String act = iter.next();
				actionAttributes.add(new Attribute(new URI(SimpleAuthorizationPolicy.ACTION_ATTR_ID), null, null, new StringAttribute(act))); 		
			}

			// finally, add the environment
			Set<Attribute> environmentAttributes = new HashSet<Attribute>();

			iter = environments.iterator();
			while (iter.hasNext()) {
				String env = iter.next();
				environmentAttributes.add(new Attribute(new URI(SimpleAuthorizationPolicy.ENVIRONMENT_ATTR_ID), null, null, new StringAttribute(env))); 		
			}

			return new RequestCtx(Collections.singleton(subject), resourceAttributes, actionAttributes, environmentAttributes);
		} catch (URISyntaxException e) {
			// Should never happen
			throw new RuntimeException("FATAL: Unable to create URIs", e);
		}
	}
}
