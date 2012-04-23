package it.unipr.ddelega.xacmldd.authz;

import java.util.List;

import com.sun.xacml.ctx.Result;
import com.sun.xacml.ctx.Status;

public class AuthorizationResponse {

	/** The decision to permit the request  */
	public static final int DECISION_PERMIT = 0;
	/** The decision to deny the request */
	public static final int DECISION_DENY = 1;
	/** The decision that a decision about the request cannot be made */
	public static final int DECISION_INDETERMINATE = 2;
	/** The decision that nothing applied to the request  */
	public static final int DECISION_NOT_APPLICABLE = 3;

	private String resource;
	private int decision;
	private List<String>  statusCodes;

	/** Default constructor.
	 * 
	 * @param xResult
	 */
	@SuppressWarnings("unchecked")
	protected AuthorizationResponse( Result xResult ) {
		resource = xResult.getResource();
		decision = xResult.getDecision();

		statusCodes = xResult.getStatus().getCode();
	}

	/**
	 * Gets the authorization decision value.
	 * 
	 * @return one of the <i>DECISION_*</i> values;
	 */
	public int getDecision() {
		return decision;
	}

	/**
	 * Gets the resource this authorization decision refers to.
	 * 
	 * @return the name of the resource.
	 */
	public String getResource() {
		return resource;
	}

	/** 
	 * Gets the status codes of the evaluations process.
	 * 
	 * @return a list of status codes. For the status code value refer to {@link Status}.
	 */
	public List<String> getStatusCodes() {
		return statusCodes;
	}
}
