package it.unipr.ddelega.xacmldd;

import java.util.List;

import org.opensaml.saml2.core.Statement;

import com.sun.xacml.AbstractPolicy;
import com.sun.xacml.Policy;
import com.sun.xacml.PolicySet;

import javax.xml.namespace.QName;

/**
 * The statement XACMLPolicyStatement as described in the SAML XACML profile.  
 * 
 * @author Thomas Florio
 *
 */
public interface XacmlddStatement extends Statement {

    /** Element local name */
    public final static String DEFAULT_ELEMENT_LOCAL_NAME = "XACMLPolicyStatement";
    
    /** Default element name */
    public final static QName DEFAULT_ELEMENT_NAME = new QName( XacmlddConstants.XACML_SAML_NS, DEFAULT_ELEMENT_LOCAL_NAME, XacmlddConstants.XACML_SAML_PREFIX );
    
    /** Local name of the XSI type */
    public final static String TYPE_LOCAL_NAME = "XACMLPolicyStatementType"; 
        
    /** QName of the XSI type */
    public final static QName TYPE_NAME = new QName( XacmlddConstants.XACML_SAML_NS, TYPE_LOCAL_NAME, XacmlddConstants.XACML_SAML_PREFIX );
    
    /** Gets the policies contained in this statement 
     * 
     * @return the list of XACML policies from the PDP.
     * 
     * @see com.sun.xacml.Policy
     */
    public List<Policy> getPolicies();
    
    /**
     * Gets the all the PolicySet embedded in this Policy Statement.
     * 
     * @return the list of XACML set of policy from the PDP.
     * 
     * @see com.sun.xacml.PolicySet
     */
    public List<PolicySet> getPolicySets();
    
    /**
     * Gets an immutable list of that contains AbstractPolicy, that can rapresent Policy and PolicySet. 
     * In this way, all Policy and PolicySet objects from the statement are manageble using a single list.
     *  
     * @return a <b>immutable<b> AbstractPolicy list
     * @see AbstractPolicy
     */ 
    public List<AbstractPolicy> getUniquePolicesList();

}
