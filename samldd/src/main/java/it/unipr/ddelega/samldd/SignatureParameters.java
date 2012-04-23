package it.unipr.ddelega.samldd;

/**
 * Specification of the parameters used to modify how SPKI certificates are signed. 
 * The possibile values are available in the class <code>XMLSignature</code> and
 * <code>Cononicalizer</code> from the Apache XML Security project.
 *  
 * @see SamlddNameCertificate#sign(java.security.KeyPair, SignatureParameters)
 *		   
 * @author Thomas Florio
 */
public class SignatureParameters {

	/** The signature signing algorithm */
	private String algorithm;
	/** The signature canonicalization algorithm */
	private String canonicalization;
	
	/**
	 * Default constructor. Initializes the parameters with the default values.<br>
	 * <br>
	 * Signing: RSA SHA1.<br>
	 * Canonicalization: C14N EXCL without comments.<br>
	 */
	public SignatureParameters()
	{
		algorithm = org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
		canonicalization = org.apache.xml.security.c14n.Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;
	}
	
	/**
	 * Initializes the object with the given algorithm and canonicalization.
	 *  
	 * @param newAlgorithm The signature algorithm.
	 * @param newCanonicalization The canonicalization algorithm.
	 * 
     * @see org.apache.xml.security.signature.XMLSignature
	 * @see org.apache.xml.security.c14n.Canonicalizer
	 */
	public SignatureParameters( String newAlgorithm, String newCanonicalization )
	{
		algorithm = newAlgorithm;
		canonicalization = newCanonicalization;
	}

	/**
	 * Gets the signing algorithm.
	 * 
	 * @return The current signing algorithm.
	 */
	public String getAlgorithm()
	{
		return algorithm;
	}
	
	/**
	 * Sets the algorithm used to generate the XML signature. 
	 * 
	 * @param newAlgorithm The signing algorithm. The valid values are supplied by the class <code>org.apache.xml.security.signature.XMLSignature</code>.
	 * 
	 * @see org.apache.xml.security.signature.XMLSignature
	 */
	public void setAlgorithm( String newAlgorithm )
	{
		 algorithm = newAlgorithm;
	}

	/**
	 * Gets the canonicalization algorithm.
	 * 
	 * @return the current canonicalization algorithm
	 */
	public String getCanonicalization()
	{
		 return canonicalization;
	}
	
	/**
	 * Sets the canonicalization algorithm used for the signature.
	 * 
	 * @param newCanonicalization The canonicalization algorithm. The valid values are supplied by the class <code>org.apache.xml.security.c14n.Canonicalizer</code>.
	 * 
	 * @see org.apache.xml.security.c14n.Canonicalizer
	 */
	public void setCanonicalization( String newCanonicalization )
	{
		canonicalization = newCanonicalization;
	}
}
