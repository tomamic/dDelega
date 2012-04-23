package it.unipr.ddelega.samldd;

import it.unipr.ddelega.samldd.name.SamlddNameCertificate;

import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;

public class ValidationContext {

	private SamlddCertificate currentCert;
	private DateTime validationInstant;
	private ValidationContextParamaters extraInfo;

	public ValidationContext()
	{
		validationInstant = new DateTime(DateTimeUtils.currentTimeMillis());
		extraInfo = null;
		currentCert = null;
	}

	public ValidationContext(DateTime instant, ValidationContextParamaters params, SamlddCertificate cert)
	{
		validationInstant = instant;
		extraInfo = params;
		//currentCert = cert;
	}

	public SamlddCertificate getCurrentCertificate()
	{
		return currentCert;
	}

	public void setCurrentCertificate( SamlddCertificate cert )
	{
		currentCert = cert;
	}

	public DateTime getValidationInstant()
	{
		return validationInstant;
	}

	public ValidationContextParamaters getExtraParameters()
	{
		return extraInfo;
	}

	public void setExtraParameters( ValidationContextParamaters cInfo )
	{
		extraInfo = cInfo;
	}
}
