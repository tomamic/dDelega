package it.unipr.ddelega.samldd.cond;

public class ConditionNotValidException extends Exception {

	private static final long serialVersionUID = 5917683313463142841L;

	public ConditionNotValidException()
	{
		super();
	}

	public ConditionNotValidException( String message )
	{
		super( message );
	}

	public ConditionNotValidException( Throwable cause )
	{
		super( cause );
	}

	public ConditionNotValidException( String message, Throwable cause )
	{
		super( message, cause );
	}

}
