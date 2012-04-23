package it.unipr.ddelega.samldd.cond;

public class ConditionNotPresentException extends Exception {
	
	private static final long serialVersionUID = -7116686623962186984L;

	public ConditionNotPresentException()
	{
		super();
	}

	public ConditionNotPresentException( String message )
	{
		super( message );
	}

	public ConditionNotPresentException( Throwable cause )
	{
		super( cause );
	}

	public ConditionNotPresentException( String message, Throwable cause )
	{
		super( message, cause );
	}
}
