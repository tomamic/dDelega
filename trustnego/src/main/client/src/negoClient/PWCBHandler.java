package negoClient;

import org.apache.ws.security.WSPasswordCallback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import java.io.IOException;

public class PWCBHandler implements CallbackHandler {

    public void handle(Callback[] callbacks) throws IOException,
            UnsupportedCallbackException {
        /*for (int i = 0; i < callbacks.length; i++) {
            WSPasswordCallback pwcb = (WSPasswordCallback)callbacks[i];
			String id = pwcb.getIdentifer();
            if("client".equals(id)) {
                pwcb.setPassword("apache");
            } else if("service".equals(id)) {
                pwcb.setPassword("apache");
            }
        }*/
        
        for (Callback callback : callbacks) {
    		
    		//When the server side need to authenticate the user
    		WSPasswordCallback pwcb = (WSPasswordCallback)callback;
    		
    		if("client".equals(pwcb.getIdentifier()))
    			pwcb.setPassword("apache");
    		else if ( "service".equals(pwcb.getIdentifier())) {
                //If authentication successful, simply return
    			pwcb.setPassword("apache");
    		} 
    		else {
    		throw new UnsupportedCallbackException(callback, "check failed");
    		}
    	} 
    }

}
