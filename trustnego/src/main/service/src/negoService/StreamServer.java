package negoService;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import edu.uiuc.cs.TrustBuilder2.TrustBuilder2;
import edu.uiuc.cs.TrustBuilder2.messages.NegotiationTarget;
import edu.uiuc.cs.TrustBuilder2.messages.TrustMessage;
import edu.uiuc.cs.TrustBuilder2.util.StrategyUtils;

/**
 * Server for a test application that needs to incorporate trust negotiation
 * using TrustBuilder2.  This server accepts client connections over a TCP
 * socket.  All communication between the client and server takes place using
 * ObjectInputStreams and ObjectOutputStreams that wrap the input and output
 * streams associated with the socket.
 * 
 * @author Adam J. Lee (adamlee@cs.uiuc.edu)
 */
public class StreamServer
{
    /** The configuration file used by the server */
	public static final String SERVER_CONFIG = "C:\\Users\\filo\\eclipse_workspace\\STSNegotiation\\src\\config\\server\\server.properties";//"src/config/server/server.properties";
    
    /** The port that the server will listen on */
    public static final int PORT = 8083;
    
    /**
     * Main method, the server does it's bit in here...
     * 
     * @param args
     */
    public static void main(String[] args)
    {
        try{
        	System.out.println("Working directory Issuer: " + System.getProperty("user.dir"));
            // Create the server's TrustBuilder2 object using the configuration
            // file specified above.
            final TrustBuilder2 server = new TrustBuilder2(SERVER_CONFIG);
            
            // Set up a server socket and wait for the client's connection
            ServerSocket socket = new ServerSocket(PORT);
            System.out.println("***SERVER***---- Socket creata----");
            Socket clientSocket = socket.accept();
            
            // Once a client is connected, set up the input and output streams
            // used to communicate with the client.
            final ObjectInputStream input = 
		new ObjectInputStream(clientSocket.getInputStream());
            final ObjectOutputStream output = 
		new ObjectOutputStream(clientSocket.getOutputStream());
            TrustMessage inMsg, outMsg;
            
            // STEP 1:  Block until the client sends the first TrustMessage of
            // the negotiation.
            inMsg = (TrustMessage)input.readObject();
            
            // STEP 2:  This first message should contain an InitBrick that
            // specifies the client's portion of the configuration for this
            // session.  The server processes this InitMessage using the
            // processInitMessage() function of TrustBuilder2.  The result
            // of this function call is a result TrustMessage containing the
            // final configuration for this TrustNegotiation session.  This
            // can then be sent to the client.
            outMsg = server.processInitMessage(inMsg);
            System.out.println("\nSERVER Init msg:\n"+outMsg.toString());
            output.writeObject(outMsg);
            output.flush();
            
            // STEP 3:  Read in the first "real" message of the trust
            // negotiation from the client.  This message will specify a
            // negotiation "target" indicating the resource that the client
            // wishes to access.
            inMsg = (TrustMessage)input.readObject();
            final NegotiationTarget target = 
		StrategyUtils.getNegotiationTarget(inMsg);
            if(target == null){
                System.err.println("No negotiation target supplied");
                return;
            }
            
            // STEP 4:  This is the main loop of the negotiation.  At this
            // point, we process client inputs and send our responses out to
            // the client until one party decides that the negotiation is over.
            while(inMsg.getContinue() && outMsg.getContinue())
            {
                
            	// process incoming message and send response
                System.out.println("INCOMING: \n"+inMsg.toString());
            	outMsg = server.negotiate(inMsg);
            	System.out.println("OUTGOING: \n" + outMsg.toString());
                output.writeObject(outMsg);
                output.flush();
                
                // If the negotiation will proceed, get input
                if(outMsg.getContinue()){
                    inMsg = (TrustMessage)input.readObject();
                }
            }
            
            System.out.println(outMsg.toString());
            System.out.println("Negotiation completed.");
            
        }
        
        // Uh oh!
        catch(Exception e){
            System.err.println("Error!");
            e.printStackTrace(System.err);
        }
        
    }  //-- end main(String[])
    
}  //-- end class StreamServer