package burp;

import com.securityriskadvisors.BigIPCookieScanner;
import com.securityriskadvisors.NetscalerCookieScanner;

import java.io.PrintWriter;

import java.lang.StringBuilder;

import java.util.ArrayList;
import java.util.List;

/**
 * A Burp Extension to find and decode loadbalancer cookies for BigIP and Netscaler
 *
 * @author Dan Herlihy
 * @version 1.0
 */
public class BurpExtender implements IBurpExtender
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        helpers = callbacks.getHelpers();
        
        callbacks.setExtensionName("Loadbalancer Cookie Scanner");
        callbacks.registerScannerCheck(new BigIPCookieScanner(this));
        callbacks.registerScannerCheck(new NetscalerCookieScanner(this));
    }

    /**
     *
     * @param response Byte array of an HTTP request or response
     * @param match Sequence of bytes to search the response for
     * @return List of int[] corresponding to start and end indices where the match sequence is found
     */
    public List<int[]> getMatches(byte[] response, byte[] match)
    {
        List<int[]> matches = new ArrayList<>();

        int start = 0;
        while (start < response.length)
        {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }
        
        return matches;
    }

    /**
     *
     * Helper function to left pad strings
     *
     * @param in Input string to be left padded
     * @param size The final size of the string after padding
     * @param pad The character to pad the string with
     * @return A left padded transformation of the input string
     */
    public static String leftPad(String in, int size, char pad){
        StringBuilder sb = new StringBuilder();
        for (int i = size - in.length(); i>0; i--) {
            sb.append(pad);
        }
        sb.append(in);
        return sb.toString();
    }

    /**
     *
     * @return Burp extender callbacks
     */
    public IBurpExtenderCallbacks getCallbacks(){
        return this.callbacks;
    }

    /**
     *
     * @return Burp extender helpers
     */
    public IExtensionHelpers getHelpers(){
        return this.helpers;
    }

    /**
     *
     * @return Stdout to Burp's extender output window
     */
    public PrintWriter getStdout() {
        return stdout;
    }
}
