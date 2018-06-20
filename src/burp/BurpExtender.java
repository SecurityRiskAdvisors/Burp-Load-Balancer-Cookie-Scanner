package burp;

import com.securityriskadvisors.BigIPCookieScanner;

import java.io.PrintWriter;

import java.lang.Integer;
import java.lang.Long;
import java.lang.StringBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.*;

public class BurpExtender implements IBurpExtender
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        callbacks.setExtensionName("BigIP Cookie Scanner");
        callbacks.registerScannerCheck(new BigIPCookieScanner(this));
    }
    
    // helper method to search a response for occurrences of a literal match string
    // and return a list of start/end offsets
    public List<int[]> getMatches(byte[] response, byte[] match)
    {
        List<int[]> matches = new ArrayList<int[]>();

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

    public IBurpExtenderCallbacks getCallbacks(){
        return this.callbacks;
    }

    public IExtensionHelpers getHelpers(){
        return this.helpers;
    }
}
