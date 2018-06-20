package burp;

import java.io.PrintWriter;

import java.lang.Integer;
import java.lang.Long;
import java.lang.StringBuilder;

import java.net.URL;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.*;

public class BurpExtender implements IBurpExtender, IScannerCheck
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;

    // RegEx pattern for finding BigIP style cookies
    private Pattern bigIpPattern = Pattern.compile("[0-9]{8,10}\\.[0-9]{3,5}\\.0000");
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        callbacks.setExtensionName("BigIP Cookie Scanner");
        callbacks.registerScannerCheck(this);
    }
    
    // helper method to search a response for occurrences of a literal match string
    // and return a list of start/end offsets
    private List<int[]> getMatches(byte[] response, byte[] match)
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

    // Given a list of cookies, return any BigIP cookies found
    private List<BigIPCookie> searchForCookies(List<ICookie> cookies){
        Matcher matcher;
        BigIPCookie bigCookie;

        List<BigIPCookie> bigCookies = new ArrayList<>();

        for (ICookie cookie: cookies){
            // Check for a cookie value that matches a BigIP cookie
            matcher = bigIpPattern.matcher(cookie.getValue());
            if (matcher.matches()){
                bigCookie = new BigIPCookie(cookie.getName(), cookie.getValue());
                bigCookies.add(bigCookie);
            }
        }

        return bigCookies;
    }
    
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        List<IScanIssue> issues = new ArrayList<>();
        List<ICookie> cookies = helpers.analyzeResponse(baseRequestResponse.getResponse()).getCookies();
        List<BigIPCookie> responseCookies = searchForCookies(cookies);
        List<int[]> matches;
        for (BigIPCookie cookie: responseCookies){
            matches = getMatches(baseRequestResponse.getResponse(), cookie.getEncoded().getBytes());
            issues.add(new BigIPCookieScanIssue(
                baseRequestResponse.getHttpService(),
                helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) }, 
                cookie
            ));
        }
        
        if (issues.size() > 0){
            return issues;
        }
        return null;

    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        if (existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()))
            return -1;
        else return 0;
    }
}


class BigIPCookie {
    private String host;
    private String port;
    private String encoded;
    private String cookieName;

    public BigIPCookie(String cookieName, String encoded){
        this.cookieName = cookieName;
        this.encoded = encoded;
        this.decodeIPv4();
    }

    // Reverses the BigIP cookie encoding
    public void decodeIPv4(){
        String[] splitString = this.encoded.split("\\.");
        String host = splitString[0];
        // Decode as hex and ensure result is padded to 8 characters
        String hostAsHex = BigIPCookie.leftPad(Long.toHexString(Long.parseLong(host)), 8, '0');
        // Each two bytes is an octet in the IP address in reverse order
        String oct4 = BigIPCookie.hexStringToDecString(hostAsHex.substring(0, 2));
        String oct3 = BigIPCookie.hexStringToDecString(hostAsHex.substring(2, 4));
        String oct2 = BigIPCookie.hexStringToDecString(hostAsHex.substring(4, 6));
        String oct1 = BigIPCookie.hexStringToDecString(hostAsHex.substring(6, 8));
        this.host = oct1 + "." + oct2 + "." + oct3 + "." + oct4;

        String port = splitString[1];
        // Decode as hex and ensure result is padded to 4 characters
        String portAsHex = BigIPCookie.leftPad(Long.toHexString(Long.parseLong(port)), 4, '0');
        String reversedHex = portAsHex.substring(2, 4) + portAsHex.substring(0, 2);
        this.port = BigIPCookie.hexStringToDecString(reversedHex);
    }

    private static String hexStringToDecString(String in){
        return String.valueOf(Long.parseLong(in, 16));
    }

    private static String leftPad(String in, int size, char pad){
        StringBuilder sb = new StringBuilder();
        for (int i = size - in.length(); i>0; i--) {
            sb.append(pad);
        }
        sb.append(in);
        return sb.toString();
    }

    public String getHost(){
        return this.host;
    }

    public String getPort(){
        return this.port;
    }

    public String getEncoded(){
        return this.encoded;
    }

    public String getCookieName(){
        return this.cookieName;
    }
}

class BigIPCookieScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private BigIPCookie cookie;

    public BigIPCookieScanIssue(
            IHttpService httpService,
            URL url, 
            IHttpRequestResponse[] httpMessages, 
            BigIPCookie cookie)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.cookie = cookie;
    }
    
    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return "Insecure BigIP Cookie";
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return "Low";
    }

    @Override
    public String getConfidence()
    {
        return "Certain";
    }

    @Override
    public String getIssueBackground()
    {
        return "Unencrypted BigIP Cookies can give an attacker information about internal IP addresses and ports.";
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("<div>");
        sb.append("Cookie Name: " + cookie.getCookieName());
        sb.append("</div>");
        sb.append("<div>");
        sb.append("Encoded: " + cookie.getEncoded());
        sb.append("</div>");
        sb.append("<div>");
        sb.append("Host: " + cookie.getHost());
        sb.append("</div>");
        sb.append("<div>");
        sb.append("Port: " + cookie.getPort());
        sb.append("</div>");
        return sb.toString();
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }
    
}