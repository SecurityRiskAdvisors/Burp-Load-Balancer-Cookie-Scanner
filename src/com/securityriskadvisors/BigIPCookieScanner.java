package com.securityriskadvisors;

import burp.*;

import java.lang.Long;

import java.net.URL;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.*;

/**
 * Scanner/decoder for BigIP Cookies
 *
 * @author Dan Herlihy
 */
public class BigIPCookieScanner implements IScannerCheck{

    private BurpExtender extender;
    
    // RegEx pattern for finding BigIP style cookies
    private Pattern bigIpPattern = Pattern.compile("[0-9]{8,10}\\.[0-9]{3,5}\\.0000");

    public BigIPCookieScanner(BurpExtender extender){
        this.extender = extender;
    }

    /**
     * Search for BigIP cookies in a list of cookies
     *
     * @param cookies List of cookies from the response
     * @return List of BigIP cookies found in the list of cookies
     */
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

    /**
     * Passively scan a request/response for Netscaler cookies.
     *
     * @param baseRequestResponse The base HTTP request / response that should
     * be passively scanned.
     * @return List of issues about BigIP cookies if found or null
     */
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        List<IScanIssue> issues = new ArrayList<>();
        List<ICookie> cookies = this.extender.getHelpers().analyzeResponse(baseRequestResponse.getResponse()).getCookies();
        List<BigIPCookie> responseCookies = searchForCookies(cookies);
        List<int[]> matches;
        for (BigIPCookie cookie: responseCookies){
            matches = extender.getMatches(baseRequestResponse.getResponse(), cookie.getEncoded().getBytes());
            issues.add(new BigIPCookieScanIssue(
                baseRequestResponse.getHttpService(),
                this.extender.getHelpers().analyzeRequest(baseRequestResponse).getUrl(), 
                new IHttpRequestResponse[] { this.extender.getCallbacks().applyMarkers(baseRequestResponse, null, matches) }, 
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

    /**
     * Determine whether two issues should be combined or not.
     *
     * @param existingIssue An issue that was previously reported by this
     * Scanner check.
     * @param newIssue An issue at the same URL path that has been newly
     * reported by this Scanner check.
     * @return -1 if the issues are about the same cookie, 0 if they are different
     */
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

    /**
     * Decode BigIP cookies into IP address and port
     */
    public void decodeIPv4(){
        String[] splitString = this.encoded.split("\\.");
        String host = splitString[0];
        // Decode as hex and ensure result is padded to 8 characters
        String hostAsHex = BurpExtender.leftPad(Long.toHexString(Long.parseLong(host)), 8, '0');
        // Each two bytes is an octet in the IP address in reverse order
        String oct4 = BigIPCookie.hexStringToDecString(hostAsHex.substring(0, 2));
        String oct3 = BigIPCookie.hexStringToDecString(hostAsHex.substring(2, 4));
        String oct2 = BigIPCookie.hexStringToDecString(hostAsHex.substring(4, 6));
        String oct1 = BigIPCookie.hexStringToDecString(hostAsHex.substring(6, 8));
        this.host = oct1 + "." + oct2 + "." + oct3 + "." + oct4;

        String port = splitString[1];
        // Decode as hex and ensure result is padded to 4 characters
        String portAsHex = BurpExtender.leftPad(Long.toHexString(Long.parseLong(port)), 4, '0');
        String reversedHex = portAsHex.substring(2, 4) + portAsHex.substring(0, 2);
        this.port = BigIPCookie.hexStringToDecString(reversedHex);
    }

    private static String hexStringToDecString(String in){
        return String.valueOf(Long.parseLong(in, 16));
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
        sb.append("Cookie Name: ").append(cookie.getCookieName());
        sb.append("</div>");
        sb.append("<div>");
        sb.append("Encoded: ").append(cookie.getEncoded());
        sb.append("</div>");
        sb.append("<div>");
        sb.append("Host: ").append(cookie.getHost());
        sb.append("</div>");
        sb.append("<div>");
        sb.append("Port: ").append(cookie.getPort());
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