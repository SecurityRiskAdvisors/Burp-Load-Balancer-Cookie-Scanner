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
    
    // RegEx patterns for finding BigIP style cookies
    private Pattern ipv4 = Pattern.compile("([0-9]{8,10})\\.([0-9]{3,5})\\.0000");
    private Pattern ipv4NonDefault = Pattern.compile("rd([0-9]+)o00000000000000000000ffff([a-f0-9]+)o([0-9]+)");
    private Pattern ipv6 = Pattern.compile("vi([a-f0-9]+).([0-9]+)");
    private Pattern ipv6NonDefault = Pattern.compile("rd([0-9]+)o(0{0,3}[a-f1-9]+0{0,3}[a-f0-9]+)o([0-9]+)");

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
        BigIPCookie bigCookie = null;

        List<BigIPCookie> bigCookies = new ArrayList<>();

        for (ICookie cookie: cookies){
            // Check for a cookie value that matches a BigIP cookie
            matcher = ipv4.matcher(cookie.getValue());
            if (matcher.matches()){
                bigCookie = new BigIPCookieIPv4(cookie.getName(), cookie.getValue(), matcher);
            } else {
                matcher = ipv4NonDefault.matcher(cookie.getValue());
                if (matcher.matches()){
                    bigCookie = new BigIPCookieIPv4NonDefault(cookie.getName(), cookie.getValue(), matcher);
                } else {
                    matcher = ipv6.matcher(cookie.getValue());
                    if (matcher.matches()){
                        bigCookie = new BigIPCookieIPv6(cookie.getName(), cookie.getValue(), matcher);
                    } else {
                        matcher = ipv6NonDefault.matcher(cookie.getValue());
                        if (matcher.matches()){
                            bigCookie = new BigIPCookieIPv6NonDefault(cookie.getName(), cookie.getValue(), matcher);
                        }
                    }
                }
            }
            if (bigCookie != null){
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

abstract class BigIPCookie {
    String host;
    String port;
    private String encoded;
    private String cookieName;
    Matcher matcher;

    public BigIPCookie(String cookieName, String encoded, Matcher matcher){
        this.cookieName = cookieName;
        this.encoded = encoded;
        this.matcher = matcher;
        this.decode();
    }

    abstract void decode();

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

class BigIPCookieIPv4 extends BigIPCookie {

    public BigIPCookieIPv4(String cookieName, String encoded, Matcher matcher){
        super(cookieName, encoded, matcher);
    }

    /**
     * Decode BigIP cookies into IP address and port
     */
    public void decode(){
        String host = this.matcher.group(1);
        // Decode as hex and ensure result is padded to 8 characters
        String hostAsHex = BurpExtender.leftPad(Long.toHexString(Long.parseLong(host)), 8, '0');
        // Each two bytes is an octet in the IP address in reverse order
        String oct4 = BurpExtender.hexStringToDecString(hostAsHex.substring(0, 2));
        String oct3 = BurpExtender.hexStringToDecString(hostAsHex.substring(2, 4));
        String oct2 = BurpExtender.hexStringToDecString(hostAsHex.substring(4, 6));
        String oct1 = BurpExtender.hexStringToDecString(hostAsHex.substring(6, 8));
        this.host = oct1 + "." + oct2 + "." + oct3 + "." + oct4;

        String port = this.matcher.group(2);
        // Decode as hex and ensure result is padded to 4 characters
        String portAsHex = BurpExtender.leftPad(Long.toHexString(Long.parseLong(port)), 4, '0');
        String reversedHex = portAsHex.substring(2, 4) + portAsHex.substring(0, 2);
        this.port = BurpExtender.hexStringToDecString(reversedHex);
    }
}

class BigIPCookieIPv4NonDefault extends BigIPCookie {

    public BigIPCookieIPv4NonDefault(String cookieName, String encoded, Matcher matcher){
        super(cookieName, encoded, matcher);
    }

    /**
     * Decode BigIP cookies into IP address and port
     */
    public void decode(){
        String routeId = this.matcher.group(1);
        String hostAsHex = this.matcher.group(2);
        // Each two bytes is an octet in the IP address in reverse order
        String oct1 = BurpExtender.hexStringToDecString(hostAsHex.substring(0, 2));
        String oct2 = BurpExtender.hexStringToDecString(hostAsHex.substring(2, 4));
        String oct3 = BurpExtender.hexStringToDecString(hostAsHex.substring(4, 6));
        String oct4 = BurpExtender.hexStringToDecString(hostAsHex.substring(6, 8));
        this.host = oct1 + "." + oct2 + "." + oct3 + "." + oct4 + "%" + routeId;

        this.port = this.matcher.group(3);
    }
}

class BigIPCookieIPv6 extends BigIPCookie {

    public BigIPCookieIPv6(String cookieName, String encoded, Matcher matcher){
        super(cookieName, encoded, matcher);
    }

    /**
     * Decode BigIP cookies into IP address and port
     */
    public void decode(){
        String host = this.matcher.group(1);
        ArrayList<String> ipv6 = new ArrayList<>();
        for (int i=0; i < host.length(); i+=4){
            ipv6.add(host.substring(i, i+4).replaceAll("^0{0,3}", ""));
        }
        this.host = String.join(":", ipv6);

        String port = this.matcher.group(2);
        // Decode as hex and ensure result is padded to 4 characters
        String portAsHex = BurpExtender.leftPad(Long.toHexString(Long.parseLong(port)), 4, '0');
        String reversedHex = portAsHex.substring(2, 4) + portAsHex.substring(0, 2);
        this.port = BurpExtender.hexStringToDecString(reversedHex);
    }
}

class BigIPCookieIPv6NonDefault extends BigIPCookie {

    public BigIPCookieIPv6NonDefault(String cookieName, String encoded, Matcher matcher){
        super(cookieName, encoded, matcher);
    }

    /**
     * Decode BigIP cookies into IP address and port
     */
    public void decode(){
        String routeId = this.matcher.group(1);
        String host = this.matcher.group(2);
        ArrayList<String> ipv6 = new ArrayList<>();
        for (int i=0; i < host.length(); i+=4){
            ipv6.add(host.substring(i, i+4).replaceAll("^0{0,3}", ""));
        }
        this.host = String.join(":", ipv6) + "%" + routeId;

        this.port = this.matcher.group(3);
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