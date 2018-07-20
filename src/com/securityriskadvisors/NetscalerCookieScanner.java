package com.securityriskadvisors;

import burp.*;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scanner/decoder for Netscaler cookies
 *
 * Credit for figuring out how to decode Netscaler cookies goes to: https://github.com/catalyst256
 * Inspired by: https://github.com/catalyst256/Netscaler-Cookie-Decryptor
 *
 * @author Dan Herlihy
 */
public class NetscalerCookieScanner implements IScannerCheck {

    private static BurpExtender extender;

    // Group 1 = Server name
    static Pattern netscalerNamePattern = Pattern.compile("NSC_([a-zA-Z0-9\\-_.]*)");
    // Group 1 = Host address, Group 2 = Host port
    static Pattern netscalerValuePattern = Pattern.compile("[0-9a-f]{8}([0-9a-f]{8}).*([0-9a-f]{4})");

    public NetscalerCookieScanner(BurpExtender extender){
        NetscalerCookieScanner.extender = extender;
    }

    /**
     * Search for Netscaler cookies in a list of cookies
     *
     * @param cookies List of cookies from the response
     * @return List of Netscaler cookies found in the list of cookies
     */
    private List<NetscalerCookie> searchForCookies(List<ICookie> cookies){
        Matcher matcher;
        NetscalerCookie netCookie;

        List<NetscalerCookie> netCookies = new ArrayList<>();

        for (ICookie cookie: cookies){
            // Check for a cookie value that matches a Netscaler cookie
            matcher = netscalerNamePattern.matcher(cookie.getName());
            if (matcher.matches()){
                netCookie = new NetscalerCookie(cookie.getName(), cookie.getValue());
                netCookies.add(netCookie);
            }
        }

        return netCookies;
    }

    /**
     * Passively scan a request/response for Netscaler cookies.
     *
     * @param baseRequestResponse The base HTTP request / response that should
     * be passively scanned.
     * @return List of issues about Netscaler cookies if found or null
     */
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();
        List<ICookie> cookies = extender.getHelpers().analyzeResponse(baseRequestResponse.getResponse()).getCookies();
        List<NetscalerCookie> netCookies = searchForCookies(cookies);
        List<int[]> matches;
        for (NetscalerCookie cookie: netCookies){
            String fullCookie = cookie.getName() + "=" + cookie.getValue();
            matches = extender.getMatches(baseRequestResponse.getResponse(), fullCookie.getBytes());
            issues.add(new NetscalerCookieScanIssue(
                    baseRequestResponse.getHttpService(),
                    extender.getHelpers().analyzeRequest(baseRequestResponse).getUrl(),
                    new IHttpRequestResponse[] { extender.getCallbacks().applyMarkers(baseRequestResponse, null, matches) },
                    cookie
            ));
        }
        if (issues.size() > 0){
            return issues;
        }
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
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
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()))
            return -1;
        else return 0;
    }
}


class NetscalerCookie {

    // Caesar cypher keys for Netscaler server names
    private static final String ORIGINAL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String SHIFTED =  "zabcdefghijklmnopqrstuvwxyZABCDEFGHIJKLMNOPQRSTUVWXY";

    // Encoded Values
    private final String name;
    private final String value;

    // Decoded values
    private String server;
    private String host;
    private String port;

    NetscalerCookie(String name, String value){

        this.name = name;
        this.value = value;
        this.decode();
    }

    /**
     * Decode the server name from the cookie name.
     *
     * @param in Encoded Netscaler cookie name beginning with NSC_
     * @return Decoded server name
     */
    private String decodeServer(String in){
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < in.length(); i++){
            int index = ORIGINAL.indexOf(in.charAt(i));
            if (index != -1) {
                sb.append(SHIFTED.charAt(index));
            } else {
                sb.append(in.charAt(i));
            }
        }
        return sb.toString();
    }

    /**
     * Decode the server host address from the cookie value
     *
     * @param in Encoded Netscaler cookie value
     * @return Decoded host address
     */
    private String decodeHost(String in){
        // Hex key used to XOR the host
        long key = Long.parseLong("03081e11", 16);
        long decoded = Long.parseLong(in, 16) ^ key;
        // Pad the hex string to 8 characters
        String decodedHost = BurpExtender.leftPad(Long.toHexString(decoded), 8, '0');
        StringBuilder hostBuilder = new StringBuilder();
        // Every two characters is an octet in the IP address in hex
        for (int i = 0; i < decodedHost.length(); i += 2){
            hostBuilder.append(String.valueOf(Long.parseLong(decodedHost.substring(i, i+2), 16)));
            hostBuilder.append('.');
        }
        hostBuilder.deleteCharAt(hostBuilder.lastIndexOf("."));

        return hostBuilder.toString();
    }

    /**
     * Decode the server port from the cookie value
     * @param in Encoded Netscaler cookie value
     * @return Decoded port
     */
    private String decodePort(String in){
        // Hex key used to XOR the host
        long key = Long.parseLong("3630", 16);
        long decoded = Long.parseLong(in, 16) ^ key;
        return String.valueOf(decoded);
    }

    /**
     * Decode the server name, host address, and port from the cookie.
     */
    private void decode(){
        Matcher nameMatcher = NetscalerCookieScanner.netscalerNamePattern.matcher(this.name);
        Matcher valueMatcher = NetscalerCookieScanner.netscalerValuePattern.matcher(this.value);
        if (nameMatcher.matches()){
            this.server = decodeServer(nameMatcher.group(1));
        }
        if (valueMatcher.matches()){
            this.host = decodeHost(valueMatcher.group(1));
            this.port = decodePort(valueMatcher.group(2));
        }

    }

    public String getServer() {
        return server;
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    public String getHost() {
        return host;
    }

    public String getPort() {
        return port;
    }
}

class NetscalerCookieScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private NetscalerCookie cookie;

    public NetscalerCookieScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            NetscalerCookie cookie)
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
        return "Insecure Netscaler Cookie";
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
        return "Unencrypted Netscaler Cookies can give an attacker information about internal IP addresses and ports.";
    }

    @Override
    public String getRemediationBackground()
    {

        return"<div>Configure cookie encryption on the Netscaler load balancer.</div>" +
                "<div>Manufacturer Reference:</div>" +
                "<a href='https://support.citrix.com/article/CTX220162'>https://support.citrix.com/article/CTX220162</a>";
    }

    @Override
    public String getIssueDetail()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("<div>");
        sb.append("Cookie Name: ").append(cookie.getName());
        sb.append("</div>");
        sb.append("<div>");
        sb.append("Cookie Value: ").append(cookie.getValue());
        sb.append("</div>");
        sb.append("<div>");
        sb.append("Server: ").append(cookie.getServer());
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