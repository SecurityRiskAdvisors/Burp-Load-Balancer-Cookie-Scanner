package com.securityriskadvisors;

import burp.*;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Credit for figuring out how to decode Netscaler cookies goes to: https://github.com/catalyst256
 * Inspired by https://github.com/catalyst256/Netscaler-Cookie-Decryptor
 */
public class NetscalerCookieScanner implements IScannerCheck {

    protected static BurpExtender extender;

    protected static Pattern netscalerNamePattern = Pattern.compile("NSC_([a-zA-Z0-9\\-_.]*)");
    protected static Pattern netscalerValuePattern = Pattern.compile("[0-9a-f]{8}([0-9a-f]{8}).*([0-9a-f]{4})");

    public NetscalerCookieScanner(BurpExtender extender){
        NetscalerCookieScanner.extender = extender;
    }

    private List<NetscalerCookie> searchForCookies(List<ICookie> cookies){
        Matcher matcher;
        NetscalerCookie netCookie;

        List<NetscalerCookie> netCookies = new ArrayList<>();

        for (ICookie cookie: cookies){
            // Check for a cookie value that matches a BigIP cookie
            matcher = netscalerNamePattern.matcher(cookie.getName());
            if (matcher.matches()){
                netCookie = new NetscalerCookie(cookie.getName(), cookie.getValue());
                netCookies.add(netCookie);
            }
        }

        return netCookies;
    }

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

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}


class NetscalerCookie {

    private static final String ORIGINAL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String SHIFTED =  "zabcdefghijklmnopqrstuvwxyZABCDEFGHIJKLMNOPQRSTUVWXY";

    private final String name;
    private final String value;

    private String server;
    private String host;
    private String port;

    public NetscalerCookie(String name, String value){

        this.name = name;
        this.value = value;
        this.decode();
    }

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

    private String decodeHost(String in){
        long key = Long.parseLong("03081e11", 16);
        long decoded = Long.parseLong(in, 16) ^ key;
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

    private String decodePort(String in){
        long key = Long.parseLong("3630", 16);
        long decoded = Long.parseLong(in, 16) ^ key;
        return String.valueOf(decoded);
    }

    private void decode(){
        Matcher nameMatcher = NetscalerCookieScanner.netscalerNamePattern.matcher(this.name);
        Matcher valueMatcher = NetscalerCookieScanner.netscalerValuePattern.matcher(this.value);
        nameMatcher.matches();
        this.server = decodeServer(nameMatcher.group(1));
        valueMatcher.matches();
        this.host = decodeHost(valueMatcher.group(1));
        this.port = decodePort(valueMatcher.group(2));

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
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("<div>");
        sb.append("Cookie Name: " + cookie.getName());
        sb.append("</div>");
        sb.append("<div>");
        sb.append("Cookie Value: " + cookie.getValue());
        sb.append("</div>");
        sb.append("<div>");
        sb.append("Server: " + cookie.getServer());
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