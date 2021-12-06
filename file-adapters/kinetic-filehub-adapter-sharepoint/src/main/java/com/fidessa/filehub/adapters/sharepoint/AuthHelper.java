
package com.fidessa.filehub.adapters.sharepoint;

import com.kineticdata.bridgehub.adapter.BridgeError;
import java.io.*;
import java.util.stream.Collectors;
import javax.xml.parsers.*;
import javax.xml.xpath.*;
import org.apache.commons.io.IOUtils;
import org.w3c.dom.Document;
import org.xml.sax.*;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.HttpClients;

public class AuthHelper {

    private final String msOnlineSts = "https://login.microsoftonline.com/extSTS.srf";
    private final String loginContextPath = "/_forms/default.aspx?wa=wsignin1.0";
    private final String sharepointContext = "iontradingcom";
    private final String fileName = "SAML.xml";
    private String username;
    private String password;

    public void initialize(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public BasicCookieStore getAuth() throws BridgeError {
        String token;
        try {
            token = getSecurityTokenWithOnline();
            BasicCookieStore cookie = submitToken(token);
            return cookie;
        } catch (Exception e) {
            throw new BridgeError("Error in getting Auth cookies with the given credentials");
        }
    }

    private String generateSAML() throws BridgeError, IOException {
       BufferedReader br = null;
        try {
            InputStream in = this.getClass().getResourceAsStream(fileName);
            br = new BufferedReader(new InputStreamReader(in));
            String saml = br.lines().collect(Collectors.joining("\n"));
            String url = String.format("https://%s.sharepoint.com/_forms/default.aspx?wa=wsignin1.0", sharepointContext);
            String[] keys = {"{username}", "{password}", "{auth_url}"};
            String[] values = {username, password, url};
            saml = StringUtils.replaceEach(saml, keys, values);
            return saml;
        } catch (Exception e) {
            throw new BridgeError("Error in generating SAML for getting security token");
        } finally {
            if(br != null){
                br.close();
            }
        }
    }

    private String getSecurityTokenWithOnline() throws BridgeError {
        try {
            String saml = generateSAML();

            HttpClient client = HttpClients.createDefault();
            HttpPost post = new HttpPost(msOnlineSts);
            post.setHeader("Accept", "application/x-www-form-urlencoded");
            post.setHeader("User-Agent", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)");
            post.setEntity(new StringEntity(saml));
            HttpResponse response = client.execute(post);

            String token = extractToken(IOUtils.toString(response.getEntity().getContent()));
            return token;
        } catch (Exception e) {
            throw new BridgeError("Error in getting request Token");
        }
    }

    private String extractToken(String result) throws SAXException, IOException, ParserConfigurationException, XPathExpressionException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document document = db.parse(new InputSource(new StringReader(result)));

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xp = xpf.newXPath();
        String token = xp.evaluate("//BinarySecurityToken/text()", document.getDocumentElement());

        return token;
    }

    private BasicCookieStore submitToken(String token) throws IOException {
        String url = String.format("https://%s.sharepoint.com%s", sharepointContext, loginContextPath);

        BasicCookieStore httpCookieStore = new BasicCookieStore();
        HttpClient client = HttpClients.custom().setDefaultCookieStore(httpCookieStore).build();
        HttpPost post = new HttpPost(url);
        post.setHeader("Accept", "application/x-www-form-urlencoded");
        post.setHeader("Content-Type", "text/xml; charset=utf-8");
        post.setHeader("User-Agent", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)");
        post.setEntity(new StringEntity(token));
        HttpResponse response = client.execute(post);
        return httpCookieStore;
    }

}
