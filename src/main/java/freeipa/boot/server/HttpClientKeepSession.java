package freeipa.boot.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.*;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.CookieStore;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.cookie.Cookie;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.*;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.nio.entity.NStringEntity;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.CharsetUtils;
import org.apache.http.util.EntityUtils;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 以下是直接使用授信的httpclient来实现的，并且使用cookie store 保存cookie
 * Created by claire on 2019-09-10 - 09:13
 **/
@Slf4j
public class HttpClientKeepSession {
    public static CloseableHttpClient httpClient = null;
    public static HttpClientContext context = null;
    public static CookieStore cookieStore = null;
    public static RequestConfig requestConfig = null;
    public static final String baseUrl = "https://xxxxx";
    public static final String ipaUrl = "https://xxxxx/ipa";
    public static final String LOGIN_SERVICE = "/ipa/session/login_password";
    public static final String LOOKUP_SERVICE = "/ipa/session/json";
    public static final String LOOKUP_REFERER = "/ipa/ui/";


    static {
        try {
            init();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
    }

    private static void init() throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        context = HttpClientContext.create();
        cookieStore = new BasicCookieStore();
        requestConfig = RequestConfig.custom()
                .setConnectTimeout(120000)
                .setSocketTimeout(60000)
                .setConnectionRequestTimeout(60000)
                .build();
        TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;
        SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom()
                .loadTrustMaterial(null, acceptingTrustStrategy)
                .build();

        SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext);

        httpClient = HttpClients.custom()
                .setSSLSocketFactory(csf)
                .setKeepAliveStrategy(new DefaultConnectionKeepAliveStrategy())
                .setRedirectStrategy(new DefaultRedirectStrategy()).setDefaultRequestConfig(requestConfig)
                .setDefaultCookieStore(cookieStore)
                .build();
    }

    /**
     * http get
     *
     * @param url
     * @return response
     * @throws ClientProtocolException
     * @throws IOException
     */
    public static CloseableHttpResponse get(String url) throws ClientProtocolException, IOException {
        HttpGet httpget = new HttpGet(url);
        CloseableHttpResponse response = httpClient.execute(httpget, context);
        try {
            cookieStore = context.getCookieStore();
            List<Cookie> cookies = cookieStore.getCookies();
            for (Cookie cookie : cookies) {
                log.info("key:" + cookie.getName() + "  value:" + cookie.getValue());
            }
        } finally {
            response.close();
        }
        return response;
    }

    /**
     * http post
     *
     * @param url
     * @param parameters form表单
     * @return response
     * @throws ClientProtocolException
     * @throws IOException
     */
    public static CloseableHttpResponse post(String url, String parameters, List<Header> headers)
            throws ClientProtocolException, IOException {
        HttpPost httpPost = new HttpPost(url);
        List<NameValuePair> nvps = toNameValuePairList(parameters);
        if (headers != null && headers.size() != 0) {
            httpPost.setHeaders(headers.toArray(new Header[headers.size()]));
        }
        httpPost.setEntity(new UrlEncodedFormEntity(nvps, "UTF-8"));

        CloseableHttpResponse response = httpClient.execute(httpPost, context);
        try {
            cookieStore = context.getCookieStore();
            List<Cookie> cookies = cookieStore.getCookies();
            for (Cookie cookie : cookies) {
                log.info("key:" + cookie.getName() + "  value:" + cookie.getValue());
            }
        } finally {
            response.close();
        }
        return response;

    }

    @SuppressWarnings("unused")
    private static List<NameValuePair> toNameValuePairList(String parameters) {
        List<NameValuePair> nvps = new ArrayList<NameValuePair>();
        String[] paramList = parameters.split("&");
        for (String parm : paramList) {
            int index = -1;
            for (int i = 0; i < parm.length(); i++) {
                index = parm.indexOf("=");
                break;
            }
            String key = parm.substring(0, index);
            String value = parm.substring(++index, parm.length());
            nvps.add(new BasicNameValuePair(key, value));
        }
        System.out.println(nvps.toString());
        return nvps;
    }

    /**
     * 手动增加cookie
     *
     * @param name
     * @param value
     * @param domain
     * @param path
     */
    public static void addCookie(String name, String value, String domain, String path) {
        BasicClientCookie cookie = new BasicClientCookie(name, value);
        cookie.setDomain(domain);
        cookie.setPath(path);
        cookieStore.addCookie(cookie);
    }

    /**
     * 把结果console出来
     *
     * @param httpResponse
     * @throws ParseException
     * @throws IOException
     */
    public static void printResponse(HttpResponse httpResponse) throws ParseException, IOException {
        // 获取响应消息实体
        HttpEntity entity = httpResponse.getEntity();
        // 响应状态
        System.out.println("status:" + httpResponse.getStatusLine());
        System.out.println("headers:");
        HeaderIterator iterator = httpResponse.headerIterator();
        while (iterator.hasNext()) {
            System.out.println("\t" + iterator.next());
        }
        // 判断响应实体是否为空
        if (entity != null) {
            //		String responseString = EntityUtils.toString(entity);
            //		System.out.println("response length:" + responseString.length());
            //		System.out.println("response content:" + responseString.replace("\r\n", ""));
        }
        System.out.println(
                "------------------------------------------------------------------------------------------\r\n");
    }

    /**
     * 把当前cookie从控制台输出出来
     */
    public static void printCookies() {
        System.out.println("headers:");
        cookieStore = context.getCookieStore();
        List<Cookie> cookies = cookieStore.getCookies();
        for (Cookie cookie : cookies) {
            System.out.println("key:" + cookie.getName() + "  value:" + cookie.getValue());
        }
    }

    /**
     * 测试版本，没有记录cookie：简单的利用httpclient 执行post 请求
     *
     * @param user
     * @param password
     * @throws IOException
     */
    public static void login(String user, String password) throws IOException {
        List<Header> l1 = new ArrayList<>();
        String loginUrl = ipaUrl + "/session/login_password";
        Header h1 = new BasicHeader("referer", loginUrl);
        Header h2 = new BasicHeader("Content-Type", "application/x-www-form-urlencoded");
        Header h3 = new BasicHeader("Accept", "text/plain");
        l1.add(h1);
        l1.add(h2);
        l1.add(h3);
        CloseableHttpResponse response = HttpClientKeepSession.post(loginUrl, "user=" + user + "&password=" + password, l1);
        printResponse(response);
        printCookies();
    }

    public static void showConfig(String params) throws IOException {
        CloseableHttpResponse response = makeRequest(params);
        printResponse(response);
        printCookies();
    }

    public static void addGroup(String params) throws IOException {
        CloseableHttpResponse response = makeRequest(params);
        HttpEntity entity = response.getEntity();
        printResponse(response);
        printCookies();

    }

    /**
     * 测试版本，没有记录cookie : 执行请求
     *
     * @param params
     * @return
     * @throws IOException
     */
    public static CloseableHttpResponse makeRequest(String params) throws IOException {
        String sessionUrl = ipaUrl + "/session/json";
        Header h4 = new BasicHeader("referer", ipaUrl);
        Header h5 = new BasicHeader("Accept", "application/json");
        Header h6 = new BasicHeader("Content-Type", "application/json");
        List<Header> l2 = new ArrayList<>();
        l2.add(h4);
        l2.add(h5);
        l2.add(h6);
        return HttpClientKeepSession.post(sessionUrl, params, l2);
    }

    public static void showGroup(String params) throws IOException {
        CloseableHttpResponse response = makeRequest(params);
        printResponse(response);
        printCookies();
    }

    /**
     * 登录操作
     *
     * @param user
     * @param password
     */
    public static void loginAndShow(String user, String password) {
        auth(user, password);
    }

    /**
     * 登录核心操作
     *
     * @param username
     * @param password
     * @return
     */
    private static Map<String, Object> auth(String username, String password) {
        try {
            CloseableHttpClient client = HttpClients.custom().
                    setHostnameVerifier(new AllowAllHostnameVerifier()).
                    setSslcontext(new SSLContextBuilder().loadTrustMaterial(null, (TrustStrategy) (arg0, arg1) -> true).build()).build();
            log.info("auth - URL: " + HttpClientKeepSession.baseUrl + HttpClientKeepSession.LOGIN_SERVICE);
            HttpPost httpPost = new HttpPost(HttpClientKeepSession.baseUrl + LOGIN_SERVICE);

            List<NameValuePair> params = new ArrayList<NameValuePair>();
            params.add(new BasicNameValuePair("user", username));
            params.add(new BasicNameValuePair("password", password));
            httpPost.setEntity(new UrlEncodedFormEntity(params));

            CloseableHttpResponse response = client.execute(httpPost);
            Integer statusCode = response.getStatusLine().getStatusCode();

            if (statusCode == 200) {
                String cookie = "";
                //这边查看请求回来的信息：cookie默认过期时间30分钟，这边的过期时间也是30分钟，timeout：30 max:100
                for (Header header : response.getAllHeaders()) {
                    if (header.getName().equals("Set-Cookie")) {
                        cookie = header.getValue();
                    }
                }

                if (StringUtils.isNotEmpty(cookie)) {
                    //带上cookie直接去请求，这边只是为了测试，还没有放进CookieStore中
                    userShow(client, cookie, username);
                    //groupShow(client,cookie,"admins");
                } else {
                    log.info("cookie is empty");
                }
            } else if (statusCode == 401) {
                log.info("Unauthorized");
            } else {
                log.info("statusCode: " + statusCode);
            }
            client.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private static Map<String, Object> groupShow(CloseableHttpClient client, String cookie, String groupname) throws IOException {
        HttpPost httpPost = new HttpPost(baseUrl + LOOKUP_SERVICE);
        httpPost.setHeader("Cookie", cookie);
        httpPost.setHeader("Referer", baseUrl + LOOKUP_REFERER);
        httpPost.setHeader("Content-Type", "application/json");
        HttpEntity entity = new NStringEntity("{\"method\":\"group_show/1\",\"params\":[[\"" + groupname + "\"],{\"all\":true,\"raw\":false,\"version\":\"2.229\"}]}", ContentType.APPLICATION_JSON);
        httpPost.setEntity(entity);
        CloseableHttpResponse response = client.execute(httpPost);
        Integer statusCode = response.getStatusLine().getStatusCode();

        if (statusCode == 200) {
            String responseBody = EntityUtils.toString(response.getEntity());
            Map<String, Object> map = new ObjectMapper().readValue(responseBody, Map.class);
            if (map != null) {
                Map<String, Object> principal = (Map<String, Object>) map.get("result");

                if (principal != null) {
                    Map<String, Object> principalDetails = (Map<String, Object>) principal.get("result");

                    if (principalDetails != null) {
                        List<String> groups = (List<String>) principalDetails.get("memberof_group");
                    } else {
                        log.info(" Unexpected response (principalDetails)");
                    }
                } else {
                    log.info(" Unexpected response (principal)");
                }
            } else {
                log.info("Unexpected response (map)");
            }
        } else if (statusCode == 401) {
            log.info("Unauthorized");
        } else {
            log.info("statusCode: " + statusCode);
        }
        return null;
    }

    private static Map<String, Object> userShow(CloseableHttpClient client, String cookie, String username) throws IOException {
        HttpPost httpPost = new HttpPost(baseUrl + LOOKUP_SERVICE);
        httpPost.setHeader("Cookie", cookie);
        httpPost.setHeader("Referer", baseUrl + LOOKUP_REFERER);
        httpPost.setHeader("Content-Type", "application/json");
        HttpEntity entity = new NStringEntity("{\"method\":\"user_show/1\",\"params\":[[\"" + username + "\"],{\"all\":true,\"version\":\"2.229\"}]}", ContentType.APPLICATION_JSON);
        httpPost.setEntity(entity);
        CloseableHttpResponse response = client.execute(httpPost);
        Integer statusCode = response.getStatusLine().getStatusCode();

        if (statusCode == 200) {
            String responseBody = EntityUtils.toString(response.getEntity());
            Map<String, Object> map = new ObjectMapper().readValue(responseBody, Map.class);
            if (map != null) {
                Map<String, Object> principal = (Map<String, Object>) map.get("result");

                if (principal != null) {
                    Map<String, Object> principalDetails = (Map<String, Object>) principal.get("result");

                    if (principalDetails != null) {
                        List<String> groups = (List<String>) principalDetails.get("memberof_group");

                        if (groups != null) {

                            for (String group : groups) {
                                //打印出来看一下请求是否成功
                                log.info("group:{}", group);
                            }
                            log.info("authenticated: " + username);
                        } else {
                            log.info("Unexpected response (groups)");
                        }
                    } else {
                        log.info("Unexpected response (principalDetails)");
                    }
                } else {
                    log.info("Unexpected response (principal)");
                }
            } else {
                log.info("Unexpected response (map)");
            }
        } else if (statusCode == 401) {
            log.info("Unauthorized");
        } else {
            log.info("statusCode: " + statusCode);
        }

        return null;
    }


    public static void main(String[] args) throws ClientProtocolException, IOException {
        String url = "https://xxxxxx";
        auth("user", "password");
        //登录尝试
       /* List<Header> l1 = new ArrayList<>();
        String loginUrl = ipaUrl +"/session/login_password";
        Header h1 = new BasicHeader("referer",loginUrl);
        Header h2 = new BasicHeader("Content-Type","application/x-www-form-urlencoded");
        Header h3 = new BasicHeader("Accept","text/plain");
        l1.add(h1);
        l1.add(h2);
        l1.add(h3);
        CloseableHttpResponse response = HttpClientKeepSession.post(loginUrl, "user=user&password=password",l1);
        printResponse(response);
        printCookies();*/
        //login("user","password");

        //获取config
       /* String sessionUrl =ipaUrl+"/session/json";
        Header h4 = new BasicHeader("referer",ipaUrl);
        Header h5 = new BasicHeader("Accept","application/json");
        Header h6 = new BasicHeader("Content-Type","application/json");
        List<Header> l2 = new ArrayList<>();
        l2.add(h4);
        l2.add(h5);
        l2.add(h6);
        CloseableHttpResponse response1 = HttpClientKeepSession.post(sessionUrl, "id=0&method=config_show&params={'all':true}", l2);
        printResponse(response1);
        printCookies();*/
        //showConfig("id=0&method=config_show&params={'all':true}");


        //添加组
        //addGroup("id=0&method=group_add&params=[{'all':true},{'description':'test add group'}]");

        //showGroup("id=0&method=group_show&params=[{'all':true},{'raw':false},{'item':['groupName']}]");
    }


}
