package freeipa.boot.server;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.websocket.Session;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by claire on 2019-09-09 - 16:15
 **/
@Slf4j
@Service
public class APIServerClient implements APIServer {
    @Autowired
    private RestTemplate restTemplate;

    private boolean sslVerify = false;
    private HttpSession session;
    private String server;

    private final String url = "https://xxxxx.com";
    private final String ipaUrl = "https://xxxxxx/ipa";


    /**
     * 做一个简单的测试，测试restTempate
     */
    public void testJson(){
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON_UTF8);
        HttpEntity<String> entity = new HttpEntity<String>("", headers);
        restTemplate.exchange(ipaUrl, HttpMethod.POST, entity, String.class);
    }

    //====================以上是模仿python的参数和写法探究出来的参数和地址书写=====================//

    /**
     * 这是用授信的restTemplate去请求https的接口，虽然写的很简陋，但是测试没有问题
     * 这是FreeIPA的登录接口
     * @param user
     * @param password
     * @throws UnsupportedEncodingException
     */
    public void login(String user,String password) throws UnsupportedEncodingException {
        RestTemplate restTemplate = new RestTemplate();
        String url = ipaUrl+"/session/login_password";
        String bodyValTemplate = "user=" + URLEncoder.encode(user
                , "utf-8") + "&password=" + URLEncoder.encode(password, "utf-8");
        HttpHeaders headers = new HttpHeaders();
        headers.set("referer", url);
        headers.setAccept(Arrays.asList(MediaType.TEXT_PLAIN));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity entity = new HttpEntity(bodyValTemplate, headers);
        ResponseEntity<String> exchange = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);
        if(exchange.getStatusCode() != null){
            log.info("status code :{}",exchange.getStatusCode().value());
            log.info("IPASESSION :{}",exchange.getHeaders().get("IPASESSION"));
            log.info("Set-Cookie :{}",exchange.getHeaders().get("Set-Cookie"));
        }
    }

    /***
     *  这个方法失败，因为这边没有做cookie的存储，除了登陆的接口，其余都需要在认证的前提之下
     * @param pdict
     * @return
     */
    public String  makeRequest(Map<String,Object> pdict){
        String sessionURL = ipaUrl+"/session/json";
        HttpHeaders headers = new HttpHeaders();
        headers.set("referer", ipaUrl);
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        HashMap<String,Object> map = new HashMap<String, Object>();
        map.put("id",0);
        map.put("method",pdict.get("method"));
        //map.put("params",Arrays.asList(pdict.get("params")));

        log.info("Making request to {}", sessionURL);
        HttpEntity<HashMap<String,Object>> entity = new HttpEntity<>(map, headers);
        ResponseEntity<Object> exchange = restTemplate.exchange(sessionURL, HttpMethod.POST, entity, Object.class);
        if(exchange.getStatusCode() != null){
            log.info("status code :{}",exchange.getStatusCode().value());
            String responseBody = String.valueOf(exchange.getBody());
            if(StringUtils.isNotBlank(responseBody)){
                return responseBody;
            }
        }
        return null;
    }

    public String showConfig() {
        HashMap<String, Object> pdict = new HashMap<String, Object>();
        pdict.put("method","config_show");
        //pdict.put("params","{'all':true}");
        //pdict.put("item","");
        return makeRequest(pdict);
    }

    public boolean isSslVerify() {
        return sslVerify;
    }

    public void setSslVerify(boolean sslVerify) {
        this.sslVerify = sslVerify;
    }

    public HttpSession getSession() {
        return session;
    }

    public void setSession(HttpSession session) {
        this.session = session;
    }

    public String getServer() {
        return server;
    }

    public void setServer(String server) {
        this.server = server;
    }



}
