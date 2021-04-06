package ipa.boot;

import freeipa.boot.IPABootApplication;
import freeipa.boot.server.APIServer;
import freeipa.boot.server.APIServerClient;
import freeipa.boot.server.HttpClientKeepSession;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.message.BasicHeader;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by claire on 2019-09-09 - 16:21
 **/
@SpringBootTest(classes = IPABootApplication.class)
@RunWith(SpringJUnit4ClassRunner.class)
public class IPATest {
    @Autowired
    private APIServer apiServer;

    @Test
    public void testAPILogin() {
        try {
            apiServer.login("username","password");
        }catch (Exception e){
            e.printStackTrace();
        }
    }


    @Test
    public void testShowConfig(){
        try {
            String config = apiServer.showConfig();
            if (StringUtils.isNotBlank(config)) {
                System.out.println(config);
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    @Test
    public void testLoginWithCookie() throws IOException {
        String url = "https://xxxx";
        String ipaUrl = "https://xxxxx/ipa";

        //用户登陆
        List<Header> l1 = new ArrayList<>();
        String loginUrl = ipaUrl +"/session/login_password";
        Header h1 = new BasicHeader("referer",loginUrl);
        Header h2 = new BasicHeader("Content-Type","application/x-www-form-urlencoded");
        Header h3 = new BasicHeader("Accept","text/plain");
        l1.add(h1);
        l1.add(h2);
        l1.add(h3);
        CloseableHttpResponse response = HttpClientKeepSession.post(loginUrl, "user=chenziyan&password=czy123456",l1);
        HttpClientKeepSession.printResponse(response);
        HttpClientKeepSession.printCookies();
    }
}
