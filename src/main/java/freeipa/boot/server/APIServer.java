package freeipa.boot.server;

import java.io.UnsupportedEncodingException;
import java.util.Map;

/**
 * Created by claire on 2019-09-09 - 16:15
 **/
public interface APIServer {

    void login(String user,String password) throws UnsupportedEncodingException;

    String makeRequest(Map<String,Object> pdict);

    String showConfig() throws UnsupportedEncodingException;
}
