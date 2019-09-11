> 以下描述一下成功对接FreeIpa认证的基本心路历程

- 背景

|技术|版本|
|----|----|
|okhttp3|3.8.1|
|logging-interceptor||
|shiro-spring|1.4.0|
|redisson|3.10.2|
|springboot|2.0.4.RELEASE|


### 阶段一：阅读官方的样例
- github上搜索freeipa，乍一看最为广泛的就是两种，一种是用python调用API，一种是调用shell命令走API
- 有官网的[API_EXAMPLE](https://www.freeipa.org/page/API_Examples),给出了很多连接，有些打不开，也就看到了python和一些其他语言书写的，从逻辑中摸索请求方式
- 总结：普通api请求auth接口，正常调用；接口请求其他内容都需要带上cookie信息

### 阶段二：java实践
- 有了第一阶段的坑之后，大约就是知道了可能需要哪些请求字段，url有哪几个

#### 第一次尝试
- 简单的restTemplate请求，但是cookie不能很好的存储，并下一次带上

#### 第二次尝试
- 使用HttpClient,配置一个CookieStore,每次请求后将cookie存起来，请求之前将cookie中的值拿出来放在请求头里面
- 但是上面的操作比较粗糙，是不是有更优雅的方式？

#### 第一次修改
- 把赤裸裸的httpclient改成okhttp3，高效异步的模式进行API请求

#### 第二次修改
- okhttp3进行cookie的存储，重写CookieJar的save和load的方法，进行cookie的存储

#### 第三阶段尝试
- 将httpclient修改成okhttp3,将cookieStore用重写cookieJar替代
- 但是将cookie存储在本地内存中，不是分布式存储，这也不是分布式应用可以接受的，因而就对接了redis

#### 第三次修改
- 通过redisson的RListMultimapCache接收了请求返回的cookie
- 但是其中还是出现了一些问题，cookie的对象不能直接通过Redisson反序列化出来，因而使用了一个DTO的实体封装了一下

### 阶段三：测试
- 通过以上尝试，使用okhttp3结合logging-interceptor保障了请求的异步和可见性
- 使用redisson缓存，实现了cookie的持久化
- 通过扩展CookieJar，使请求自动保有了传承cookie的特性，使携带cookie变得自然，不需要编写请求的时候刻意去设置
  
### 附录
- 有些语言都不是很懂，就意会意会，[example总页面](https://www.freeipa.org/page/API_Examples)
- p5-net-freeipa:[官网example-JSON-RPC](https://vda.li/en/posts/2015/05/28/talking-to-freeipa-api-with-sessions/)
- perl-Net-IPA: [Net::IPA](https://github.com/NickCis/perl-Net-IPA)
- python-freeipa-json: [python算是最易懂的](https://github.com/nordnet/python-freeipa-json/blob/master/ipahttp/ipahttp.py)  -- 详细的请求文件地址：python-freeipa-json/ipahttp/ipahttp.py
                                                                                                                                
### 终极版
- 项目里面有一些测试的代码无关紧要，下面展示一下正式版代码
- okhttp3打日志：
```java
public class HttpLogger implements HttpLoggingInterceptor.Logger {
    @Override
    public void log(String s) {
       log.info(s);
    }
}
```
- OkHttpClientConfig
```java
/**
 * Created by claire on 2019-09-10 - 15:02
 **/
@Configuration
public class OkHttpClientConfig {

    @Autowired
    private ICacheService cacheService;
    @Autowired
    private IpaProperties ipaProperties;

    private SSLSocketFactory createSSLSocketFactory() {
        SSLSocketFactory ssfFactory = null;

        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[]{new TrustCerts()}, new SecureRandom());
            ssfFactory = sc.getSocketFactory();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        return ssfFactory;
    }

    @Bean
    public ConnectionPool pool() {
        return new ConnectionPool(200, 5, TimeUnit.MINUTES);
    }

    @Bean
    public OkHttpClient okHttpClient() {
        HttpLoggingInterceptor loggingInterceptor = new HttpLoggingInterceptor(new HttpLogger());
        loggingInterceptor.setLevel(HttpLoggingInterceptor.Level.BODY);


        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .retryOnConnectionFailure(false)
                .connectionPool(pool())
                .sslSocketFactory(createSSLSocketFactory())
                .cookieJar(new RequestCookieJar(cacheService,ipaProperties))
                .hostnameVerifier((hostname, session) -> true)
                .addNetworkInterceptor(loggingInterceptor);

        return builder.build();
    }
}

```
- 存cookie的
```java
@Component
public class RequestCookieJar implements CookieJar {
    public static final String LOGIN_SERVICE = "/ipa/session/login_password";
    private ICacheService cacheService;
    private IpaProperties ipaProperties;
    private String loginRequestFullUrl="";


    public RequestCookieJar(ICacheService cacheService,IpaProperties ipaProperties){
        this.cacheService = cacheService;
        this.ipaProperties = ipaProperties;
        if(StringUtils.isNotBlank(ipaProperties.getBaseUrl())){
            loginRequestFullUrl+= (ipaProperties.getBaseUrl()+LOGIN_SERVICE);
        }
    }

    @Override
    public void saveFromResponse(HttpUrl url, List<Cookie> cookies) {
        RListMultimapCache<String, CookieDTO> cookieListMap = cacheService.getCookieListMap();
        if(!cookieListMap.containsKey(url.toString())){
            if(cookies.size() != 0) {
                List<CookieDTO> cookieDTOS = cookies.stream().map(this::transCookie2DTO).collect(Collectors.toList());
                if(cookieDTOS.size() != 0) {
                    cookieListMap.putAll(url.toString(), cookieDTOS);
                    cookieListMap.expireKey(url.toString(), 29, TimeUnit.MINUTES);
                }
            }
        }
    }

    @Override
    public List<Cookie> loadForRequest(HttpUrl url) {
        if(!url.toString().contains(LOGIN_SERVICE)) {
            RListMultimapCache<String, CookieDTO> cookieListMap = cacheService.getCookieListMap();
            if (cookieListMap.containsKey(loginRequestFullUrl)) {
                RList<CookieDTO> cookies = cookieListMap.get(loginRequestFullUrl);
                if(cookies != null && cookies.size() !=0) {
                    List<Cookie> cookieList = cookies.stream().map(this::transDTO2Cookie).collect(Collectors.toList());
                    if(cookieList.size() != 0) {
                        return cookieList;
                    }
                }
            }
        }
        return  Collections.emptyList();
    }

    private CookieDTO transCookie2DTO(Cookie cookie){
        CookieDTO dto = new CookieDTO();
        if(StringUtils.isNotBlank(cookie.domain())){
            dto.setDomain(cookie.domain());
        }
        if(StringUtils.isNotBlank(cookie.name())){
            dto.setName(cookie.name());
        }

        if(StringUtils.isNotBlank(cookie.path())){
            dto.setPath(cookie.path());
        }

        if(StringUtils.isNotBlank(cookie.value())){
            dto.setValue(cookie.value());
        }
        dto.setExpiresAt(cookie.expiresAt());
        return dto;

    }
    private Cookie transDTO2Cookie(CookieDTO dto){
        Cookie.Builder builder = new Cookie.Builder();
        //secure = true
        //httponly = true
        //hostholy = false
        builder.domain(dto.getDomain());
        builder.expiresAt(dto.getExpiresAt());
        builder.name(dto.getName());
        builder.path(dto.getPath());
        builder.value(dto.getValue());
        return builder.build();
    }
}

```
- 信任证书
```java
public class TrustCerts implements X509TrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public X509Certificate[] getAcceptedIssuers() {return new X509Certificate[0];}

}
```
- shiro和redisson的配置就不展示了
- 接口返回值IPAResponse
```java
@JsonIgnoreProperties(ignoreUnknown = true)
public class IPAResponse {
    private IPAResult result;
    private String version;
    private String error;
    private String id;
    private String principal;

    public IPAResult getResult() {
        return result;
    }

    public void setResult(IPAResult result) {
        this.result = result;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getPrincipal() {
        return principal;
    }

    public void setPrincipal(String principal) {
        this.principal = principal;
    }
}

public class IPAResult {

    private Map<String,Object> result;
    private String value;
    private String summary;

    public Map<String, Object> getResult() {
        return result;
    }

    public void setResult(Map<String, Object> result) {
        this.result = result;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }
}

```
- FreeIpaAuthenticationManager 接口调用，这些代码都是从这边的尝试里面积累而来的
```java
@Slf4j
@Component
public class FreeIpaAuthenticationManager {

    @Autowired
    private ICacheService cacheService;
    @Autowired
    private IpaProperties ipaProperties;


    public boolean auth(String user, String password) {
        if (StringUtils.isNotBlank(ipaProperties.getBaseUrl())) {
            String baseUrl = ipaProperties.getBaseUrl();
            String refer = baseUrl + IPARequestConstant.LOGIN_SERVICE;
            //header
            Map<String, String> headMap = new HashMap<>();
            headMap.put(HttpHeaders.REFERER, refer);
            headMap.put(HttpHeaders.ACCEPT, MediaType.TEXT_PLAIN_VALUE);
            headMap.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
            //param
            Map<String, String> params = new HashMap<>();
            params.put(IPARequestConstant.USER_NAME, user);
            params.put(IPARequestConstant.USER_PASSWORD, password);

            //AUTH前，需清除之前的所有缓存
            RListMultimapCache<String, CookieDTO> cookieListMap = cacheService.getCookieListMap();
            cookieListMap.clear();

            String response = HttpClientUtils.postFormParams(refer, params, headMap);
            return null != response;
        }
        return false;
    }

    public void showUser(String username) throws IOException {
        if (StringUtils.isNotBlank(ipaProperties.getBaseUrl())) {
            String baseUrl = ipaProperties.getBaseUrl();
            String refer = baseUrl + IPARequestConstant.LOOKUP_REFERER;
            String requestUrl = baseUrl + IPARequestConstant.LOOKUP_SERVICE;
            //param
            String params = IPARequestConstant.buildUserRequestInfo(username);
            //header
            Map<String, String> headMap = new HashMap<>();
            headMap.put(HttpHeaders.REFERER, refer);
            headMap.put(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
            headMap.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

            String response = HttpClientUtils.postJsonParams(requestUrl, params, headMap);
            if (StringUtils.isNotBlank(response)) {
                ObjectMapper objectMapper = new ObjectMapper();
                try {
                    IPAResponse ipaResponse = objectMapper.readValue(response, IPAResponse.class);
                    IPAResult result = ipaResponse.getResult();
                } catch (Exception e) {
                    log.error("解析响应字符串异常，认证最终失败");
                    e.printStackTrace();
                }
            }
        }
    }
}
```
- 最后一个辅助类 HttpClientUtils
```java
@Slf4j
public class HttpClientUtils {
    private static String execNewCall(Request request){
        Response response = null;
        try {
           OkHttpClient okHttpClient = SpringContextUtil.getBean(OkHttpClient.class);
            response = okHttpClient.newCall(request).execute();
            if(okHttpClient.cookieJar() != CookieJar.NO_COOKIES){
                List<Cookie> cookies = Cookie.parseAll(request.url(), response.headers());
                if(!cookies.isEmpty()){
                    okHttpClient.cookieJar().saveFromResponse(request.url(),cookies);
                }
            }
            int status = response.code();
            if (status == 200 && response.isSuccessful()) {
                return response.body().string();
            }
        } catch (Exception e) {
            log.error("okhttp3 put error >> ex = {}", ExceptionUtils.getStackTrace(e));
        } finally {
            if (response != null) {
                response.close();
            }
        }
        return null;
    }

    public static String postFormParams(String url, Map<String, String> params,Map<String, String> headerParamsMap) {
        FormBody.Builder builder = new FormBody.Builder();
        //添加参数
        if (params != null && params.keySet().size() > 0) {
            for (String key : params.keySet()) {
                builder.add(key, params.get(key));
            }
        }
        Request.Builder builder1 = new Request.Builder();
        if(headerParamsMap != null && headerParamsMap.keySet().size()>0){
            Headers headers = Headers.of(headerParamsMap);
            builder1.headers(headers);
        }
        Request request = builder1
                .url(url)
                .post(builder.build())
                .build();
        return execNewCall(request);
    }

    public static String postJsonParams(String url, String jsonParams,Map<String, String> headerParamsMap ) {
        RequestBody requestBody = RequestBody.create(MediaType.parse("application/json; charset=utf-8"), jsonParams);
        Request.Builder builder = new Request.Builder()
                .url(url)
                .post(requestBody);
        if(headerParamsMap != null && !headerParamsMap.isEmpty()) {
            Headers headers = Headers.of(headerParamsMap);
            builder.headers(headers);
        }
        return execNewCall(builder.build());
    }

    public static String postJsonParams(String url, String jsonParams) {
        RequestBody requestBody = RequestBody.create(MediaType.parse("application/json; charset=utf-8"), jsonParams);
        Request request = new Request.Builder()
                .url(url)
                .post(requestBody)
                .build();
        return execNewCall(request);
    }
}
```
- 测试一下，这个就可以放在Shiro的Realm里面，结合本地做身份认证
```txt
 @Test
    public void testLogin() throws IOException {
        if (authenticationManager.auth("user", "password")) {
            authenticationManager.showUser("user");
        }
    }
```

### 实验过程中一个BUG
- 一个很奇怪竟然不知道是为什么的bug
```$xslt
WARNING     -- [2019-09-10 16:15:27 CEST] -- HttpRequestGroup::executeRequest(): Error running command https://@{host}:8080/platform/1/statistics/current?key=node.disk.name.0&[full request omitted for sake of clarity]&devid=all on host isilon for requests group ISILON2-NODE-DISK-PERFORMANCE-METRICS
java.lang.ClassCastException: [B cannot be cast to java.lang.String
    at org.apache.http.conn.ssl.DefaultHostnameVerifier.getSubjectAltNames(DefaultHostnameVerifier.java:309)
    at org.apache.http.conn.ssl.AbstractVerifier.verify(AbstractVerifier.java:136)
    at org.apache.http.conn.ssl.AbstractVerifier.verify(AbstractVerifier.java:123)
    at org.apache.http.conn.ssl.SSLConnectionSocketFactory.verifyHostname(SSLConnectionSocketFactory.java:463)
    at org.apache.http.conn.ssl.SSLConnectionSocketFactory.createLayeredSocket(SSLConnectionSocketFactory.java:397)
    at org.apache.http.conn.ssl.SSLConnectionSocketFactory.connectSocket(SSLConnectionSocketFactory.java:355)
    at org.apache.http.impl.conn.DefaultHttpClientConnectionOperator.connect(DefaultHttpClientConnectionOperator.java:142)
    at org.apache.http.impl.conn.PoolingHttpClientConnectionManager.connect(PoolingHttpClientConnectionManager.java:359)
    at org.apache.http.impl.execchain.MainClientExec.establishRoute(MainClientExec.java:381)
    at org.apache.http.impl.execchain.MainClientExec.execute(MainClientExec.java:237)
    at org.apache.http.impl.execchain.ProtocolExec.execute(ProtocolExec.java:185)
    at org.apache.http.impl.execchain.RetryExec.execute(RetryExec.java:89)
    at org.apache.http.impl.execchain.RedirectExec.execute(RedirectExec.java:111)
    at org.apache.http.impl.client.InternalHttpClient.doExecute(InternalHttpClient.java:185)
    at org.apache.http.impl.client.CloseableHttpClient.execute(CloseableHttpClient.java:72)
    at 
```  
- 然后找到了一个帖，说是版本问题 
```$xslt
After upgrade to HttpClient 4.5.3, all of a sudden I started to receive the following exception in one of my projects:
java.lang.ClassCastException: [B cannot be cast to java.lang.String
```
- 果然，我将httpclient的版本升级到4.5.5就可以了，隐藏的有点深
- [refer](https://community.emc.com/docs/DOC-64472)