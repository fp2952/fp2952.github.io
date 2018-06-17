---
layout: post
title:  "Spring Cloud OAuth2（一） 搭建授权服务"
date:   2016-05-13 13:25:35 +0200
categories: jekyll update
---

## 概要
本文内容主要为spring cloud 授权服务的搭建，采用jwt认证。  
GitHub 地址：<https://github.com/fp2952/spring-cloud-base/tree/master/auth-center/auth-center-provider>


## 添加依赖
Spring Security 及 Security 的OAuth2 扩展  

```
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-oauth2</artifactId>
        </dependency>
```


## 启动类注解
启动类添加 `@EnableAuthorizationServer` 注解  

```
@SpringCloudApplication
@EnableAuthorizationServer
@EnableFeignClients("com.peng.main.client")
public class AuthCenterProviderApplication {
   public static void main(String[] args){
       SpringApplication.run(AuthCenterProviderApplication.class, args);
   }
}
```



## Oauth2配置类AuthorizationServerConfigurerAdapter
AuthorizationServerConfigurerAdapter中:  

* ClientDetailsServiceConfigurer：用来配置客户端详情服务（ClientDetailsService），客户端详情信息在这里进行初始化，你能够把客户端详情信息写死在这里或者是通过数据库来存储调取详情信息。
* AuthorizationServerSecurityConfigurer：用来配置令牌端点(Token Endpoint)的安全约束.
* AuthorizationServerEndpointsConfigurer：用来配置授权（authorization）以及令牌（token）的访问端点和令牌服务(token services)。
主要配置如下：

### 配置客户端详情信息（Client Details)
ClientDetailsServiceConfigurer (AuthorizationServerConfigurer 的一个回调配置项) 能够使用内存或者JDBC来实现客户端详情服务（ClientDetailsService），Spring Security OAuth2的配置方法是编写@Configuration类继承AuthorizationServerConfigurerAdapter，然后重写void configure(ClientDetailsServiceConfigurer clients)方法，如：  

```
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // 使用JdbcClientDetailsService客户端详情服务
        clients.withClientDetails(new JdbcClientDetailsService(dataSource));
    }
```

这里使用Jdbc实现客户端详情服务，数据源dataSource不做叙述，使用框架默认的表，schema链接：  
<https://github.com/spring-projects/spring-security-oauth/blob/master/spring-security-oauth2/src/test/resources/schema.sql>



### 配置令牌 管理 (jwtAccessTokenConverter)
JwtAccessTokenConverter是用来生成token的转换器，而token令牌默认是有签名的，且资源服务器需要验证这个签名。此处的加密及验签包括两种方式：  
对称加密、非对称加密（公钥密钥）  
对称加密需要授权服务器和资源服务器存储同一key值，而非对称加密可使用密钥加密，暴露公钥给资源服务器验签，本文中使用非对称加密方式，配置于AuthorizationServerConfigurerAdapter如下：  

```
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.authenticationManager(authenticationManager)
                // 配置JwtAccessToken转换器
                .accessTokenConverter(jwtAccessTokenConverter())
                // refresh_token需要userDetailsService
                .reuseRefreshTokens(false).userDetailsService(userDetailsService);
                //.tokenStore(getJdbcTokenStore());
    }

    /**
     * 使用非对称加密算法来对Token进行签名
     * @return
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {

        final JwtAccessTokenConverter converter = new JwtAccessToken();
        // 导入证书
        KeyStoreKeyFactory keyStoreKeyFactory =
                new KeyStoreKeyFactory(new ClassPathResource("keystore.jks"), "mypass".toCharArray());
        converter.setKeyPair(keyStoreKeyFactory.getKeyPair("mytest"));

        return converter;
    }
```


通过 JDK 工具生成 JKS 证书文件，并将 keystore.jks 放入resource目录下
`keytool -genkeypair -alias mytest -keyalg RSA -keypass mypass -keystore keystore.jks -storepass mypass`


此处我们自定义JwtAccessToken用于添加额外用户信息  

```
/**
 * Created by fp295 on 2018/4/16.
 * 自定义JwtAccessToken转换器
 */
public class JwtAccessToken extends JwtAccessTokenConverter {

    /**
     * 生成token
     * @param accessToken
     * @param authentication
     * @return
     */
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        DefaultOAuth2AccessToken defaultOAuth2AccessToken = new DefaultOAuth2AccessToken(accessToken);

        // 设置额外用户信息
        BaseUser baseUser = ((BaseUserDetail) authentication.getPrincipal()).getBaseUser();
        baseUser.setPassword(null);
        // 将用户信息添加到token额外信息中
        defaultOAuth2AccessToken.getAdditionalInformation().put(Constant.USER_INFO, baseUser);

        return super.enhance(defaultOAuth2AccessToken, authentication);
    }

    /**
     * 解析token
     * @param value
     * @param map
     * @return
     */
    @Override
    public OAuth2AccessToken extractAccessToken(String value, Map<String, ?> map){
        OAuth2AccessToken oauth2AccessToken = super.extractAccessToken(value, map);
        convertData(oauth2AccessToken, oauth2AccessToken.getAdditionalInformation());
        return oauth2AccessToken;
    }

    private void convertData(OAuth2AccessToken accessToken,  Map<String, ?> map) {
        accessToken.getAdditionalInformation().put(Constant.USER_INFO,convertUserData(map.get(Constant.USER_INFO)));

    }

    private BaseUser convertUserData(Object map) {
        String json = JsonUtils.deserializer(map);
        BaseUser user = JsonUtils.serializable(json, BaseUser.class);
        return user;
    }
}
```



JwtAccessToken 类中从authentication里的getPrincipal（实际为UserDetails接口）获取用户信息，所以我们需要实现自己的UserDetails  

```
/**
 * Created by fp295 on 2018/4/29.
 * 包装org.springframework.security.core.userdetails.User类
 */
public class BaseUserDetail implements UserDetails, CredentialsContainer {

    private final BaseUser baseUser;
    private final org.springframework.security.core.userdetails.User user;

    public BaseUserDetail(BaseUser baseUser, User user) {
        this.baseUser = baseUser;
        this.user = user;
    }


    @Override
    public void eraseCredentials() {
        user.eraseCredentials();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getAuthorities();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return user.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return user.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return user.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }

    public BaseUser getBaseUser() {
        return baseUser;
    }
}
```


### 授权端点开放
```
    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
        oauthServer
                // 开启/oauth/token_key验证端口无权限访问
                .tokenKeyAccess("permitAll()")
                // 开启/oauth/check_token验证端口认证权限访问
                .checkTokenAccess("isAuthenticated()");
    }
```


## Security 配置
需要配置 DaoAuthenticationProvider、UserDetailService 等  

```
@Configuration
@Order(ManagementServerProperties.ACCESS_OVERRIDE_ORDER)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    // 自动注入UserDetailsService
    @Autowired
    private BaseUserDetailService baseUserDetailService;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http    // 配置登陆页/login并允许访问
                .formLogin().permitAll()
                // 登出页
                .and().logout().logoutUrl("/logout").logoutSuccessUrl("/")
                // 其余所有请求全部需要鉴权认证
                .and().authorizeRequests().anyRequest().authenticated()
                // 由于使用的是JWT，我们这里不需要csrf
                .and().csrf().disable();
    }

    /**
     * 用户验证
     * @param auth
     */
    @Override
    public void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(daoAuthenticationProvider());
    }


    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        // 设置userDetailsService
        provider.setUserDetailsService(baseUserDetailService);
        // 禁止隐藏用户未找到异常
        provider.setHideUserNotFoundExceptions(false);
        // 使用BCrypt进行密码的hash
        provider.setPasswordEncoder(new BCryptPasswordEncoder(6));
        return provider;
    }
}
```

### UserDetailsService 实现
```
@Service
public class BaseUserDetailService implements UserDetailsService {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private BaseUserService baseUserService;
    @Autowired
    private BaseRoleService baseRoleService;
 
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 调用FeignClient查询用户
        ResponseData<BaseUser> baseUserResponseData = baseUserService.getUserByUserName(username);
        if(baseUserResponseData.getData() == null || !ResponseCode.SUCCESS.getCode().equals(baseUserResponseData.getCode())){
            logger.error("找不到该用户，用户名：" + username);
            throw new UsernameNotFoundException("找不到该用户，用户名：" + username);
        }
        BaseUser baseUser = baseUserResponseData.getData();

        // 调用FeignClient查询角色
        ResponseData<List<BaseRole>> baseRoleListResponseData = baseRoleService.getRoleByUserId(baseUser.getId());
        List<BaseRole> roles;
        if(baseRoleListResponseData.getData() == null ||  !ResponseCode.SUCCESS.getCode().equals(baseRoleListResponseData.getCode())){
            logger.error("查询角色失败！");
            roles = new ArrayList<>();
        }else {
            roles = baseRoleListResponseData.getData();
        }

        // 获取用户权限列表
        List<GrantedAuthority> authorities = new ArrayList();
        roles.forEach(e -> {
            // 存储用户、角色信息到GrantedAuthority，并放到GrantedAuthority列表
            GrantedAuthority authority = new SimpleGrantedAuthority(e.getRoleCode());
            authorities.add(authority);
        
        });

        // 返回带有用户权限信息的User
        org.springframework.security.core.userdetails.User user =  new org.springframework.security.core.userdetails.User(baseUser.getUserName(),
                baseUser.getPassword(), isActive(baseUser.getActive()), true, true, true, authorities);
        return new BaseUserDetail(baseUser, user);
    }

    private boolean isActive(int active){
        return active == 1 ? true : false;
    }
}
```


## 授权服务器验证
`http://127.0.0.1:8080/oauth/authorize?client_id=clientId&response_type=code&redirect_uri=www.baidu.com`

注意：client_id：为存储在数据库里的client_id, response_type：写死code

1. 链接回车后进入spring security 的简单登陆页面,  
![](http://112.74.60.248:8080/image/simplelogin.png)  

2. 输入账号密码，为实现的 UserDetailsService 要里获取的用户，点击 login,
3. 进入简单授权页面，点击 Authorize,
4. 重定向到 redirect_uri，并带有 code 参数:
`http://www.baidu.com?code=rTKETX`
5. post请求获取 token:  
![](http://112.74.60.248:8080/image/posttoken.png)
注意，此处需加 `Authorization` 请求头，值为 `Basic xxx` xxx 为 `client_id:client_secret` 的 base64编码。