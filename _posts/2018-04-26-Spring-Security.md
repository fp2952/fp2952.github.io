---
layout: post
title:  "Spring Boot 整合 Spring Security "
date:   2016-05-13 13:25:35 +0200
categories: jekyll update
---

在本例中，主要讲解spring-boot与spring-security的集成，实现方式为：

* 将用户、权限、资源（url）采用数据库存储  
* 自定义过滤器，代替原有的 FilterSecurityInterceptor
* 自定义实现 UserDetailsService、AccessDecisionManager和InvocationSecurityMetadataSourceService，并在配置文件进行相应的配置
 
## 用户角色表（基于RBAC权限控制）
* 用户表(base_user)

| code | type | length | 
| --- | --- | --- | 
| ID | varchar| 32 | 
| USER_NAME | varchar | 50 | 
| USER_PASSWORD | varchar | 100 |
| NIKE_NAME | varchar | 50 |
| STATUS | int | 11 |

* 用户角色表(base_user_role)

| code | type | length | 
| --- | --- | --- | 
| ID | varchar| 32 | 
| USER_ID | varchar | 32 | 
| ROLE_ID | varchar | 32 |

* 角色表(base_role)

| code | type | length | 
| --- | --- | --- | 
| ID | varchar| 32 | 
| ROLE_CODE | varchar | 32 | 
| ROLE_NAME | varchar | 64 |

* 角色菜单表(base_role_menu)

| code | type | length | 
| --- | --- | --- | 
| ID | varchar| 32 | 
| ROLE_ID | varchar | 32 | 
| MENU_ID | varchar | 32 |

* 菜单表(base_menu)

| code | type | length | 
| --- | --- | --- | 
| ID | varchar| 32 | 
| MENU_URL | varchar | 120 | 
| MENU_SEQ | varchar | 120 |
| MENU_PARENT_ID | varchar| 32 | 
| MENU_NAME | varchar | 50 | 
| MENU_ICON | varchar | 20 |
| MENU_ORDER | int | 11 | 
| IS_LEAF | varchar | 20 |

## 实现主要配置类 

### 实现AbstractAuthenticationProcessingFilter 
用于用户表单验证，内部调用了authenticationManager完成认证，根据认证结果执行successfulAuthentication或者unsuccessfulAuthentication，无论成功失败，一般的实现都是转发或者重定向等处理。
```
   @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        if (postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException(
                    "Authentication method not supported: " + request.getMethod());
        }
        //获取表单中的用户名和密码
        String username = obtainUsername(request);
        String password = obtainPassword(request);
        if (username == null) {
            username = "";
        }
        if (password == null) {
            password = "";
        }
        username = username.trim();
        //组装成username+password形式的token
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                username, password);
        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);
        //交给内部的AuthenticationManager去认证，并返回认证信息
        return this.getAuthenticationManager().authenticate(authRequest);
    }
```


### AuthenticationManager
AuthenticationManager是一个用来处理认证（Authentication）请求的接口。在其中只定义了一个方法authenticate()，该方法只接收一个代表认证请求的Authentication对象作为参数，如果认证成功，则会返回一个封装了当前用户权限等信息的Authentication对象进行返回。
``Authentication authenticate(Authentication authentication) throws AuthenticationException;``
在Spring Security中，AuthenticationManager的默认实现是ProviderManager，而且它不直接自己处理认证请求，而是委托给其所配置的AuthenticationProvider列表，然后会依次使用每一个AuthenticationProvider进行认证，如果有一个AuthenticationProvider认证后的结果不为null，则表示该AuthenticationProvider已经认证成功，之后的AuthenticationProvider将不再继续认证。然后直接以该AuthenticationProvider的认证结果作为ProviderManager的认证结果。如果所有的AuthenticationProvider的认证结果都为null，则表示认证失败，将抛出一个ProviderNotFoundException。  
校验认证请求最常用的方法是根据请求的用户名加载对应的UserDetails，然后比对UserDetails的密码与认证请求的密码是否一致，一致则表示认证通过。  
Spring Security内部的DaoAuthenticationProvider就是使用的这种方式。其内部使用UserDetailsService来负责加载UserDetails。在认证成功以后会使用加载的UserDetails来封装要返回的Authentication对象，加载的UserDetails对象是包含用户权限等信息的。认证成功返回的Authentication对象将会保存在当前的SecurityContext中。

### 实现UserDetailsService
UserDetailsService只定义了一个方法 loadUserByUsername，根据用户名可以查到用户并返回的方法。

```
@Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.debug("权限框架-加载用户");
        List<GrantedAuthority> auths = new ArrayList<>();

        BaseUser baseUser = new BaseUser();
        baseUser.setUserName(username);
        baseUser = baseUserService.selectOne(baseUser);

        if (baseUser == null) {
            logger.debug("找不到该用户 用户名:{}", username);
            throw new UsernameNotFoundException("找不到该用户！");
        }
        if(baseUser.getStatus()==2)
        {
            logger.debug("用户被禁用，无法登陆 用户名:{}", username);
            throw new UsernameNotFoundException("用户被禁用！");
        }
        List<BaseRole> roles = baseRoleService.selectRolesByUserId(baseUser.getId());
        if (roles != null) {
            //设置角色名称
            for (BaseRole role : roles) {
                SimpleGrantedAuthority authority = new SimpleGrantedAuthority(role.getRoleCode());
                auths.add(authority);
            }
        }

        return new org.springframework.security.core.userdetails.User(baseUser.getUserName(), baseUser.getUserPassword(), true, true, true, true, auths);
    }
```

### 实现AbstractSecurityInterceptor
访问url时，会被AbstractSecurityInterceptor拦截器拦截，然后调用FilterInvocationSecurityMetadataSource的方法来获取被拦截url所需的全部权限，再调用授权管理器AccessDecisionManager鉴权。  
```
public class CustomSecurityInterceptor extends AbstractSecurityInterceptor implements Filter {
    private FilterInvocationSecurityMetadataSource securityMetadataSource;
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(request, response, chain);
        invoke(fi);
    }
    @Override
    public void destroy() {
    }
    @Override
    public Class<?> getSecureObjectClass() {
        return FilterInvocation.class;
    }
    @Override
    public SecurityMetadataSource obtainSecurityMetadataSource() {
        return this.securityMetadataSource;
    }
    public void invoke(FilterInvocation fi) throws IOException {
        InterceptorStatusToken token = super.beforeInvocation(fi);
        try {
            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        } catch (ServletException e) {
            super.afterInvocation(token, null);
        }
    }
    public FilterInvocationSecurityMetadataSource getSecurityMetadataSource() {
        return securityMetadataSource;
    }

    public void setSecurityMetadataSource(FilterInvocationSecurityMetadataSource securityMetadataSource) {
        this.securityMetadataSource = securityMetadataSource;
    }
}
```

### FilterInvocationSecurityMetadataSource 获取所需权限
```
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        //获取当前访问url
        String url = ((FilterInvocation) object).getRequestUrl();
        int firstQuestionMarkIndex = url.indexOf("?");
        if (firstQuestionMarkIndex != -1) {
            url = url.substring(0, firstQuestionMarkIndex);
        }
        List<ConfigAttribute> result = new ArrayList<>();

        try {
            //设置不拦截
            if (propertySourceBean.getProperty("security.ignoring") != null) {
                String[] paths = propertySourceBean.getProperty("security.ignoring").toString().split(",");
                //判断是否符合规则
                for (String path: paths) {
                    String temp = StringUtil.clearSpace(path);
                    if (matcher.match(temp, url)) {
                        return SecurityConfig.createList("ROLE_ANONYMOUS");
                    }
                }
            }

            //如果不是拦截列表里的, 默认需要ROLE_ANONYMOUS权限
            if (!isIntercept(url)) {
                return SecurityConfig.createList("ROLE_ANONYMOUS");
            }

            //查询数据库url匹配的菜单
            List<BaseMenu> menuList = baseMenuService.selectMenusByUrl(url);
            if (menuList != null && menuList.size() > 0) {
                for (BaseMenu menu : menuList) {
                    //查询拥有该菜单权限的角色列表
                    List<BaseRole> roles = baseRoleService.selectRolesByMenuId(menu.getId());
                    if (roles != null && roles.size() > 0) {
                        for (BaseRole role : roles) {
                            ConfigAttribute conf = new SecurityConfig(role.getRoleCode());
                            result.add(conf);
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

     /**
     * 判断是否需要过滤
     * @param url
     * @return
     */
    public boolean isIntercept(String url) {
        String[] filterPaths = propertySourceBean.getProperty("security.intercept").toString().split(",");
        for (String filter: filterPaths) {
            if (matcher.match(StringUtil.clearSpace(filter), url) & !matcher.match(indexUrl, url)) {
                return true;
            }
        }

        return false;
    }
```

### AccessDecisionManager 鉴权
```
    @Override
    public void decide(Authentication authentication, Object o, Collection<ConfigAttribute> collection) throws AccessDeniedException, InsufficientAuthenticationException {
        if (collection == null) {
            return;
        }
        for (ConfigAttribute configAttribute : collection) {
            String needRole = configAttribute.getAttribute();
            for (GrantedAuthority ga : authentication.getAuthorities()) {
                if (needRole.trim().equals(ga.getAuthority().trim()) || needRole.trim().equals("ROLE_ANONYMOUS")) {
                    return;
                }
            }
        }
        throw new AccessDeniedException("无权限！");
    }
```

### 配置 WebSecurityConfigurerAdapter
```
/**
 * spring-security配置
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PropertySource propertySourceBean;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        logger.debug("权限框架配置");

        String[] paths = null;
        //设置不拦截
        if (propertySourceBean.getProperty("security.ignoring") != null) {
            paths = propertySourceBean.getProperty("security.ignoring").toString().split(",");
            paths = StringUtil.clearSpace(paths);
        }

        //设置过滤器
        http    // 根据配置文件放行无需验证的url
                .authorizeRequests().antMatchers(paths).permitAll()
                .and()
                .httpBasic()
                // 配置验证异常处理
                .authenticationEntryPoint(getCustomLoginAuthEntryPoint())
                // 配置登陆过滤器
                .and().addFilterAt(getCustomLoginFilter(), UsernamePasswordAuthenticationFilter.class)
                // 配置 AbstractSecurityInterceptor
                .addFilterAt(getCustomSecurityInterceptor(), FilterSecurityInterceptor.class)
                // 登出成功处理
                .logout().logoutSuccessHandler(getCustomLogoutSuccessHandler())
                // 关闭csrf
                .and().csrf().disable()
                // 其他所有请求都需要验证
                .authorizeRequests().anyRequest().authenticated()
                // 配置登陆url, 登陆页面并无需验证
                .and().formLogin().loginProcessingUrl("/login").loginPage("/login.ftl").permitAll()
                // 登出
                .and().logout().logoutUrl("/logout").permitAll();
        
        logger.debug("配置忽略验证url");

    }

    @Autowired
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.authenticationProvider(getDaoAuthenticationProvider());
    }


    /**
     * spring security 配置
     * @return
     */
    @Bean
    public CustomLoginAuthEntryPoint getCustomLoginAuthEntryPoint() {
        return new CustomLoginAuthEntryPoint();
    }

    /**
     * 用户验证
     * @return
     */
    @Bean
    public DaoAuthenticationProvider getDaoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setHideUserNotFoundExceptions(false);
        provider.setPasswordEncoder(new BCryptPasswordEncoder());
        return provider;
    }

    /**
     * 登陆
     * @return
     */
    @Bean
    public CustomLoginFilter getCustomLoginFilter() {
        CustomLoginFilter filter = new CustomLoginFilter();
        try {
            filter.setAuthenticationManager(this.authenticationManagerBean());
        } catch (Exception e) {
            e.printStackTrace();
        }
        filter.setAuthenticationSuccessHandler(getCustomLoginAuthSuccessHandler());
        filter.setAuthenticationFailureHandler(new CustomLoginAuthFailureHandler());

        return filter;
    }

    @Bean
    public CustomLoginAuthSuccessHandler getCustomLoginAuthSuccessHandler() {
        CustomLoginAuthSuccessHandler handler =  new CustomLoginAuthSuccessHandler();
        if (propertySourceBean.getProperty("security.successUrl")!=null){
            handler.setAuthSuccessUrl(propertySourceBean.getProperty("security.successUrl").toString());
        }
        return handler;
    }

    /**
     * 登出
     * @return
     */
    @Bean
    public CustomLogoutSuccessHandler getCustomLogoutSuccessHandler() {
        CustomLogoutSuccessHandler handler = new CustomLogoutSuccessHandler();
        if (propertySourceBean.getProperty("security.logoutSuccessUrl")!=null){
            handler.setLoginUrl(propertySourceBean.getProperty("security.logoutSuccessUrl").toString());
        }
        return handler;
    }

    /**
     * 过滤器
     * @return
     */
    @Bean
    public CustomSecurityInterceptor getCustomSecurityInterceptor() {
        CustomSecurityInterceptor interceptor = new CustomSecurityInterceptor();
        interceptor.setAccessDecisionManager(new CustomAccessDecisionManager());
        interceptor.setSecurityMetadataSource(getCustomMetadataSourceService());
        try {
            interceptor.setAuthenticationManager(this.authenticationManagerBean());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return interceptor;
    }
    
    @Bean
    public CustomMetadataSourceService getCustomMetadataSourceService() {
        CustomMetadataSourceService sourceService = new CustomMetadataSourceService();
        if (propertySourceBean.getProperty("security.successUrl")!=null){
            sourceService.setIndexUrl(propertySourceBean.getProperty("security.successUrl").toString());
        }
        return sourceService;
    }
}
```