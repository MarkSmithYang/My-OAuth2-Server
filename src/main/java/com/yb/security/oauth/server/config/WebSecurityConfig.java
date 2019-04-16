package com.yb.security.oauth.server.config;

import com.yb.security.oauth.server.impl.UserDetailsServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.servlet.http.HttpServletResponse;

/**
 * Description: 安全配置
 * EnableWebSecurity---启用安全配置
 * EnableGlobalMethodSecurity 启用全局方法安全注解,就可以在方法上使用注解来对请求进行过滤
 * author biaoyang
 * date 2019/4/9 000911:29
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)//使用表达式实现方法级别的安全性有4个注解可用
//@EnableGlobalAuthentication//这个应该是包含了上面的@EnableGlobalMethodSecurity的功能的,是个更大范围的控制
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private static final Logger log = LoggerFactory.getLogger(WebSecurityConfig.class);

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 这个方法是必要的,而且需要加@Bean注释,实例化一个AuthenticationManager,
     * 不然其他的地方就无法注入此类(实例)--实测(开始以为无关紧要)
     *
     * @return
     * @throws Exception
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        log.info("WebSecurityConfig======authenticationManagerBean()");
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        log.info("WebSecurityConfig======configure(HttpSecurity http)");
        //设置密码加密,查了下发现是spring security 版本在5.0后就要加个PasswordEncoder了,官推是BCryptPasswordEncoder
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        log.info("WebSecurityConfig======configure(HttpSecurity http)");
        http.csrf().and().httpBasic().disable()
                //设置无权限访问时的响应提示,默认是403的无权访问
                .exceptionHandling().authenticationEntryPoint((request, response, exception) -> {
            response.setCharacterEncoding("UTF-8");
            response.setHeader("Content-Type", "application/json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getOutputStream().write("请登录".getBytes());
        }).and()
                .authorizeRequests()
                //这里设置了全部放过---
                .antMatchers("/","/oauth/token").permitAll()
                .anyRequest().authenticated();
    }

    //下面是自定义的身份认证类,仅供参考
//==============================================================================================
//    /**
//     * @author yangbiao
//     * @Description:自定义身份认证类
//     * @date 2018/11/30
//     */
//    @Component
//    public class CustomAuthenticationProvider implements AuthenticationProvider {
//
//        @Autowired
//        private UserDetailsServiceImpl userDetailsServiceImpl;
//
//        /**
//         * 自定义认证的实现方法
//         */
//        @Override
//        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//            //把对象转换为json字符串,传递到loadUserByUsername里进行处理,这样可以减少查询用户的次数
//            String authen = JSONObject.toJSON(authentication).toString();
//            //获取Security自带的详情信息(主要是用户名密码一级一些锁定账户,账户是否可用的信息)
//            UserDetails userDetails = userDetailsServiceImpl.loadUserByUsername(authen);
//            //构造token对象--因为在那边已经sysUser会抛出异常,所以正常返回的都是能构造成功的,所以UserDetails不会为空
//            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
//                    userDetails.getUsername(), userDetails.getPassword(), userDetails.getAuthorities());
//            //设置用户详情信息
//            token.setDetails(userDetails);
//            //返回令牌信息
//            return token;
//        }
//
//        @Override
//        public boolean supports(Class<?> aClass) {
//            //是否可以提供输入类型的认证服务
//            return aClass.equals(UsernamePasswordAuthenticationToken.class);
//        }
//    }
//==============================================================================================

    //下面是自己整合的demo的信息
//==============================================================================================
//    @Autowired
//    private AuthenticationEntryPointImpl authenticationEntryPoint;
//    @Autowired
//    private CustomAuthenticationProvider customAuthenticationProvider;
//    @Autowired
//    private RedisSecurityContextRepository redisSecurityContextRepository;
//    @Autowired
//    private AccessDeniedHandlerImpl accessDeniedHandlerImpl;
//
//    @Value("${allow.common.url}")
//    private String[] commonUrl;
//    @Value("${allow.server.url}")
//    private String[] serverUrl;
//
//    /**
//     * 设置 HTTP 验证规则
//     */
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        //解决SpringBoot不允许加载iframe问题
//        http.headers().frameOptions().disable();
//        //关闭默认的登录认证
//        http.httpBasic().disable()
//                //添加处理ajxa的类实例
//                .exceptionHandling().accessDeniedHandler(accessDeniedHandlerImpl)
//                //添加拦截未登录用户访问的提示类实例,因为AuthenticationEntryPoint接口只有一个方法,可以用lambda来直接实现,而不用写类注入
//                .authenticationEntryPoint(authenticationEntryPoint).and()
//                //添加改session为redis存储实例
//                .securityContext().securityContextRepository(redisSecurityContextRepository).and()
//                //把session的代理创建关闭
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
//
//        // 关闭csrf验证,我们用jwt的token就不需要了
//        http.csrf().disable()
//                //对请求进行认证
//                .authorizeRequests()
//                //所有带/的请求都放行-->可以统一放到配置文件,然后读取过来,那样更方便修改特别是使用云配置的那种更方便
//                //放开登录和验证码相关的接口(建议不要加层路径例如/auth,
//                //会导致/security下的其他的不想放开的接口被放开等问题,直接放确定的最好,方正也没有几个接口)
//                .antMatchers(serverUrl).permitAll()
//                //.antMatchers(HttpMethod.GET, commonUrl).permitAll()//这个下面已经设置的了
//                //访问指定路径的ip地址校验,访问指定路径的权限校验--这些接口需要的权限可以通过注解@PreAuthorize等来设置
//                //.antMatchers("/auth/yes").hasIpAddress("192.168.11.130")//这个注解目前还没发现,可以在这里设置
//                //所有请求需要身份认证
//                .anyRequest().authenticated().and()
//                //添加一个过滤器,对其他请求的token进行合法性认证
//                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
//
//    }
//
//    //解决过滤器无法注入(依赖)Bean的问题
//    @Bean
//    public JwtAuthenticationFilter jwtAuthenticationFilter() {
//        return new JwtAuthenticationFilter();
//    }
//
//    /**
//     * 使用自定义身份验证组件
//     * Spring Security中进行身份验证的是AuthenticationManager接口，ProviderManager是它的一个默认实现，
//     * 但它并不用来处理身份认证，而是委托给配置好的AuthenticationProvider，每个AuthenticationProvider
//     * 会轮流检查身份认证。检查后或者返回Authentication对象或者抛出异常。
//     */
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        //使用自定义身份验证(组件)
//        auth.authenticationProvider(customAuthenticationProvider);
//    }
//
//    @Override
//    public void configure(WebSecurity web){
//        // 设置不拦截规则,这里确实会优先上面的生效,其实如果这里设置了,上面就不用设置了
//        web.ignoring().antMatchers(HttpMethod.GET,commonUrl);
//    }
//==============================================================================================


    //下面是网上的写法,因为许多类已经加了spring的实例化注解了,所以可以直接注入使用,而不用@Bean再实例化了
//==============================================================================================
//    /**
//     * 注入用户信息服务
//     * @return 用户信息服务对象
//     */
//    @Bean
//    public UserDetailsService userDetailsService() {
//        return new UserDetailsServiceImpl();
//    }
//
//    /**
//     * 全局用户信息
//     * @param auth 认证管理
//     * @throws Exception 用户认证异常信息
//     */
//    @Autowired
//    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userDetailsService());
//    }
//
//    /**
//     * 认证管理
//     * @return 认证管理对象
//     * @throws Exception 认证异常信息
//     */
//    @Override
//    @Bean
//    public AuthenticationManager authenticationManagerBean() throws Exception {
//        return super.authenticationManagerBean();
//    }
//
//    /**
//     * http安全配置
//     * @param http http安全对象
//     * @throws Exception http安全异常信息
//     */
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests().antMatchers(HttpMethod.OPTIONS).permitAll().anyRequest().authenticated().and()
//                .httpBasic().and().csrf().disable();
//    }
}
