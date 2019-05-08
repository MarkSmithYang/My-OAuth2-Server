package com.yb.security.oauth.server.config;

import com.yb.security.oauth.server.impl.UserDetailsServiceImpl;
import lombok.AllArgsConstructor;
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
 * -----------------------这个可以和AuthorizationServerConfig整合到一起,因为这个是配合它使用的,
 * 这里做的控制也是针对认证服务器做的,因为它设置放开和不放开都只影响到认证服务器相关的东西,
 * 提供的实例化bean即AuthenticationManager也是给它用的----也可以像这样单独写一个配置
 * author biaoyang
 * date 2019/4/9 000911:29
 */
@EnableWebSecurity
@AllArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true)//使用表达式实现方法级别的安全性有4个注解可用
//@EnableGlobalAuthentication//这个应该是包含了上面的@EnableGlobalMethodSecurity的功能的,是个更大范围的控制
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private static final Logger log = LoggerFactory.getLogger(WebSecurityConfig.class);

    private final UserDetailsServiceImpl userDetailsService;

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

    /**
     * 这是设置自定义的userDetailsService(实现这个接口UserDetailsService)信息到安全管理器的构造器里去,便于认证时的使用
     * 不过我这里并没有用这个一套东西去认证,而是直接登录接口那里直接校验用户信息,直接扔到安全上下文,这样就跳过了这个security
     * 的认证了,其实是一样的,只是这个security比较好一点,但是麻烦,所以这里设不设置都可以的,因为没有用到
     *
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        log.info("WebSecurityConfig======configure(HttpSecurity http)");
        //设置密码加密,查了下发现是spring security 版本在5.0后就要加个PasswordEncoder了,官推是BCryptPasswordEncoder(必要),实例化即可
        auth.userDetailsService(userDetailsService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        log.info("WebSecurityConfig======configure(HttpSecurity http)");
        http.csrf().and().httpBasic().disable()
                //这里为了更友好,直接重定向跳转到登录页,不过一般不会请求认证服务器的太多东西,仅仅只是获取code或token的
                //当然这里也可以不设置,如果访问认证服务器的其他资源直接,提示无权限访问资源就行了,重定向到login登录页,在资源服务器设置即可
                .exceptionHandling().authenticationEntryPoint((request, response, exception) -> response.sendError(HttpStatus.FORBIDDEN.value(), "You have no access to this resource")).and()
                //由于这里只控制得到认证服务器相关的资源,所以仅仅放开对应需要放开的资源即可,如/oauth/token
//                .authorizeRequests().antMatchers("/").permitAll()
                .authorizeRequests().antMatchers("/**").permitAll()
                .anyRequest().authenticated();
    }

}
