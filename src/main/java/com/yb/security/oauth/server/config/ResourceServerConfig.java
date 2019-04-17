package com.yb.security.oauth.server.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletResponse;

/**
 * Description: 资源服务配置
 * EnableResourceServer----启用资源服务
 * author biaoyang
 * date 2019/4/9 000910:05
 */
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
    private static final Logger log = LoggerFactory.getLogger(ResourceServerConfig.class);

    @Autowired
    private TokenStore tokenStore;

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.tokenStore(tokenStore);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        log.info("ResourceServerConfig======configure(HttpSecurity http)");
        http.exceptionHandling().authenticationEntryPoint((request, response, exception) ->
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "请登录"));
        http.authorizeRequests().anyRequest().authenticated();
//        http.requestMatcher(request -> {
//            String token = request.getHeader("Authorization");
//            //oauth2授权的是头部的Authorization值以Bearer开头的请求(设定为jwt的标准,必须是以Authorization为key且Bearer空格开头的字符串)
//            //这里并没有做jwt的验证签名操作---------------------------------------------------------------------
//            System.err.println("aaaaaaaa");
//            return StringUtils.hasText(token) && token.startsWith("Bearer ") ? true : false || request.getParameter("access_token") != null;
////            return StringUtils.hasText(token) && token.startsWith("Bearer ") ? true : false || request.getParameter("access_token") != null;
//        }).authorizeRequests()
//                //HttpMethod.OPTIONS
//                //获取服务器支持的HTTP请求方法；也是黑客经常使用的方法
//                //用来检查服务器的性能,例如:AJAX进行跨域请求时的预检,需要向另外一个域名的资源发送一个HTTP OPTIONS请求头,
//                //用以判断实际发送的请求是否安全
//                .antMatchers("/**")
//                //这里通过接口的访问方式开放,实际并不会这么做
//                .permitAll()
//                .anyRequest()
//                .authenticated();
    }
}
