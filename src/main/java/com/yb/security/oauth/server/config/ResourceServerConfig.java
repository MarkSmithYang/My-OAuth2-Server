package com.yb.security.oauth.server.config;

import com.yb.security.oauth.server.filter.MyFilter;
import lombok.AllArgsConstructor;
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
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
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
@AllArgsConstructor
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
    private static final Logger log = LoggerFactory.getLogger(ResourceServerConfig.class);

    private final TokenStore tokenStore;
    private final MyFilter myFilter;

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.tokenStore(tokenStore);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        log.info("ResourceServerConfig======configure(HttpSecurity http)");
        http.addFilterAfter(myFilter, SecurityContextPersistenceFilter.class);
        http.exceptionHandling().authenticationEntryPoint((request, response, exception) -> response.sendRedirect("/login"));
        //注意指定没有登录的重定向跳转页需要放开才能正常跳转
        http.authorizeRequests().antMatchers("/","/login").permitAll().anyRequest().authenticated();
    }
}
