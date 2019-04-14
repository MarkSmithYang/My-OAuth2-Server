package com.yb.security.oauth.server.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

import javax.servlet.http.HttpServletResponse;

/**
 * Description: 授权服务配置
 * EnableAuthorizationServer--启用授权服务
 * author biaoyang
 * date 2019/4/9 00099:34
 */
@Configuration
//@EnableOAuth2Sso//OAuth2单点登录(SSO)
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    private static final Logger log = LoggerFactory.getLogger(AuthorizationServerConfig.class);
    //认证管理器
    private final AuthenticationManager authenticationManager;
    //redis连接工厂
    private final RedisConnectionFactory redisConnectionFactory;
    //加密类
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    public AuthorizationServerConfig(AuthenticationManager authenticationManager,
                                     BCryptPasswordEncoder bCryptPasswordEncoder,
                                     RedisConnectionFactory redisConnectionFactory) {
        this.authenticationManager = authenticationManager;
        this.redisConnectionFactory = redisConnectionFactory;
        this.bCryptPasswordEncoder=bCryptPasswordEncoder;
    }

    /**
     * 令牌存储
     * redis的token(令牌)存储对象
     *
     * @return
     */
    @Bean
    public TokenStore tokenStore() {
        log.info("AuthorizationServerConfig======tokenStore()=======");
        return new RedisTokenStore(redisConnectionFactory);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        log.info("AuthorizationServerConfig======configure(AuthorizationServerSecurityConfigurer security)=======");
        security.authenticationEntryPoint((request,response,exception)->{
            response.setCharacterEncoding("UTF-8");
            response.setHeader("Content-Type", "application/json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getOutputStream().write("请登录".getBytes());
        });
        security.allowFormAuthenticationForClients();
        security.passwordEncoder(bCryptPasswordEncoder);
        security.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        log.info("AuthorizationServerConfig======configure(ClientDetailsServiceConfigurer clients)=========");
//        clients.jdbc()
        clients.inMemory()
                .withClient("android")
                .scopes("part")
                .secret("android")
                .authorizedGrantTypes("password", "authorization_code", "refresh_token")
                .and()
                .withClient("web")
                .scopes("all")
                .secret("web")
                .authorizedGrantTypes("implicit");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        log.info("AuthorizationServerConfig======configure(AuthorizationServerEndpointsConfigurer endpoints)=========");
        endpoints.authenticationManager(authenticationManager)
                .tokenStore(tokenStore());
    }

}
