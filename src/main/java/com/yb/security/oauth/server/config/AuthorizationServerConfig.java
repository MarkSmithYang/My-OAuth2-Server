package com.yb.security.oauth.server.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

import javax.servlet.http.HttpServletResponse;
import java.util.*;

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

    @Autowired
    public AuthorizationServerConfig(AuthenticationManager authenticationManager, RedisConnectionFactory redisConnectionFactory) {
        this.authenticationManager = authenticationManager;
        this.redisConnectionFactory = redisConnectionFactory;
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
        //通过redis存储token信息
        //return new RedisTokenStore(redisConnectionFactory);
        //通过jwt存储token
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    /**
     * 通过jwt存储token
     * @return
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        //都是函数式接口
        //JwtAccessTokenConverterConfigurer
        //JwtAccessTokenConverterRestTemplateCustomizer
        JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
        //这里没有使用非对称加密(证书公钥秘钥)
        tokenConverter.setSigningKey("mySecret");
        return tokenConverter;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        log.info("AuthorizationServerConfig======configure(AuthorizationServerSecurityConfigurer security)=======");
        security.allowFormAuthenticationForClients();//允许提交表单,一般都是json对象提交的
        security.tokenKeyAccess("permitAll()")//对获取Token的请求不再拦截
                .checkTokenAccess("isAuthenticated()");//验证获取Token的验证信息
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        log.info("AuthorizationServerConfig======configure(ClientDetailsServiceConfigurer clients)=========");
        //clients.jdbc(...)
        clients.inMemory()
                .withClient("android")
                .scopes("part")
                //因为spring后面的版本必须配置加密算法,所以需要把登录密码加加密比对(实测需要加密内存里的密码)
                .secret("$2a$10$hMija4S45OB2KXYvXxAt0.vXG9yq7yEiItOrKl6hhRHChbG8QdBwS")
                .authorizedGrantTypes("password", "authorization_code", "refresh_token")
                .and()
                .withClient("web")
                .scopes("all")
                .secret("$2a$10$ec1kgB1yWRV0V1fV6gmyfe/BbJhgYQ/DEkMxeHsFGl2mzn3/lrsvi")
                .authorizedGrantTypes("implicit");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        log.info("AuthorizationServerConfig======configure(AuthorizationServerEndpointsConfigurer endpoints)=========");
        endpoints.authenticationManager(new OAuth2AuthenticationManager());
        endpoints.tokenStore(tokenStore());
        //增强token(为token添加一些额外的信息)
        TokenEnhancer tokenEnhancer = (oAuth2AccessToken, oAuth2Authentication) -> {
            DefaultOAuth2AccessToken accessToken = (DefaultOAuth2AccessToken) oAuth2AccessToken;
            Map<String, Object> infos = new HashMap<>(10);
            //实测这个数据是和token和refresh_token是同级的,也就是没有在jwt的荷载里
            infos.put("username", "jack");
            infos.put("jti",UUID.randomUUID().toString().replaceAll("-",""));
            //设置额外的参数
            accessToken.setAdditionalInformation(infos);
            //设置过期时间
            accessToken.setExpiration(new Date(System.currentTimeMillis() + 300000));
            //返回数据
            return accessToken;
        };
        TokenEnhancerChain chain = new TokenEnhancerChain();
        chain.setTokenEnhancers(Arrays.asList(tokenEnhancer, jwtAccessTokenConverter()));
        endpoints.tokenEnhancer(chain);
    }

//
//    @Override
//    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
//        endpoints.tokenStore(tokenStore()).tokenEnhancer(jwtTokenEnhancer()).authenticationManager(authenticationManager);
//    }
//
//    @Autowired
//    @Qualifier("authenticationManagerBean")
//    private AuthenticationManager authenticationManager;
//
//    @Bean
//    public TokenStore tokenStore() {
//        return new JwtTokenStore(jwtTokenEnhancer());
//    }
//
//    @Bean
//    protected JwtAccessTokenConverter jwtTokenEnhancer() {
//        //注意此处需要相应的jks文件
//        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("fzp-jwt.jks"), "fzp123".toCharArray());
//        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
//        converter.setKeyPair(keyStoreKeyFactory.getKeyPair("fzp-jwt"));
//        return converter;
//    }

}
