package com.yb.security.oauth.server.config;

import com.yb.security.oauth.server.dic.ApplicationConfig;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Description: 授权服务配置
 * EnableAuthorizationServer--启用授权服务
 * author biaoyang
 * date 2019/4/9 00099:34
 */
@Configuration
@AllArgsConstructor
@EnableAuthorizationServer
//@EnableOAuth2Sso//OAuth2单点登录(SSO)//通过请求头带jwt的token的方式可实现sso
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    private static final Logger log = LoggerFactory.getLogger(AuthorizationServerConfig.class);
    //来自于WebSecurityConfig
    private final ApplicationConfig applicationConfig;
    private final AuthenticationManager authenticationManager;

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
     *
     * @return
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
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

    public static void main(String[] args) {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String j = bCryptPasswordEncoder.encode("admin");
        System.err.println(j);
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        log.info("AuthorizationServerConfig======configure(ClientDetailsServiceConfigurer clients)=========");
        //clients.jdbc(...)
        clients.inMemory()
                .withClient("client")
                .scopes("part")
                //因为spring后面的版本必须配置加密算法,所以需要把登录密码加加密比对(实测需要加密内存里的密码)
//                .secret("$2a$10$xdefvkbwoQ5mc34d.73WL.WIwX14rdJFFXGUIz9zk7P/FA5E29wPe")//android
//                .secret("$2a$10$mDkWKlMzwI2Iw1lJUSNUmuzV0R.N0o3qrKPTvdqXxt.vyJ/Tykuy2")//client
                .secret("$2a$10$rtLK3Ene/J8DotqLzZpDNennHof.tWHynYAHC/tTTewul9UbhTOM6")//admin
                .authorizedGrantTypes("password", "authorization_code", "refresh_token")
                //这个为true表示不用登录用户手动授权,直接通过返回code(这个主要是authorization_code的情况),false就是用户点击授权才会得到code
                .autoApprove(false)
                //这个是必须要的,不然就会导致跳转uri的时候出现At least one redirect_uri must be registered with the client(必须至少向客户机注册一个redirect_uri)
                .redirectUris(applicationConfig.getRedirectUrl())
                //有效token的有效时间
                .accessTokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(30))
                //刷新token的有效时间
                .refreshTokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(365));
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        log.info("AuthorizationServerConfig======configure(AuthorizationServerEndpointsConfigurer endpoints)=========");
        //切记不能用new OAuth2AuthenticationManager()来用,不然就会报TokenPoint是空指针的错误
        endpoints.authenticationManager(authenticationManager);
        endpoints.tokenStore(tokenStore());
        //允许通过get请求来获取token默认是post请求(当然了post请求一直都可以)
        endpoints.allowedTokenEndpointRequestMethods(HttpMethod.GET);
        //增强token(为token添加一些额外的信息)
        TokenEnhancer tokenEnhancer = (oAuth2AccessToken, oAuth2Authentication) -> {
            DefaultOAuth2AccessToken accessToken = (DefaultOAuth2AccessToken) oAuth2AccessToken;
            Map<String, Object> infos = new HashMap<>(10);
            //实测这个数据是和token和refresh_token是同级的,也就是没有在jwt的荷载里
            infos.put("username", "jack");
            infos.put("jti", UUID.randomUUID().toString().replaceAll("-", ""));
            //设置额外的参数
            accessToken.setAdditionalInformation(infos);
            //设置过期时间
            accessToken.setExpiration(new Date(System.currentTimeMillis() + 300000));
            //返回数据
            return accessToken;
        };
        TokenEnhancerChain chain = new TokenEnhancerChain();
        chain.setTokenEnhancers(Arrays.asList(tokenEnhancer, jwtAccessTokenConverter()));
        //实测这个对于jwt来说是必要的,不管不增强不增强,都需要设置这个才能正确获取到jwt的token,
        //否则只是个UUID,是没实现jwt存储和转换的,这里仅仅只是使用了,普通的字符串作为秘钥签名的
        //可以使用公私钥加密和增强(添加额外的内容到jwt里)来
        endpoints.tokenEnhancer(chain);
    }

}
