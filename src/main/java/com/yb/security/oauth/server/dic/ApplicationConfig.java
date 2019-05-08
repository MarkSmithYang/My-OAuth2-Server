package com.yb.security.oauth.server.dic;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Description:
 * author biaoyang
 * date 2019/5/8 00089:43
 */
@Setter
@Getter
@Configuration
@ConfigurationProperties(prefix = "server-url")
public class ApplicationConfig {

    /**
     * 认证服务器的地址
     */
    private String authUrl;

    /**
     * 重定向的地址
     */
    private String redirectUrl;

    /**
     * 客户端id
     */
    private String clientId;

    /**
     * 客户端秘钥
     */
    private String clientSecret;

    /**
     * 认证类型
     */
    private String grantType;

    /**
     * 响应类型
     */
    private String responseType;

}
