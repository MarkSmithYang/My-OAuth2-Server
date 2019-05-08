package com.yb.security.oauth.server.utils;

import com.alibaba.fastjson.JSON;
import com.yb.security.oauth.server.dic.JwtDic;
import com.yb.security.oauth.server.model.LoginUser;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.util.StringUtils;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.Objects;

/**
 * Description: Jwt生成和解析工具
 * author biaoyang
 * date 2019/4/25 002511:05
 */
public class JwtUtils {

    /**
     * author biaoyang
     * Date: 2019/4/25 0025
     * Description:获取jwt唯一身份识别码jti
     */
    public static String createJti() {
        return String.valueOf(System.nanoTime());
    }

    /**
     * 通过加密算法和秘钥生成加密jwt的token的Key
     *
     * @param base64Secret 经过Base64编码的Secret(秘钥)
     * @param algorithm    加密算法
     * @return
     */
    private static Key getKey(String base64Secret, String algorithm) {
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(base64Secret);
        return new SecretKeySpec(apiKeySecretBytes, algorithm);
    }

    /**
     * 验证jwt的token的 签名
     *
     * @param jsonWebToken
     * @param key
     * @return
     */
    public static boolean verifySignature(String jsonWebToken, Key key) {
        return Jwts.parser()
                .setSigningKey(key)
                .isSigned(jsonWebToken);
    }

    /**
     * 生成accessToken
     *
     * @param user
     * @param ttlMillis
     * @param base64Secret
     * @return
     */
    public static String createAccessToken(LoginUser user, long ttlMillis, String base64Secret) {
        // 采用椭圆曲线加密算法, 提升加密速度
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);

        //通过加密算法和秘钥生成加密jwt的token的Key
        Key key = getKey(base64Secret, SignatureAlgorithm.HS512.getJcaName());
        //添加构成JWT的参数
        JwtBuilder builder = Jwts.builder().setHeaderParam("typ", "JWT")
                //这个两个内容可要可不要
                //.setIssuer(iss)
                //.setAudience(aud)
                //添加jwt的id,也就是jti
                .setId(user.getJti())
                //装填用户信息到荷载
                .addClaims((Map<String, Object>) JSON.toJSON(user))
                //设置subject
                .setSubject(user.getUsername())
                .signWith(SignatureAlgorithm.HS512, key);
        //添加Token过期时间
        if (ttlMillis > 0) {
            long expMillis = System.currentTimeMillis() + ttlMillis;
            Date exp = new Date(expMillis);
            builder.setExpiration(exp).setNotBefore(new Date(System.currentTimeMillis()));
        }
        //生成JWT并为其加上前缀Bearer
        return JwtDic.HEADERS_VALUE_PREFIX + builder.compact();
    }

    /**
     * 创建刷新token
     *
     * @param username
     * @param ttlMillis
     * @param base64Secret
     * @return
     */
    public static String createRefreshToken(String username, long ttlMillis, String base64Secret) {
        //通过加密算法和秘钥生成加密jwt的token的Key
        Key key = getKey(base64Secret, SignatureAlgorithm.HS512.getJcaName());
        //添加构成JWT的参数
        JwtBuilder builder = Jwts.builder().setHeaderParam("typ", "JWT")
                //这个两个内容可要可不要
                //.setIssuer(iss)
                //.setAudience(aud)
                .claim("scope", "REFRESH")
                .setSubject(username)
                .signWith(SignatureAlgorithm.HS256, key);
        //添加Token过期时间
        if (ttlMillis > 0) {
            long expMillis = System.currentTimeMillis() + ttlMillis;
            Date exp = new Date(expMillis);
            builder.setExpiration(exp).setNotBefore(new Date(System.currentTimeMillis()));
        }
        //生成JWT
        return builder.compact();
    }

    /**
     * 校验token的合法性,并且获取荷载信息
     *
     * @param jwtWebToken
     * @return
     */
    public static LoginUser checkAndGetPayload(String jwtWebToken, String base64Secret) {
        //判断token的合法性
        if (StringUtils.hasText(jwtWebToken) && jwtWebToken.startsWith("Bearer ")) {
            //去掉头部的Bearer
            jwtWebToken = jwtWebToken.replaceFirst("Bearer ", "");
            Key key = getKey(base64Secret, SignatureAlgorithm.HS512.getJcaName());
            //验证签名
            if (verifySignature(jwtWebToken, key)) {
                //对jwt的token进行切割判断
                if (jwtWebToken.contains(".") && jwtWebToken.split("\\.").length == 3) {
                    //获取荷载内容,实测用DatatypeConverter.parseBase64Binary解析,会导致解析出的荷载是没有后面那个大括号的,会导致解析成LoginUser失败
                    //String payload = new String(DatatypeConverter.parseBase64Binary(jwtWebToken.split("\\.")[1]));
                    String payload = new String(Base64.getDecoder().decode(jwtWebToken.split("\\.")[1]));
                    //解析荷载(封装的时候也要是JSON转的对象,才能反过来解析出来)
                    if (StringUtils.hasText(payload)) {
                        //解析用户信息
                        LoginUser loginUser = JSON.parseObject(payload, LoginUser.class);
                        //如果不拥有用户名,那么登录无效
                        if (Objects.nonNull(loginUser) && StringUtils.hasText(loginUser.getUsername())) {
                            return loginUser;
                        }
                    }
                }
            }
        }
        //不满足条件返回null
        return null;
    }

}
