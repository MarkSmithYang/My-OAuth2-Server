package com.yb.security.oauth.server.utils;

import org.apache.commons.lang.StringUtils;

import javax.servlet.http.HttpServletRequest;

/**
 * Description:
 * author biaoyang
 * date 2019/5/9 000915:16
 */
public class GetIpAddressUtils {

    /**
     * 获取登录用户的ip地址
     *
     * @param request
     * @return
     */
    public static String getIpAddress(HttpServletRequest request) {
        String[] headers = {"x-forwarded-for", "Proxy-Client-IP", "WL-Proxy-Client-IP", "HTTP_CLIENT_IP", "HTTP_X_FORWARDED_FOR"};
        String ip = null;
        String unknown = "unknown";
        for (String header : headers) {
            ip = request.getHeader(header);
            if (StringUtils.isNotBlank(ip) && !unknown.equalsIgnoreCase(ip)) {
                break;
            }
        }
        if (StringUtils.isBlank(ip) || unknown.equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return "0:0:0:0:0:0:0:1".equals(ip) ? "127.0.0.1" : ip;
    }
}
