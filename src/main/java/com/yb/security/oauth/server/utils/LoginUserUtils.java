package com.yb.security.oauth.server.utils;

import com.yb.security.oauth.server.model.LoginUser;

import java.util.Optional;
import java.util.Set;

/**
 * author biaoyang
 * Date: 2019/4/29 0029
 * Description:
 */
public class LoginUserUtils {

    private static InheritableThreadLocal<LoginUser> userInfo = new InheritableThreadLocal<>();

    /**
     * 设置用户信息
     **/
    public static void setUser(LoginUser user) {
        userInfo.set(user);
    }

    /**
     * 获取所有用户信息
     * @return 用户信息
     **/
    public static Optional<LoginUser> getUser() {
        return Optional.ofNullable(userInfo.get());
    }

    /**
     * 获取用户id
     * @return 用户id
     **/
    public static Optional<String> getUserId() {
        return getUser()
                .map(LoginUser::getUserId);
    }

    /**
     * 获取用户名
     * @return 用户名
     */
    public static Optional<String> getUsername() {
        return getUser()
                .map(LoginUser::getUsername);
    }


    /**
     * 获取姓名
     * @return 姓名(昵称)
     */
    public static Optional<String> getName() {
        return getUser()
                .map(LoginUser::getFullName);
    }

    /**
     * 获取用户身份证号(互联网用户)
     * @return 身份证号码
     */
    public static Optional<String> getIdCard() {
        return getUser()
                .map(LoginUser::getIdCard);
    }

    /**
     * 获取用户实名认证状态
     * update zhangjw 20190124
     * @return 实名认证状态
     */
    public static Optional<String> getAuthStatus() {
        return getUser()
                .map(LoginUser::getAuthStatus);
    }

    /**
     * 获取手机号
     */
    public static Optional<String> getCellphone(){
        return getUser()
                .map(LoginUser::getCellphone);
    }

    /**
     * 获取机构代码
     * @return 机构代码
     */
    public static Optional<Long> getOrgCode(){
        return getUser()
                .map(LoginUser::getOrgCode);
    }

    /**
     * 获取机构名称(部门)
     * @return 机构名称
     */
    public static Optional<String> getOrgName(){
        return getUser()
                .map(LoginUser::getOrgName);
    }

    /**
     * 获取角色
     * @return 角色列表
     */
    public static Optional<Set<String>> getRoles() {
        return getUser()
                .map(LoginUser::getRoles);
    }

    /**
     * 获取客户端
     * @return 来源
     */
    public static Optional<String> getFrom() {
        return getUser()
                .map(LoginUser::getFrom);
    }

    /**
     * 获取IP
     * @return IP
     */
    public static Optional<String> getIp() {
        return getUser()
                .map(LoginUser::getIp);
    }

    /**
     * 获取uri
     * @return uri
     */
    public static Optional<String> getUri() {
        return getUser()
                .map(LoginUser::getUri);
    }

    /**
     * 获取jti(唯一登陆随机码)
     * @return jti
     */
    public static Optional<String> getJti(){
        return getUser()
                .map(LoginUser::getJti);
    }
}
