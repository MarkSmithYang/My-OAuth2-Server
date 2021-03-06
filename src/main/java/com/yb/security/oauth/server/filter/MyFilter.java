package com.yb.security.oauth.server.filter;

import com.yb.security.oauth.server.dic.JwtDic;
import com.yb.security.oauth.server.model.LoginUser;
import com.yb.security.oauth.server.utils.GetIpAddressUtils;
import com.yb.security.oauth.server.utils.JwtUtils;
import com.yb.security.oauth.server.utils.LoginUserUtils;
import lombok.AllArgsConstructor;
import org.apache.commons.lang.StringUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
 * ------------------->最后的总结:
 * ----------------注意里面有些是错误的,实测security和资源服务器都设置成/**,也还是会报如下错,实测之前之所以成功是因为最开始使用了带有token的请求,
 * -----------经过过滤器后,把用户信息设置到了安全上下文了,所以去掉了token去请求/oauth/**的资源时才不会报错,所以就正如你需要登录系统之后才能授权
 * -------------------它去认证服务器获取code和token,所以这个是必须登录的,而这个登录是还是不能访问资源服务器的资源的,只有认证服务器发的token才行,
 * -----------------而这个登录仅是security的登录
 * &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
 * Description: 用于认证过token合法性的校验---实测先走SecurityContextPersistenceFilter,然后再走OAuth2AuthenticationProcessingFilter
 * -------SecurityContextPersistenceFilter---------->OAuth2AuthenticationProcessingFilter(去认证服务器存储token的TokenStore获取token验证
 * 所以才需要资源服务保持和认证服务器的秘钥或者配套的公私钥,这样才能正确解析出认证服务器颁发的token),实测资源服务器/**放开所有url,让security
 * 只放过/(相当于没有放过任何url)这样除了接口方法上注解了@PreAuthorize的(这个会去security的安全上下文里找对应的信息,因为我们没有),其他的都可以正常访问
 * 请求的顺序是这样的,先进入这个过滤器MyFilter,然后进入OAuth2AuthenticationProcessingFilter里里面去,最后还是再回到MyFilter过滤器,如果是
 * 是用JwtUtils工具生成的token,MyFilter过滤器可以直接解析并添加用户信息到安全上下文里去,但是去到OAuth2AuthenticationProcessingFilter后,
 * OAuth2AuthenticationProcessingFilter获取到的Authentication是principal为token的对象,这个token也是从请求头或这请求参数里拿到的,然后把
 * 通过 new PreAuthenticatedAuthenticationToken(token, "");构造出来的,然后拿着这个对象去调用OAuth2AuthenticationManager的authenticate
 * 方法(OAuth2AuthenticationManager是AuthenticationManager的一个实现,断点进的是这个实现),然后再去调用DefaultTokenServices的loadAuthentication
 * 方法,然后再去调用org.springframework.security.oauth2.provider.token.store.JwtTokenStore(TokenStore的实现类)的readAccessToken方法,在这个方法
 * 里获取convertAccessToken来看是否能正确转换token(其实就是token的解析),这里如果和颁发token的认证服务器的加密不匹配,那么就会解析失败,也就是
 * 不是认证服务颁发的token,它是不认的,然后就返回错误信息---Cannot convert access token to JSON等信息,
 * -------但是如果资源服务器是/**放过所有,但是security是放过/oauth/**,也就是请求认证服务器code和token等相关的url的时候,会正常跳转的去进行授权
 * 获取code(授权码认证的方式情况下)--因为security放过了/oauth/**相关的url了,否则需要通过security的认证,才能成功请求到code,然后就能通过授权码code
 * 去认证服务器获取访问资源的token,方然了这个token是为了去访问资源服务拦截的url的资源的
 * -------这里的security的安全控制,很明显是控制认证服务器的,因为资源服务器设置/**而security设置了/,也就是拦截所有的时候,还是可以正常访问那些没有
 * security认证注解的接口方法(这个需要security认证并设置安全上下文含有对应的内容才能访问),这个就说明,security对于资源并不去控制,不然那些普通接口
 * 早就被拦截了,而访问/oauth/相关的认证服务器的资源的时候,如果security不放开的话,就需要通过认证之后(带上认证信息例如token)之后才能成功的去请求
 * 认证服务器相关的东西,比如授权码,访问令牌token等,如果放过的话,就可以直接去获取这些code等信息,因为OAuth2依赖会自动依赖security依赖,所以可以
 * 使用security相关的注解,同时也会拦截认证服务器资源的url,所以需要配置security的配置类,不管是直接和认证服务器放在一起,还是自己另写一个配置类来
 * 完成security的安全设置,而且需要通过这个配置实例化一个bean,这个bean是AuthenticationManager,这个是必要的,需要通过它做很多的事情,而目前找不到
 * 其他方式实例化这个bean,只能通过继承WebSecurityConfigurerAdapter,去调用父类来帮助实例化
 * ----------如果security设置了/**(放开所有url),而资源服务器设置了/(也就是拦截所有),那么访问/oauth/**相关的资源会抛出这个异常
 * User must be authenticated with Spring Security before authorization can be completed(在完成授权之前，必须使用Spring安全性对用户进行身份验证),就是你需要先登录才能访问
 * 而去访问那些普通的接口(没有认证注解在接口方法上的),返回的是Full authentication is required to access this resource(访问此资源需要完全的身份验证)这样的错误
 * --------如果是上面的那种security是/而资源服务器是/**,请求/oauth/**相关的信息就是会是security设置的跳转或返回的提示登录的信息,不过一般不设置这个,
 * 因为肯定是要放开认证服务器获取code和token的url的,如果访问其他的不让其访问的资源,就直接提示它,你无权访问此资源
 * -------------------------------------这个过滤器处理的其实仅仅只是security的认证,另一个过滤器OAuth2AuthenticationProcessingFilter
 * 才是处理的才是认证服务器和资源服务器的认证的
 * -------------------------------如果认证服务器和资源服务器是分离的话,资源服务器里的接口方法如果加了认证注解,那么就需要引入security的东西,然后又会出现
 * security拦住url的问题,所以分开的时候建议加注解来认证,而是通过获取上下文信息来认证,自己写代码认证
 * author biaoyang
 * date 2019/5/6 000615:56
 */
@Component
@AllArgsConstructor
public class MyFilter extends SecurityContextPersistenceFilter {

    private final RedisTemplate<String, Serializable> redisTemplate;


    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        //获取请求头里的token信息
        String token = request.getHeader(JwtDic.HEADERS_NAME);
        //如果请求头不存在,则去请求参数获取
        if (!StringUtils.isNotBlank(token)) {
            token = request.getParameter(JwtDic.ACCESS_TOKEN);
        }
        //判断从请求里获取的token是否有效,如果为null则去redis里去获取
        if (checkToken(token, request) == null) {
            //获取登录用户的ip地址,用来作为key,因为redis存储,用来区分不同用户,统一台电脑登录的用户只会是最后登录的用户的登录信息(因为key相同,会被覆盖)
            String ip = StringUtils.isNotBlank(GetIpAddressUtils.getIpAddress(request)) ? GetIpAddressUtils.getIpAddress(request) : "";
            //为了解决每次都需要带token请求头或请求参数,这里先采用老式的方法(redis存储token)来处理用户登录信息
            String accessToken = (String) redisTemplate.opsForValue().get(JwtDic.ACCESS_TOKEN + ip);
            //一开始的登录是用JwtUtils生成的token,是用来登录整个系统的,只有认证成功了这个才能去认证服务器收取并获取请求资源服务器资源的token,
            //最开始的那个JwtUtils生成的token是不能获取到资源服务器的资源的,因为一你为资源配置了资源服务器的配置,就会开启OAuth2的过滤器,它会去
            //认证服务器那里找token,并验证,如果没有发证书就会通不过验证,自然就没法获取资源,所以还需要授权并获取token,然后才能得到能访问资源服务器资源的token
            //实测,让获得能访问资源服务器资源的token的时候,带上资源去访问,就把之前JwtUtils生成的登录的token清除,也就是过滤器也没法设置安全上下文的时候,因为过滤器
            //能解析的token是JwtUtils生成的,它并不能解析新生成的能访问资源服务器资源的token,也就是安全上下文是空的,也能通过带上新的能访问资源服务器资源的token来访问
            //资源服务器的资源(token有效的情况下),当然了,如果在资源的接口方法上有权限认证的话,这个就需要有指定的安全上下文信息才能认证通过,而原本不需要安全上下文就能
            //访问的,这个资源就访问不了了,必须有指定的安全上下文信息,因为能访问资源服务器资源的token是认证服务器和资源服务器已经配置了的,会自动通过自己的过滤器去认证,
            //所以没法通过这个能访问资源的token来生成安全上下文信息,所以就只能是JwtUtils生成的token在这个过滤器里认证并解析,并设置安全上下文信息,而那个资源的接口方法
            //上的权限认证也只能通过这个安全上下文来认证,而我这里因为用了redis存储用来登录的token(一般不会存储在redis这种做法,基本都是放在请求(头/参数)里面的),虽然可以
            //一个设置在请求参数里,一个设置在请求头里,然后在过滤器里分别处理---->注意:OAuth2的那个OAuth2AuthenticationProcessingFilter过滤器里会先去请求头里获取能访问
            //资源的token,请求头的key为Authorization获取不到再去请求参数里获取token,那个key是access_token,所以如果要这样做,建议登录的token放在请求参数上,并且key不要设置
            //为access_token,可以避免被错误的获取token,建议key为accessToken,这也符合我们平时命名,当然了也可以用redis,就像现在这样,但是不建议这么做,因为这个会增大风险并且
            //不利于维护,一旦redis出了点状况,就挂了,设置在请求里,就不用去配置安装redis,也不用担心它挂掉,存储的东西被删除和过期等问题,而且存储token的key很难区分用户(我这里用ip还行)
            //String accessToken = (String) redisTemplate.opsForValue().get(JwtDic.ACCESS_TOKEN + ip+"1111");
            //验证并设置安全上下文
            checkToken(accessToken, request);
        }
        //执行过滤
        chain.doFilter(req, res);
    }

    /**
     * 校验token合法性和设置安全上下文
     *
     * @param token
     * @return
     */
    private LoginUser checkToken(String token, HttpServletRequest request) {
        //判断token是否存在,并校验其合法性,(checkAndGetPayload已经做了判空和前缀判断)
        LoginUser loginUser = JwtUtils.checkAndGetPayload(token, JwtDic.BASE64_ENCODE_SECRET);
        //判断是否能正确解析出放在荷载里的用户信息(验证签名不通过返回null)
        if (Objects.nonNull(loginUser)) {
            //实例化一个装权限/角色的集合
            Set<GrantedAuthority> roles = new HashSet<>(5);
            //判断用户是否带有权限/角色信息
            if (!CollectionUtils.isEmpty(loginUser.getRoles())) {
                //注意这里需要为角色添加前缀,接口认证的时候是带有前缀的,否则匹配不上
                loginUser.getRoles().forEach(s -> roles.add(new SimpleGrantedAuthority(
                        s.startsWith(JwtDic.SECURITY_ROLE_PREFIX) ? s : JwtDic.SECURITY_ROLE_PREFIX + s)));
            }
            //获取请求的url的地址,例如http://localhost:9095/producer/hello?name=小明,获取到的是/producer/hello
            String path = request.getRequestURI();//肯定不为空
            if (!"/oauth/token".equals(path)) {
                //这是个深坑,弄了好多天,断了好多断点去看源码,没看到问题,今日去源码找到问题所在了,当请求/oauth/token的时候,就会通过参数(Principal principal)
                //去获取当前用户信息,然后判断是否属于Authentication,然后转换Authentication client = (Authentication) principal;然后String clientId = client.getName();
                //然后判断 (Authentication) principal是否instanceof这个OAuth2Authentication,如果不属于那么就直接返回clientId,不然就
                // clientId = ((OAuth2Authentication) client).getOAuth2Request().getClientId();来获取clientId,所以当请求/oauth/token的时候不能设置安全上下文
                //所以需要在过滤器这里设置不设置安全上下文,实测不能设置上下文为null,如下,不然还是失败,因为属于OAuth2Authentication的Authentication也置空了,没clientId了
                //SecurityContextHolder.getContext().setAuthentication(null);
                //设置安全上下文信息
                Authentication authentication = new UsernamePasswordAuthenticationToken(loginUser.getUsername(), "", roles);
                //设置安全信息到上下文中
                SecurityContextHolder.getContext().setAuthentication(authentication);
                //设置用户信息到LoginUserUtils里方便获取用户信息
                LoginUserUtils.setUser(loginUser);
            }else {
                //这个实测是上下文里的username是client,也就是客户端的信息,不是认证服务器设置的tom,也不是登录的jack
                //所以可以试着去源码看看如何获取到认证服务器发的token的用户权限(认证服务器设置)等信息,然后即使资源服务器分离了也可以做接口方法的认证
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                System.err.println(authentication.getPrincipal().toString());
            }
        }
        return loginUser;
    }
}