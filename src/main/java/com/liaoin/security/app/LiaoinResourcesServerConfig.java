package com.liaoin.security.app;

import com.liaoin.security.app.social.openid.OpenIdAuthenctiationSecurityConfig;
import com.liaoin.security.core.authentication.mobile.SmsCodeAuthenticationSecurityConfig;
import com.liaoin.security.core.authorize.AuthorizeCofigManager;
import com.liaoin.security.core.constants.SecurityConstants;
import com.liaoin.security.core.properties.SecurityProperties;
import com.liaoin.security.core.validate.config.ValidateCodeSecurityConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.social.security.SpringSocialConfigurer;

/**
 * @author mc
 * @version 1.0v
 * 资源服务器
 */
@Configuration
@EnableResourceServer
public class LiaoinResourcesServerConfig extends ResourceServerConfigurerAdapter {

    @Autowired
    protected AuthenticationSuccessHandler liaoinAuthenticationSuccessHandler;

    @Autowired
    protected AuthenticationFailureHandler liaoinAuthenticationFailureHandler;

    @Autowired
    private SmsCodeAuthenticationSecurityConfig smsCodeAuthenticationSecurityConfig;

    @Autowired
    private SpringSocialConfigurer liaoinSocialSecurityConfig;

    @Autowired
    private SecurityProperties securityProperties;

    @Autowired
    private ValidateCodeSecurityConfig validateCodeSecurityConfig;
    @Autowired
    private OpenIdAuthenctiationSecurityConfig openIdAuthenctiationSecurityConfig;
    @Autowired
    private AuthorizeCofigManager authorizeCofigManager;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        //密码登陆相关配置
        //表单登陆
        http.formLogin()
                //当请求需要身份认证时，默认跳转的url
                .loginPage(SecurityConstants.DEFAULT_UNAUTHENTICATION_URL)
                //默认的用户名密码登录请求处理url
                .loginProcessingUrl(securityProperties.getDefaultLoginProcessingUrlFrom())
                //自定义登陆成功配置
                .successHandler(liaoinAuthenticationSuccessHandler)
                //自定义登陆失败配置
                .failureHandler(liaoinAuthenticationFailureHandler);
        //效验码相关配置
        http
//				.apply(validateCodeSecurityConfig)
//                .and()
                //短信登陆相关配置
                .apply(smsCodeAuthenticationSecurityConfig)
                .and()
                //第三方登陆相关配置
                .apply(liaoinSocialSecurityConfig)
                .and()
                //支持三方openid登陆
                .apply(openIdAuthenctiationSecurityConfig)
                .and()
                /*//授权配置
                .authorizeRequests()
                //在授权配置后面加入匹配器，不需要权限验证的配置，浏览器授权特有相关配置
                .antMatchers(
                        //当请求需要身份认证时，默认跳转到controller层的url：/authentication/require
                        SecurityConstants.DEFAULT_UNAUTHENTICATION_URL,
                        SecurityConstants.DEFAULT_LOGIN_PROCESSING_URL_MOBILE,
                        securityProperties.getBrowser().getLoginPage(),
                        SecurityConstants.DEFAULT_VALIDATE_CODE_URL_PREFIX+"/*",
                        //跳转到用户配置的登陆页
                        securityProperties.getBrowser().getSignUpUrl(),
                        securityProperties.getBrowser().getSession().getSessionInvalidUrl()+".json",
                        securityProperties.getBrowser().getSession().getSessionInvalidUrl()+".html",
                        "/user/regist","/social/signUp")
                .permitAll()
                //所有请求
                .anyRequest()
                //需要认证
                .authenticated()
                .and()*/
                //关闭跨战请求防护
                .csrf().disable();
        authorizeCofigManager.config(http.authorizeRequests());
    }
}
