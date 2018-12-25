package com.liaoin.security.app.social.impl;

import com.liaoin.security.core.social.SocialAuthenticationFilterPostProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.social.security.SocialAuthenticationFilter;
import org.springframework.stereotype.Component;

/**
 * @author mc
 * @version 1.0v
 * 把自定义的成功处理器写入拦截器中
 */
@Component
public class AppSocialAuthenticationFilterPostProcessor implements SocialAuthenticationFilterPostProcessor {

    @Autowired
    private AuthenticationSuccessHandler liaoinAuthenticationSuccessHandler;
    @Override
    public void processor(SocialAuthenticationFilter socialAuthenticationFilter) {
        socialAuthenticationFilter.setAuthenticationSuccessHandler(liaoinAuthenticationSuccessHandler);
    }
}
