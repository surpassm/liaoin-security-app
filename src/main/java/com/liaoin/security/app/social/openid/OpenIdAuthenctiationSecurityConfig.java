package com.liaoin.security.app.social.openid;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.social.connect.UsersConnectionRepository;
import org.springframework.social.security.SocialUserDetailsService;
import org.springframework.stereotype.Component;

/**
 * @author mc
 * @version 1.0v
 */
@Component
public class OpenIdAuthenctiationSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain,HttpSecurity> {
    @Autowired
    private AuthenticationSuccessHandler liaoinAuthenticationSuccessHandler;
    @Autowired
    private AuthenticationFailureHandler liaoinAuthenticationFailureHandler;
    @Autowired
    private SocialUserDetailsService userDetailsService;
    @Autowired
    private UsersConnectionRepository usersConnectionRepository;
    @Override
    public void configure(HttpSecurity http) throws Exception {
        OpenIdAuthenctiationFilter openIdAuthenctiationFilter = new OpenIdAuthenctiationFilter();
        openIdAuthenctiationFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        openIdAuthenctiationFilter.setAuthenticationSuccessHandler(liaoinAuthenticationSuccessHandler);
        openIdAuthenctiationFilter.setAuthenticationFailureHandler(liaoinAuthenticationFailureHandler);

        OpenIdAuthenctiationProvider openIdAuthenctiationProvider = new OpenIdAuthenctiationProvider();
        openIdAuthenctiationProvider.setSocialUserDetailsService(userDetailsService);
        openIdAuthenctiationProvider.setUsersConnectionRepository(usersConnectionRepository);

        http.authenticationProvider(openIdAuthenctiationProvider)
                .addFilterAfter(openIdAuthenctiationFilter,UsernamePasswordAuthenticationFilter.class);


    }



}
