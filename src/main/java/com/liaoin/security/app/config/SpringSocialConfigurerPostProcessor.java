package com.liaoin.security.app.config;

import com.liaoin.security.core.social.LiaoinSpringSocialConfigurer;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.stereotype.Component;

/**
 * @author mc
 * @version 1.0v
 * spring初始化之前和之后所有bean都要经过该类，目的是容器中初始化liaoinSocialSecurityConfig这个对象后
 * 根据APP三方登陆注册绑定来修改该对象
 */
@Component
public class SpringSocialConfigurerPostProcessor implements BeanPostProcessor {

    @Override
    public Object postProcessBeforeInitialization(Object bean, String s) throws BeansException {
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (StringUtils.equals(beanName,"liaoinSocialSecurityConfig")){
            LiaoinSpringSocialConfigurer configurer = (LiaoinSpringSocialConfigurer) bean;
            configurer.signupUrl("/social/signUp");
            return configurer;
        }
        return bean;
    }
}
