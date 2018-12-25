package com.liaoin.security.app.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.liaoin.security.core.enums.LoginResponseType;
import com.liaoin.security.core.properties.SecurityProperties;
import com.liaoin.security.core.support.SimpleResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 自定义登陆失败配置
 * 继承security默认失败处理器
 */
@Component("liaoinAuthenctiationFailureHandler")
public class LiaoinAuthenctiationFailureHandler  extends SimpleUrlAuthenticationFailureHandler {

    private Logger logger = LoggerFactory.getLogger(getClass());

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SecurityProperties securityProperties;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        logger.info("登录失败");
        if (LoginResponseType.JSON.equals(securityProperties.getBrowser().getLoginType())) {
            //设置返回状态码 默认返回状态码为200
            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(new SimpleResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(),exception.getMessage(),"")));
        }else{
            super.onAuthenticationFailure(request, response, exception);
        }


    }
}
