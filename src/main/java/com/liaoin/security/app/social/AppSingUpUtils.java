package com.liaoin.security.app.social;

import com.liaoin.security.app.exception.AppSecretException;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.social.connect.*;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;

import java.util.concurrent.TimeUnit;

/**
 * @author mc
 * @version 1.0v
 * 自定义三方登陆注册绑定
 */
@Component
public class AppSingUpUtils {

    @Autowired
    private RedisTemplate<Object,Object> redisTemplate;

    @Autowired
    private UsersConnectionRepository usersConnectionRepository;
    /**
     * 根据connectionData获取Connection
     */
    @Autowired
    private ConnectionFactoryLocator connectionFactoryLocator;

    /**
     * 缓存第三方用户信息到redis
     */
    public void saveConnectionData(WebRequest request, ConnectionData connectionData){
        redisTemplate.opsForValue().set(getKey(request),connectionData,10,TimeUnit.MINUTES);
    }

    /**
     * 将缓存中上方信息与系统用户注册绑定 需要业务系统传入用户id
     */
    public void doPoatSignUp(WebRequest request,String userId){
        String key = getKey(request);
        if (!redisTemplate.hasKey(key)){
            throw new AppSecretException("无法找到redis缓存中的用户社交账号信息");
        }
        //从缓存中取出connectiondata
        ConnectionData connectionData = (ConnectionData) redisTemplate.opsForValue().get(key);
        //根据connectionData.getProviderId()创建Connection
        Connection<?> connection = connectionFactoryLocator.getConnectionFactory(connectionData.getProviderId()).createConnection(connectionData);
        usersConnectionRepository.createConnectionRepository(userId).addConnection(connection);
    }
    /**
     * redis缓存中存入的第三放信息key
     * @return 缓存中的key
     */
    private String getKey(WebRequest request) {
        String deviceId = request.getHeader("deviceId");
        if (StringUtils.isBlank(deviceId)){
            throw new AppSecretException("设备ID参数不能为空");
        }
        return "liaoin:security:social:connect"+deviceId;
    }
}
