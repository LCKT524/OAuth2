package cn.iocoder.springboot.lab68.authorizationserverdemo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

/**
 * 授权服务器配置
 * @author Liuc_dell
 */
@Configuration
@EnableAuthorizationServer  //声明开启 OAuth 授权服务器的功能
public class OAuth2AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    /**
     * 用户认证 Manager
     */
    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        //配置用户认证功能
        endpoints.authenticationManager(authenticationManager);
    }


    @Override
    //设置 /oauth/check_token 端点（对应 CheckTokenEndpoint 类，用于校验访问令牌的有效性），通过认证后可访问
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.checkTokenAccess("isAuthenticated()");//已通过身份验证
//        oauthServer.tokenKeyAccess("isAuthenticated()")
//                .checkTokenAccess("isAuthenticated()");
//        oauthServer.tokenKeyAccess("permitAll()")
//                .checkTokenAccess("permitAll()");
    }

    @Override
    //进行 Client 客户端的配置
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
                //设置使用基于内存的 Client 存储器。实际情况下，最好放入数据库中，方便管理
                clients.inMemory()
                // Client 账号、密码。
                .withClient("clientapp").secret("112233")
                // 密码模式
                .authorizedGrantTypes("password")
                // 可授权的 Scope
                .scopes("read_userinfo", "read_contacts")
                // 可以继续配置新的 Client
//                .and().withClient()
                ;
    }

}
