package io.github.panxiaochao.authorization.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * <p>
 * RegisteredClientConfiguration 客户端配置类.
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-17
 */
@Configuration(proxyBeanMethods = false)
public class RegisteredClientConfiguration {

	/**
	 * （必需）负责注册的 Client 信息, 对应 oauth2_registered_client 表.
	 * @return RegisteredClientRepository
	 */
	@Bean
	public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
		return new JdbcRegisteredClientRepository(jdbcTemplate);
	}

}
