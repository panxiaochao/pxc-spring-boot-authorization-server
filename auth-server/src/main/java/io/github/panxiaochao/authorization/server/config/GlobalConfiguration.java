package io.github.panxiaochao.authorization.server.config;

import io.github.panxiaochao.authorization.server.core.crypto.PasswordEncoderFactory;
import io.github.panxiaochao.authorization.server.core.service.UserDetailsServiceImpl;
import io.github.panxiaochao.authorization.server.properties.Oauth2Properties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Objects;

/**
 * <p>
 * 全局 Bean 构造，包括 UserDetailsService, PasswordEncoder.
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-18
 */
@Configuration(proxyBeanMethods = false)
public class GlobalConfiguration {

	/**
	 * 自定义 UserDetailsService.
	 */
	@Bean
	public UserDetailsService userDetailService() {
		return new UserDetailsServiceImpl();
	}

	/**
	 * 自定义密码模式 - 默认MD5模式.
	 * @return PasswordEncoder
	 */
	@Bean
	public PasswordEncoder passwordEncoder(Oauth2Properties oauth2Properties) {
		return Objects.isNull(oauth2Properties.getPasswordEncoder())
				? PasswordEncoderFactory.createDelegatingPasswordEncoder() : PasswordEncoderFactory
					.createDelegatingPasswordEncoder(oauth2Properties.getPasswordEncoder().getName());
	}

}
