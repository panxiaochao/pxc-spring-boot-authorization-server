package io.github.panxiaochao.authorization.server.config;

import io.github.panxiaochao.authorization.server.core.constants.GlobalSecurityConstant;
import io.github.panxiaochao.authorization.server.core.handler.ServerFormAuthenticationFailureHandler;
import io.github.panxiaochao.authorization.server.core.handler.ServerFormAuthenticationSuccessHandler;
import io.github.panxiaochao.authorization.server.core.handler.ServerLogoutSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Collections;

/**
 * <p>
 * SecurityConfiguration 配置类.
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-17
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class SecurityConfiguration {

	/**
	 * 配置本地静态资源放行
	 * @return WebSecurityCustomizer
	 */
	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return (web) -> web.ignoring().antMatchers("/assets/**");
	}

	/**
	 * Security 默认安全策略
	 * @param httpSecurity httpSecurity
	 * @return SecurityFilterChain
	 */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 1)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) {
		// @formatter:off
		try {
			// 基础配置
			httpSecurity.cors().configurationSource(corsConfigurationSource());

			// 过滤请求
			httpSecurity.authorizeHttpRequests(authorize -> authorize
				// 只放行OAuth相关接口
				.antMatchers("/api/**", GlobalSecurityConstant.LOGIN_PATH, "/oauth2/consent", "/error").permitAll()
				// 除上面外的所有请求全部需要鉴权认证
				.anyRequest().authenticated())
				.formLogin(formLogin -> formLogin
						.loginPage(GlobalSecurityConstant.LOGIN_PATH)
						.failureHandler(new ServerFormAuthenticationFailureHandler())
						.successHandler(new ServerFormAuthenticationSuccessHandler())
						.permitAll())
					.logout(logout -> logout
							.logoutSuccessHandler(new ServerLogoutSuccessHandler())
							.deleteCookies("JSESSIONID")
							.invalidateHttpSession(true))
					.csrf().and().headers().frameOptions().sameOrigin();
			return httpSecurity.build();
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
		// @formatter:on
	}

	/**
	 * security cors 配置
	 * @return CorsConfigurationSource
	 */
	private CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Collections.singletonList("*"));
		configuration.setAllowedMethods(Collections.singletonList("*"));
		configuration.setAllowedHeaders(Collections.singletonList("*"));
		configuration.setAllowCredentials(true);
		configuration.setMaxAge(3600L);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

}
