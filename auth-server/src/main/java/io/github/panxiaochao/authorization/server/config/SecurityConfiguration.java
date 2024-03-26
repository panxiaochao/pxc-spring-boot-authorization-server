package io.github.panxiaochao.authorization.server.config;

import io.github.panxiaochao.authorization.server.properties.Oauth2Properties;
import io.github.panxiaochao.security.core.constants.GlobalSecurityConstant;
import io.github.panxiaochao.security.core.handler.ServerAccessDeniedHandler;
import io.github.panxiaochao.security.core.handler.ServerLogoutSuccessHandler;
import io.github.panxiaochao.security.core.handler.form.ServerFormAuthenticationEntryPoint;
import io.github.panxiaochao.security.core.handler.form.ServerFormAuthenticationFailureHandler;
import io.github.panxiaochao.security.core.handler.form.ServerFormAuthenticationSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.CollectionUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.annotation.Resource;
import java.util.Collections;
import java.util.List;

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

	@Resource
	private Oauth2Properties oauth2Properties;

	/**
	 * <p>
	 * 配置本地静态资源放行, 暴露静态资源
	 * </p>
	 * <p>
	 * <a href= "https://github.com/spring-projects/spring-security/issues/10938">WARN
	 * when ignoring antMatchers - please use permitAll</a>
	 * </p>
	 * @param httpSecurity httpSecurity
	 */
	@Bean
	@Order(0)
	public SecurityFilterChain resources(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.requestMatchers((matchers) -> matchers.antMatchers("/assets/**"))
			.authorizeHttpRequests((authorize) -> authorize.anyRequest().permitAll());
		// .requestCache(RequestCacheConfigurer::disable)
		// .securityContext(AbstractHttpConfigurer::disable)
		// .sessionManagement(AbstractHttpConfigurer::disable);
		return httpSecurity.build();
	}

	/**
	 * Security 默认安全策略
	 * @param httpSecurity httpSecurity
	 * @return SecurityFilterChain
	 */
	@Bean
	@Order
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) {
		List<String> whiteUrls = oauth2Properties.getWhiteUrls();
		// @formatter:off
		try {
			// 基础配置
			httpSecurity.cors().configurationSource(corsConfigurationSource());

			// 过滤白名单
			if (CollectionUtils.isEmpty(whiteUrls)) {
				httpSecurity.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
			} else{
				httpSecurity.authorizeHttpRequests(authorize -> authorize
						// 只放行OAuth相关接口
						.antMatchers(whiteUrls.toArray(new String[0])).permitAll()
						// 除上面外的所有请求全部需要鉴权认证
						.anyRequest().authenticated());
			}

			// 过滤请求
			httpSecurity.formLogin(formLogin -> formLogin
						.loginPage(GlobalSecurityConstant.LOGIN_PATH)
						.failureHandler(new ServerFormAuthenticationFailureHandler())
						.successHandler(new ServerFormAuthenticationSuccessHandler())
						.permitAll())
					.logout(logout -> logout
							.logoutSuccessHandler(new ServerLogoutSuccessHandler())
							.deleteCookies("JSESSIONID")
							.invalidateHttpSession(true))
					// 异常报错拦截
					.exceptionHandling(
							exception -> exception
									.accessDeniedHandler(new ServerAccessDeniedHandler())
									.authenticationEntryPoint(new ServerFormAuthenticationEntryPoint())
					)
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
