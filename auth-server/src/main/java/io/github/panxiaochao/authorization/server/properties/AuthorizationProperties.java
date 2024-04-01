package io.github.panxiaochao.authorization.server.properties;

import io.github.panxiaochao.security.core.password.PasswordEncoderEnum;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>
 * 自定义属性.
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-17
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "authorization.server", ignoreInvalidFields = true)
@Component
public class AuthorizationProperties {

	/**
	 * passwordEncoder 密码加密模式
	 */
	private PasswordEncoderEnum passwordEncoder;

	/**
	 * seed
	 */
	private String seed = "@123456$";

	/**
	 * 数据库加密是否是明文
	 */
	private boolean plainPassword;

	/**
	 * 白名单 Url
	 */
	private List<String> whiteUrls = new ArrayList<>();

}
