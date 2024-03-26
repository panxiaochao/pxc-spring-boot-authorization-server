package io.github.panxiaochao.authorization.server.core.service;

import io.github.panxiaochao.authorization.infrastucture.user.entity.SysUser;
import io.github.panxiaochao.authorization.infrastucture.user.entity.SysUserAuths;
import io.github.panxiaochao.authorization.infrastucture.user.service.ISysUserService;
import io.github.panxiaochao.authorization.server.properties.Oauth2Properties;
import io.github.panxiaochao.security.core.endpoint.OAuth2EndpointUtils;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;

/**
 * <p>
 * 自定义user查询类.
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-18
 */
public class UserDetailsServiceImpl implements UserDetailsService {

	@Resource
	private ISysUserService sysUserService;

	@Resource
	public PasswordEncoder passwordEncoder;

	@Resource
	private Oauth2Properties oauth2Properties;

	private static final Pattern EMAIL_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)+$");

	private static final Pattern PHONE_PATTERN = Pattern.compile("^1(3|4|5|6|7|8|9)\\d{9}$");

	@Override
	public UserDetails loadUserByUsername(String username) {
		String identityType = IdentityTypeEnum.USERNAME.getName();
		if (PHONE_PATTERN.matcher(username).matches()) {
			identityType = IdentityTypeEnum.PHONE.getName();
		}
		else if (EMAIL_PATTERN.matcher(username).matches()) {
			identityType = IdentityTypeEnum.EMAIL.getName();
		}
		return loadUserByIdentityType(username, identityType);
	}

	public UserDetails loadUserByIdentityType(String username, String identityType) {
		SysUser sysUser = getUser(username, identityType);
		if (sysUser == null) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.SERVER_ERROR,
					"登陆类型[" + identityType + "], 用户[" + username + "]不存在或者密码错误！", null);
		}
		Collection<GrantedAuthority> authList = getAuthorities(sysUser);
		String credential = sysUser.getSysUserAuths()
			.stream()
			.filter(s -> s.getIdentityType().equals(identityType))
			.map(SysUserAuths::getCredential)
			.findFirst()
			.orElse(null);
		if (credential == null) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.SERVER_ERROR,
					"登陆类型[" + identityType + "], 用户[" + username + "]密码不存在！", null);
		}
		return createUserDetails(username, credential, authList);
	}

	protected UserDetails createUserDetails(String username, String password,
			Collection<? extends GrantedAuthority> authorities) {
		// 是否是明文
		if (oauth2Properties.isPlainPassword()) {
			// 明文的情况下，需要加密置入
			password = passwordEncoder.encode(password);
		}
		return new User(username, password, authorities);
	}

	private Collection<GrantedAuthority> getAuthorities(SysUser sysUser) {
		List<GrantedAuthority> authList = new ArrayList<>();
		sysUser.getRoles().forEach(s -> authList.add(new SimpleGrantedAuthority(s.getRoleCode().toUpperCase())));
		return authList;
	}

	private SysUser getUser(String username, String credentialsType) {
		return sysUserService.findUserByIdentityType(username, credentialsType);
	}

	/**
	 * 登录类型枚举
	 */
	@AllArgsConstructor
	@Getter
	enum IdentityTypeEnum {

		/**
		 * 用户名
		 */
		USERNAME("USERNAME"),
		/**
		 * 手机号
		 */
		PHONE("PHONE"),
		/**
		 * 邮箱
		 */
		EMAIL("EMAIL"),
		/**
		 * 微信号
		 */
		WEIXIN("WEIXIN"),
		/**
		 * 微博
		 */
		WEIBO("WEIBO"),
		/**
		 * QQ号
		 */
		QQ("QQ"),
		/**
		 * 钉钉
		 */
		DD("DD");

		private final String name;

	}

}
