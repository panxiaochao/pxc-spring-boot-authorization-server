package io.github.panxiaochao.authorization.server.core.service;

import io.github.panxiaochao.authorization.infrastucture.user.entity.SysUser;
import io.github.panxiaochao.authorization.infrastucture.user.entity.SysUserAuths;
import io.github.panxiaochao.authorization.infrastucture.user.service.ISysUserService;
import io.github.panxiaochao.authorization.server.properties.Oauth2Properties;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

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
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		String identityType = IdentityTypeEnum.USERNAME.name();
		if (PHONE_PATTERN.matcher(username).matches()) {
			identityType = IdentityTypeEnum.PHONE.name();
		}
		else if (EMAIL_PATTERN.matcher(username).matches()) {
			identityType = IdentityTypeEnum.EMAIL.name();
		}
		return loadUserByIdentityType(username, identityType);
	}

	public UserDetails loadUserByIdentityType(String username, String identityType) {
		SysUser sysUser = getUser(username, identityType);
		if (sysUser == null) {
			throw new UsernameNotFoundException("用户[" + username + "]不存在或者密码错误！");
		}
		Collection<GrantedAuthority> authList = getAuthorities(sysUser);
		String credential = sysUser.getSysUserAuths()
			.stream()
			.filter(s -> s.getIdentityType().equals(identityType))
			.map(SysUserAuths::getCredential)
			.findFirst()
			.orElse(null);
		if (credential == null) {
			throw new UsernameNotFoundException("用户[" + username + "]密码错误！");
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

		USERNAME, PHONE, EMAIL, WEIXIN, WEIBO, QQ, DINGDING

	}

}
