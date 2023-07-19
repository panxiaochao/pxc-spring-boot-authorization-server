package io.github.panxiaochao.authorization.infrastucture.user.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * <p>
 * 用户授权信息表
 * </p>
 *
 * @author pxc creator
 * @since 2022-02-15
 */
@Getter
@Setter
public class SysUserAuths implements Serializable {

	private static final long serialVersionUID = 1L;

	/**
	 * 唯一标识
	 */
	@TableId(value = "id", type = IdType.AUTO)
	private Integer id;

	/**
	 * 关联用户ID
	 */
	private Integer userId;

	/**
	 * 登录类型(手机号/邮箱/用户名/微信/微博/QQ）等
	 */
	private String identityType;

	/**
	 * 登录标识(手机号/邮箱/用户名/微信/微博/QQ）等唯一标识，等同于登录账号
	 */
	private String identifier;

	/**
	 * 密码凭证（自建密码，或者第三方access_token）
	 */
	private String credential;

	/**
	 * 是否已经验证：1验证，0未验证
	 */
	private String verified;

	/**
	 * 登录标识失效时间
	 */
	private LocalDateTime expireTime;
}
