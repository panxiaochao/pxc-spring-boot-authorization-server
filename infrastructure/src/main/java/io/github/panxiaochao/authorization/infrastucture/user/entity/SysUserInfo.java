package io.github.panxiaochao.authorization.infrastucture.user.entity;

import io.github.panxiaochao.authorization.infrastucture.role.entity.SysRoleInfo;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

/**
 * <p>
 * 用户表
 * </p>
 *
 * @author pxc creator
 * @since 2022-02-15
 */
@Getter
@Setter
public class SysUserInfo {

	private Integer id;

	/**
	 * 用户真实姓名
	 */
	private String realName;

	/**
	 * 用户昵称（花名）
	 */
	private String nickName;

	/**
	 * 用户头像
	 */
	private String avatar;

	/**
	 * 性别：1男，0女
	 */
	private String sex;

	/**
	 * 手机号码
	 */
	private String mobile;

	/**
	 * 皮肤风格
	 */
	private String skins;

	/**
	 * 所在区域或者部门ID，多数据请用逗号隔开
	 */
	private Integer orgId;

	/**
	 * 所在区域或者部门编码code，多数据请用逗号隔开
	 */
	private String orgCode;

	/**
	 * 角色集合
	 */
	private List<SysRoleInfo> roles;

}
