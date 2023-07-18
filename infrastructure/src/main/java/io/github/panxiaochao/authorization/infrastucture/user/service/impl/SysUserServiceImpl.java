package io.github.panxiaochao.authorization.infrastucture.user.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import io.github.panxiaochao.authorization.infrastucture.role.entity.SysRole;
import io.github.panxiaochao.authorization.infrastucture.role.service.ISysRoleService;
import io.github.panxiaochao.authorization.infrastucture.user.entity.SysUser;
import io.github.panxiaochao.authorization.infrastucture.user.entity.SysUserAuths;
import io.github.panxiaochao.authorization.infrastucture.user.mapper.SysUserMapper;
import io.github.panxiaochao.authorization.infrastucture.user.service.ISysUserAuthsService;
import io.github.panxiaochao.authorization.infrastucture.user.service.ISysUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

/**
 * <p>
 * 用户表 服务实现类
 * </p>
 *
 * @author pxc creator
 * @since 2022-02-15
 */
@Service
public class SysUserServiceImpl extends ServiceImpl<SysUserMapper, SysUser> implements ISysUserService {

	@Autowired
	private ISysRoleService sysRoleService;

	@Autowired
	private ISysUserAuthsService sysUserAuthsService;

	@Override
	public SysUser findUserByUsername(String username) {
		SysUser sysUser = querySysUserAuthsByIdentity(username, "username");
		if (sysUser != null) {
			List<SysRole> listRoles = sysRoleService.queryRolesByUser(sysUser);
			sysUser.setRoles(listRoles);
			return sysUser;
		}
		return null;
	}

	@Override
	public SysUser findUserByIdentityType(String username, String credentialsType) {
		SysUser sysUser = querySysUserAuthsByIdentity(username, credentialsType);
		if (sysUser != null) {
			List<SysRole> listRoles = sysRoleService.queryRolesByUser(sysUser);
			sysUser.setRoles(listRoles);
			return sysUser;
		}
		return null;
	}

	private SysUser querySysUserAuthsByIdentity(String username, String credentialsType) {
		SysUserAuths sysUserAuths = sysUserAuthsService.querySysUserByIdentity(credentialsType, username);
		if (sysUserAuths == null) {
			return null;
		}
		SysUser sysUser = this.getById(sysUserAuths.getUserId());
		sysUser.setSysUserAuths(Collections.singletonList(sysUserAuths));
		return sysUser;
	}

}
