//! RBAC（T-33，设计文档 §31/§68，api.md §12）：权限码 + 默认角色 → 权限映射 + 校验助手。
//!
//! 默认角色（§161）：`admin` 全权；`operator` = nodes/routes 读写；`viewer` = 全部只读。
//! 角色名来自 `users` 会话（`User.role`，单角色，登录时取首个角色名）；权限不足返回 403。

use super::ApiError;
use crate::session::User;

/// 权限码（api.md §12）。稳定机器可读字符串，供日志/错误信息输出。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    NodesRead,
    NodesWrite,
    RoutesRead,
    RoutesWrite,
    UsersRead,
    UsersWrite,
    LogsRead,
    AuditRead,
    SettingsRead,
    SettingsWrite,
}

impl Permission {
    /// 稳定权限码字符串（如 `nodes.read`）。
    pub fn code(self) -> &'static str {
        match self {
            Self::NodesRead => "nodes.read",
            Self::NodesWrite => "nodes.write",
            Self::RoutesRead => "routes.read",
            Self::RoutesWrite => "routes.write",
            Self::UsersRead => "users.read",
            Self::UsersWrite => "users.write",
            Self::LogsRead => "logs.read",
            Self::AuditRead => "audit.read",
            Self::SettingsRead => "settings.read",
            Self::SettingsWrite => "settings.write",
        }
    }

    /// 是否为只读权限（`viewer` 角色的默认授权集合）。
    fn is_read(self) -> bool {
        matches!(
            self,
            Self::NodesRead
                | Self::RoutesRead
                | Self::UsersRead
                | Self::LogsRead
                | Self::AuditRead
                | Self::SettingsRead
        )
    }
}

/// 判断某角色是否拥有某权限（纯函数，无 IO）。
pub fn role_has_permission(role: &str, perm: Permission) -> bool {
    match role {
        "admin" => true,
        "operator" => matches!(
            perm,
            Permission::NodesRead
                | Permission::NodesWrite
                | Permission::RoutesRead
                | Permission::RoutesWrite
        ),
        "viewer" => perm.is_read(),
        _ => false,
    }
}

/// 判断某用户是否拥有某权限（按其会话角色）。
pub fn user_has_permission(user: &User, perm: Permission) -> bool {
    role_has_permission(&user.role, perm)
}

/// 校验用户权限，不足返回 403。供各 handler 在写/读操作前调用（T-33）。
pub fn require_permission(user: &User, perm: Permission) -> Result<(), ApiError> {
    if user_has_permission(user, perm) {
        Ok(())
    } else {
        Err(ApiError::forbidden(format!(
            "permission '{}' required",
            perm.code()
        )))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn admin_has_everything() {
        for perm in [
            Permission::NodesRead,
            Permission::NodesWrite,
            Permission::RoutesWrite,
            Permission::UsersWrite,
            Permission::SettingsWrite,
        ] {
            assert!(role_has_permission("admin", perm), "{perm:?} for admin");
        }
    }

    #[test]
    fn operator_has_nodes_and_routes_rw() {
        assert!(role_has_permission("operator", Permission::NodesRead));
        assert!(role_has_permission("operator", Permission::NodesWrite));
        assert!(role_has_permission("operator", Permission::RoutesRead));
        assert!(role_has_permission("operator", Permission::RoutesWrite));
        // operator 不能管用户/审计/设置。
        assert!(!role_has_permission("operator", Permission::UsersRead));
        assert!(!role_has_permission("operator", Permission::UsersWrite));
        assert!(!role_has_permission("operator", Permission::SettingsWrite));
    }

    #[test]
    fn viewer_is_read_only() {
        assert!(role_has_permission("viewer", Permission::NodesRead));
        assert!(role_has_permission("viewer", Permission::RoutesRead));
        assert!(role_has_permission("viewer", Permission::LogsRead));
        // viewer 不能写。
        assert!(!role_has_permission("viewer", Permission::NodesWrite));
        assert!(!role_has_permission("viewer", Permission::RoutesWrite));
        assert!(!role_has_permission("viewer", Permission::UsersWrite));
    }

    #[test]
    fn unknown_role_has_nothing() {
        assert!(!role_has_permission("user", Permission::NodesRead));
        assert!(!role_has_permission("", Permission::NodesRead));
    }
}
