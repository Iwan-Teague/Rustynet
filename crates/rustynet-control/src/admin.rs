#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Viewer,
    Operator,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAction {
    ViewNodes,
    ManagePolicy,
    ManageExitNodes,
    ManageCredentials,
    ManageUsers,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminPrincipal {
    pub user_id: String,
    pub role: Role,
    pub mfa_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSecurity {
    pub secure_cookie: bool,
    pub http_only_cookie: bool,
    pub same_site_strict: bool,
    pub csrf_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminError {
    Unauthorized,
    MfaRequired,
    CsrfInvalid,
    SessionInsecure,
    InvalidInput,
    CommandRejected,
}

impl fmt::Display for AdminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdminError::Unauthorized => f.write_str("unauthorized"),
            AdminError::MfaRequired => f.write_str("mfa required"),
            AdminError::CsrfInvalid => f.write_str("invalid csrf token"),
            AdminError::SessionInsecure => f.write_str("insecure session policy"),
            AdminError::InvalidInput => f.write_str("invalid input"),
            AdminError::CommandRejected => f.write_str("privileged command rejected"),
        }
    }
}

impl std::error::Error for AdminError {}

pub struct AdminAuthorizer;

impl AdminAuthorizer {
    pub fn authorize(
        principal: &AdminPrincipal,
        action: AdminAction,
        submitted_csrf_token: &str,
        session: &SessionSecurity,
    ) -> Result<(), AdminError> {
        if !session.secure_cookie || !session.http_only_cookie || !session.same_site_strict {
            return Err(AdminError::SessionInsecure);
        }
        if submitted_csrf_token != session.csrf_token {
            return Err(AdminError::CsrfInvalid);
        }

        if !role_allows(principal.role, action) {
            return Err(AdminError::Unauthorized);
        }
        if is_privileged(action) && !principal.mfa_verified {
            return Err(AdminError::MfaRequired);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSecurityHeaders {
    pub x_frame_options: String,
    pub content_security_policy: String,
    pub referrer_policy: String,
}

pub fn default_web_security_headers() -> WebSecurityHeaders {
    WebSecurityHeaders {
        x_frame_options: "DENY".to_string(),
        content_security_policy: "frame-ancestors 'none'".to_string(),
        referrer_policy: "no-referrer".to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdminApiState {
    nodes: Vec<String>,
    policies: Vec<String>,
    exit_nodes: Vec<String>,
    credentials: Vec<String>,
}

impl AdminApiState {
    pub fn add_node(&mut self, node_id: impl Into<String>) {
        self.nodes.push(node_id.into());
    }

    pub fn list_nodes(
        &self,
        principal: &AdminPrincipal,
        submitted_csrf_token: &str,
        session: &SessionSecurity,
    ) -> Result<Vec<String>, AdminError> {
        AdminAuthorizer::authorize(
            principal,
            AdminAction::ViewNodes,
            submitted_csrf_token,
            session,
        )?;
        Ok(self.nodes.clone())
    }

    pub fn update_policy(
        &mut self,
        principal: &AdminPrincipal,
        submitted_csrf_token: &str,
        session: &SessionSecurity,
        policy: String,
    ) -> Result<(), AdminError> {
        if policy.trim().is_empty() {
            return Err(AdminError::InvalidInput);
        }
        AdminAuthorizer::authorize(
            principal,
            AdminAction::ManagePolicy,
            submitted_csrf_token,
            session,
        )?;
        self.policies.push(policy);
        Ok(())
    }

    pub fn set_exit_node(
        &mut self,
        principal: &AdminPrincipal,
        submitted_csrf_token: &str,
        session: &SessionSecurity,
        node_id: String,
    ) -> Result<(), AdminError> {
        if node_id.trim().is_empty() {
            return Err(AdminError::InvalidInput);
        }
        AdminAuthorizer::authorize(
            principal,
            AdminAction::ManageExitNodes,
            submitted_csrf_token,
            session,
        )?;
        self.exit_nodes.push(node_id);
        Ok(())
    }

    pub fn create_credential(
        &mut self,
        principal: &AdminPrincipal,
        submitted_csrf_token: &str,
        session: &SessionSecurity,
        credential_id: String,
    ) -> Result<(), AdminError> {
        if credential_id.trim().is_empty() {
            return Err(AdminError::InvalidInput);
        }
        AdminAuthorizer::authorize(
            principal,
            AdminAction::ManageCredentials,
            submitted_csrf_token,
            session,
        )?;
        self.credentials.push(credential_id);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegedCommand {
    pub program: String,
    pub args: Vec<String>,
    pub run_as_user: String,
}

pub fn validate_privileged_command(command: &PrivilegedCommand) -> Result<(), AdminError> {
    if !command.program.starts_with('/') {
        return Err(AdminError::CommandRejected);
    }
    if command.run_as_user.trim().is_empty() || command.run_as_user == "root" {
        return Err(AdminError::CommandRejected);
    }
    if command.args.iter().any(|arg| contains_shell_meta(arg)) {
        return Err(AdminError::CommandRejected);
    }
    Ok(())
}

pub fn command_preview(command: &PrivilegedCommand) -> Result<String, AdminError> {
    validate_privileged_command(command)?;
    let mut output = String::new();
    output.push_str("program=");
    output.push_str(&command.program);
    output.push_str(" args=");
    output.push_str(&command.args.join(" "));
    output.push_str(" run_as=");
    output.push_str(&command.run_as_user);
    Ok(output)
}

fn role_allows(role: Role, action: AdminAction) -> bool {
    match role {
        Role::Viewer => matches!(action, AdminAction::ViewNodes),
        Role::Operator => matches!(
            action,
            AdminAction::ViewNodes | AdminAction::ManageExitNodes
        ),
        Role::Admin => true,
    }
}

fn is_privileged(action: AdminAction) -> bool {
    matches!(
        action,
        AdminAction::ManagePolicy
            | AdminAction::ManageExitNodes
            | AdminAction::ManageCredentials
            | AdminAction::ManageUsers
    )
}

fn contains_shell_meta(value: &str) -> bool {
    value.chars().any(|ch| {
        matches!(
            ch,
            ';' | '|' | '&' | '$' | '`' | '<' | '>' | '(' | ')' | '{' | '}'
        )
    })
}

pub fn policy_bootstrap_defaults() -> BTreeMap<String, String> {
    let mut defaults = BTreeMap::new();
    defaults.insert("mode".to_string(), "default-deny".to_string());
    defaults.insert("allow_all".to_string(), "false".to_string());
    defaults
}

#[cfg(test)]
mod tests {
    use super::{
        AdminApiState, AdminError, AdminPrincipal, PrivilegedCommand, Role, SessionSecurity,
        command_preview, default_web_security_headers, policy_bootstrap_defaults,
        validate_privileged_command,
    };

    fn secure_session() -> SessionSecurity {
        SessionSecurity {
            secure_cookie: true,
            http_only_cookie: true,
            same_site_strict: true,
            csrf_token: "csrf-123".to_string(),
        }
    }

    #[test]
    fn rbac_is_deny_by_default_for_privileged_actions() {
        let mut api = AdminApiState::default();
        let viewer = AdminPrincipal {
            user_id: "viewer".to_string(),
            role: Role::Viewer,
            mfa_verified: true,
        };

        let result = api.update_policy(
            &viewer,
            "csrf-123",
            &secure_session(),
            "allow group:family -> tag:servers".to_string(),
        );
        assert_eq!(result.err(), Some(AdminError::Unauthorized));
    }

    #[test]
    fn mfa_is_required_for_privileged_mutations() {
        let mut api = AdminApiState::default();
        let admin_without_mfa = AdminPrincipal {
            user_id: "admin".to_string(),
            role: Role::Admin,
            mfa_verified: false,
        };

        let result = api.update_policy(
            &admin_without_mfa,
            "csrf-123",
            &secure_session(),
            "allow group:family -> tag:servers".to_string(),
        );
        assert_eq!(result.err(), Some(AdminError::MfaRequired));
    }

    #[test]
    fn csrf_and_session_policies_are_enforced() {
        let mut api = AdminApiState::default();
        api.add_node("node-a");
        let admin = AdminPrincipal {
            user_id: "admin".to_string(),
            role: Role::Admin,
            mfa_verified: true,
        };

        let csrf_err = api.list_nodes(&admin, "wrong", &secure_session());
        assert_eq!(csrf_err.err(), Some(AdminError::CsrfInvalid));

        let mut insecure = secure_session();
        insecure.secure_cookie = false;
        let insecure_err = api.list_nodes(&admin, "csrf-123", &insecure);
        assert_eq!(insecure_err.err(), Some(AdminError::SessionInsecure));
    }

    #[test]
    fn clickjacking_headers_are_hardened() {
        let headers = default_web_security_headers();
        assert_eq!(headers.x_frame_options, "DENY");
        assert_eq!(headers.content_security_policy, "frame-ancestors 'none'");
    }

    #[test]
    fn privileged_helper_validation_rejects_shell_construction() {
        let invalid = PrivilegedCommand {
            program: "ip".to_string(),
            args: vec!["route".to_string(), "add;rm -rf /".to_string()],
            run_as_user: "netadmin".to_string(),
        };
        assert_eq!(
            validate_privileged_command(&invalid).err(),
            Some(AdminError::CommandRejected)
        );
    }

    #[test]
    fn privileged_helper_validation_accepts_argv_only_commands() {
        let command = PrivilegedCommand {
            program: "/sbin/ip".to_string(),
            args: vec![
                "route".to_string(),
                "replace".to_string(),
                "100.64.0.0/10".to_string(),
                "dev".to_string(),
                "rustynet0".to_string(),
            ],
            run_as_user: "netadmin".to_string(),
        };
        let preview = command_preview(&command).expect("command should be accepted");
        assert!(preview.contains("/sbin/ip"));
    }

    #[test]
    fn policy_bootstrap_defaults_to_safe_values() {
        let defaults = policy_bootstrap_defaults();
        assert_eq!(defaults.get("mode"), Some(&"default-deny".to_string()));
        assert_eq!(defaults.get("allow_all"), Some(&"false".to_string()));
    }
}
