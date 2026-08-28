//! Tool failures, and how they reach each front end.
//!
//! MCP models two different failures and the difference matters here:
//!
//! * `Err(ErrorData)` — the server could not route the request at all. Clients
//!   render these opaquely, so the message does *not* reach the model.
//! * `Ok(CallToolResult { is_error: Some(true), .. })` — the tool ran and
//!   reported failure. The content reaches the model, which can correct itself.
//!
//! Everything in this file produces the second kind. The CLI turns the same
//! outcome into a non-zero exit code plus stderr; that translation lives in
//! `main.rs` and reads
//! [`ToolOutcome::is_error`](vibrev_kit::ToolOutcome::is_error), so the two front
//! ends cannot disagree about whether a call failed.

use std::fmt;

use rmcp::model::{CallToolResponse, CallToolResult, ContentBlock};

/// A failure a caller should see and can act on.
#[derive(Debug)]
pub enum ToolError {
    /// Arguments parsed, but do not name anything this engine can act on.
    InvalidParams(String),
    /// The named function / address / view does not exist.
    NotFound(String),
    /// Binary Ninja refused, or answered in a way we cannot use.
    Bn(String),
    /// A worker process failed to spawn, died, or stopped answering.
    Worker(String),
    /// The request is well formed and this server simply has no room for it
    /// right now. Distinct from [`Self::Worker`] because nothing failed, and
    /// from [`Self::InvalidParams`] because nothing the caller wrote is wrong —
    /// retrying later is the correct response, and neither of those two says so.
    Busy(String),
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParams(m) => write!(f, "invalid parameters: {m}"),
            Self::NotFound(m) => write!(f, "not found: {m}"),
            Self::Bn(m) => write!(f, "Binary Ninja error: {m}"),
            Self::Worker(m) => write!(f, "worker error: {m}"),
            Self::Busy(m) => write!(f, "busy: {m}"),
        }
    }
}

impl std::error::Error for ToolError {}

impl ToolError {
    /// The MCP shape of this failure: a *successful* response carrying
    /// `isError: true`.
    pub fn to_tool_result(&self) -> CallToolResult {
        CallToolResult::error(vec![ContentBlock::text(self.to_string())])
    }

    pub fn to_response(&self) -> CallToolResponse {
        self.to_tool_result().into()
    }
}

#[cfg(test)]
mod tests {
    use super::ToolError;

    /// The distinction this file turns on: a failed tool is a *successful*
    /// response carrying `isError: true`, because that is the only form whose
    /// message reaches the model.
    #[test]
    fn a_tool_failure_is_a_successful_response_flagged_as_an_error() {
        let result =
            ToolError::NotFound("no function named frobnicate".to_owned()).to_tool_result();
        assert_eq!(result.is_error, Some(true));
        let text = result
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.clone())
            .expect("the failure carries text a model can read");
        assert!(text.contains("frobnicate"), "{text}");
    }
}
