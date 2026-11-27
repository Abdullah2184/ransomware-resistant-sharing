use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::{
    AppState, error, failure, middleware::invalid_signature_failure, parse_bearer_token,
    unix_seconds,
};
use crate::{
    auth::{LoginChallenge, challenge_digest, parse_member_id, parse_nonce, recover_signer},
    store::{encode_hex, hash_session_token, source_identifier},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChallengeRequest {
    pub(crate) member_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionRequest {
    challenge: LoginChallenge,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionResponse {
    token: String,
    token_type: &'static str,
    expires_at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionIdentity {
    member_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PublicIdentityResponse {
    pub(crate) member_id: String,
    pub(crate) organization_id: String,
    pub(crate) signing_address: String,
    pub(crate) signing_key_version: u32,
    pub(crate) encryption_key_version: u32,
    pub(crate) encryption_public_key: String,
    pub(crate) status: &'static str,
    pub(crate) finalized_block: u64,
    pub(crate) finalized_block_hash: String,
}

pub(crate) async fn health() -> &'static str {
    "ok"
}

pub(crate) async fn public_identity(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(raw_member_id): Path<String>,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let Ok(member_id) = parse_member_id(&raw_member_id) else {
        return failure(
            &state,
            "identity.lookup",
            &source_id,
            "invalid_request",
            None,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Ok(finalized) = state.chain.finalized_block().await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    };
    let identity = match state
        .chain
        .member_identity(
            &state.config.access_governance,
            member_id.as_bytes(),
            finalized.number,
        )
        .await
    {
        Ok(Some(identity)) => identity,
        Ok(None) => return error(StatusCode::NOT_FOUND, "not_found"),
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    let status = match identity.status {
        1 => "active",
        2 => "suspended",
        3 => "revoked",
        _ => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    Json(PublicIdentityResponse {
        member_id: member_id.to_string(),
        organization_id: encode_hex(&identity.organization_id),
        signing_address: identity.signing_address.to_string(),
        signing_key_version: identity.signing_key_version,
        encryption_key_version: identity.encryption_key_version,
        encryption_public_key: encode_hex(&identity.encryption_public_key),
        status,
        finalized_block: finalized.number,
        finalized_block_hash: finalized.hash,
    })
    .into_response()
}

pub(crate) async fn create_challenge(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: Result<Json<ChallengeRequest>, JsonRejection>,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let Ok(Json(request)) = body else {
        return failure(
            &state,
            "auth.challenge",
            &source_id,
            "invalid_json",
            None,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Ok(member) = parse_member_id(&request.member_id) else {
        return failure(
            &state,
            "auth.challenge",
            &source_id,
            "invalid_request",
            None,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Some(issued_at) = unix_seconds() else {
        return failure(
            &state,
            "auth.challenge",
            &source_id,
            "clock_unavailable",
            None,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
        )
        .await;
    };
    let Some(expires_at) = issued_at.checked_add(state.config.challenge_ttl_seconds) else {
        return failure(
            &state,
            "auth.challenge",
            &source_id,
            "clock_unavailable",
            None,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
        )
        .await;
    };
    let mut nonce = [0; 32];
    if getrandom::fill(&mut nonce).is_err() || nonce == [0; 32] {
        return failure(
            &state,
            "auth.challenge",
            &source_id,
            "randomness_unavailable",
            None,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
        )
        .await;
    }
    let challenge = LoginChallenge {
        member_id: member.to_string(),
        nonce: encode_hex(&nonce),
        issued_at,
        expires_at,
        audience: state.config.audience.clone(),
        protocol_version: 1,
    };
    match state
        .store
        .create_challenge(&challenge, &source_id, state.config.chain_id)
        .await
    {
        Ok(()) => Json(challenge).into_response(),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

pub(crate) async fn create_session(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: Result<Json<SessionRequest>, JsonRejection>,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let Ok(Json(request)) = body else {
        return failure(
            &state,
            "auth.session",
            &source_id,
            "invalid_json",
            None,
            StatusCode::BAD_REQUEST,
            "unauthorized",
        )
        .await;
    };
    let Ok(member) = parse_member_id(&request.challenge.member_id) else {
        return failure(
            &state,
            "auth.session",
            &source_id,
            "invalid_challenge",
            None,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    };
    if validate_challenge(&state, &request.challenge).is_err() {
        return failure(
            &state,
            "auth.session",
            &source_id,
            "invalid_challenge",
            None,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    }
    let Ok(digest) = challenge_digest(
        &request.challenge,
        state.config.chain_id,
        state.config.access_governance,
    ) else {
        return failure(
            &state,
            "auth.session",
            &source_id,
            "invalid_challenge",
            None,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    };
    let Ok(claimed_signer) = recover_signer(&digest, &request.signature) else {
        return invalid_signature_failure(&state, "auth.session", &source_id, None).await;
    };
    let Ok(finalized) = state.chain.finalized_block().await else {
        return failure(
            &state,
            "auth.session",
            &source_id,
            "chain_unavailable",
            None,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
        )
        .await;
    };
    let Ok(identity) = state
        .chain
        .member_identity(
            &state.config.access_governance,
            member.as_bytes(),
            finalized.number,
        )
        .await
    else {
        return failure(
            &state,
            "auth.session",
            &source_id,
            "chain_unavailable",
            None,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
        )
        .await;
    };
    let active_signer = identity
        .filter(|member| member.active())
        .map(|member| member.signing_address);
    if active_signer != Some(claimed_signer) {
        return invalid_signature_failure(&state, "auth.session", &source_id, None).await;
    }

    let Some(session_expires_at) =
        unix_seconds().and_then(|now| now.checked_add(state.config.session_ttl_seconds))
    else {
        return failure(
            &state,
            "auth.session",
            &source_id,
            "clock_unavailable",
            None,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
        )
        .await;
    };
    let mut token = [0; 32];
    if getrandom::fill(&mut token).is_err() || token == [0; 32] {
        return failure(
            &state,
            "auth.session",
            &source_id,
            "randomness_unavailable",
            None,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
        )
        .await;
    }
    match state
        .store
        .complete_login(
            &request.challenge,
            &hash_session_token(&token),
            session_expires_at,
            &source_id,
            state.config.chain_id,
            finalized.number,
        )
        .await
    {
        Ok(true) => Json(SessionResponse {
            token: encode_hex(&token),
            token_type: "Bearer",
            expires_at: session_expires_at,
        })
        .into_response(),
        Ok(false) => {
            failure(
                &state,
                "auth.session",
                &source_id,
                "challenge_consumed_or_expired",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await
        }
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

pub(crate) async fn session_identity(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let Some(token) = parse_bearer_token(&headers) else {
        return failure(
            &state,
            "auth.session.validate",
            &source_id,
            "invalid_session",
            None,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    };
    match state
        .store
        .active_session_member(&hash_session_token(&token))
        .await
    {
        Ok(Some(member_id)) => {
            match state
                .store
                .record_session_validation(
                    Some(&member_id),
                    &source_id,
                    "authenticated",
                    None,
                    state.config.chain_id,
                )
                .await
            {
                Ok(()) => Json(SessionIdentity { member_id }).into_response(),
                Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
            }
        }
        Ok(None) => {
            match state
                .store
                .record_session_validation(
                    None,
                    &source_id,
                    "denied",
                    Some("invalid_session"),
                    state.config.chain_id,
                )
                .await
            {
                Ok(()) => error(StatusCode::UNAUTHORIZED, "unauthorized"),
                Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
            }
        }
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

pub(crate) async fn revoke_session(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let Some(token) = parse_bearer_token(&headers) else {
        return failure(
            &state,
            "auth.session.revoke",
            &source_id,
            "invalid_session",
            None,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    };
    match state
        .store
        .revoke_session(
            &hash_session_token(&token),
            &source_id,
            state.config.chain_id,
        )
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => {
            failure(
                &state,
                "auth.session.revoke",
                &source_id,
                "invalid_session",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await
        }
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

fn validate_challenge(state: &AppState, challenge: &LoginChallenge) -> Result<(), ()> {
    let now = unix_seconds().ok_or(())?;
    parse_nonce(&challenge.nonce).map_err(|_| ())?;
    if challenge.protocol_version != 1
        || challenge.audience != state.config.audience
        || challenge.issued_at == 0
        || challenge.issued_at > now
        || challenge.expires_at <= now
        || challenge.expires_at <= challenge.issued_at
        || challenge.expires_at - challenge.issued_at > state.config.challenge_ttl_seconds
    {
        return Err(());
    }
    Ok(())
}
