use crypto::{ChainId, Eip712Domain, LoginChallengeDigestInput};
use domain::{DomainError, EvmAddress};
use ports::{AuthenticatedSession, Clock, GatewayAuthPort, KeyCustodyProvider};

/// Configuration for authenticating an endpoint session against a gateway.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthConfig {
    pub chain_id: u64,
    pub access_governance: EvmAddress,
    pub expected_audience: String,
    pub max_challenge_ttl_seconds: u64,
}

/// Orchestrates EIP-712 challenge-response login using key custody.
pub struct AuthService<K, G, C> {
    custody: K,
    gateway: G,
    clock: C,
    config: AuthConfig,
}

impl<K, G, C> AuthService<K, G, C>
where
    K: KeyCustodyProvider,
    G: GatewayAuthPort,
    C: Clock,
{
    pub fn new(custody: K, gateway: G, clock: C, config: AuthConfig) -> Self {
        Self {
            custody,
            gateway,
            clock,
            config,
        }
    }

    /// Runs the one-time EIP-712 login challenge flow and returns a short-lived session.
    pub async fn login(&self) -> Result<AuthenticatedSession, DomainError> {
        let identity = self
            .custody
            .public_identity()
            .await
            .map_err(|_| DomainError::KeyCustodyUnavailable)?;
        let challenge = self.gateway.request_challenge(identity.member_id).await?;
        let now = self.clock.now_unix_seconds()?;

        if challenge.member_id != identity.member_id
            || challenge.audience != self.config.expected_audience
            || challenge.protocol_version != 1
            || challenge.issued_at == 0
            || challenge.issued_at > now
            || challenge.expires_at <= now
            || challenge.expires_at.saturating_sub(challenge.issued_at)
                > self.config.max_challenge_ttl_seconds
        {
            return Err(DomainError::Unauthenticated);
        }

        let digest_input = LoginChallengeDigestInput::new(
            challenge.member_id,
            challenge.nonce,
            challenge.issued_at,
            challenge.expires_at,
            challenge.audience.clone(),
            challenge.protocol_version,
        )
        .map_err(|_| DomainError::Unauthenticated)?;
        let domain = Eip712Domain::gateway(
            ChainId::from_u64(self.config.chain_id),
            self.config.access_governance,
        );
        let digest = digest_input
            .digest(&domain)
            .map_err(|_| DomainError::Internal)?;
        let signature = self
            .custody
            .sign_typed_digest(&identity.signing_key_id, &digest)
            .await
            .map_err(|_| DomainError::KeyCustodyUnavailable)?;

        let session = self
            .gateway
            .exchange_challenge(&challenge, &signature)
            .await?;
        if session.member_id != identity.member_id || session.expires_at <= now {
            return Err(DomainError::Unauthenticated);
        }
        Ok(session)
    }
}
