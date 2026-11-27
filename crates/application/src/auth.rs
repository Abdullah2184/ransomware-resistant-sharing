use crypto::{ChainId, Eip712Domain, LoginChallengeDigestInput};
use domain::{DomainError, EvmAddress};
use ports::{AuthenticatedSession, Clock, GatewayAuthPort, KeyCustodyProvider};

/// Bounded clock-skew tolerance for `challenge.issued_at` (seconds).
///
/// Permits up to 5 seconds of routine NTP drift between endpoint and gateway
/// clocks while still strictly requiring `challenge.expires_at > now` and
/// bounding total challenge lifetime to `max_challenge_ttl_seconds`.
pub const MAX_CHALLENGE_CLOCK_SKEW_SECONDS: u64 = 5;

/// Configuration for authenticating an endpoint session against a gateway.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthConfig {
    pub chain_id: u64,
    pub access_governance: EvmAddress,
    pub expected_audience: String,
    pub max_challenge_ttl_seconds: u64,
}

impl AuthConfig {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.chain_id == 0
            || self.expected_audience.is_empty()
            || self.expected_audience.len() > 512
            || self.expected_audience.chars().any(char::is_control)
            || self.max_challenge_ttl_seconds == 0
        {
            return Err(DomainError::Internal);
        }
        Ok(())
    }
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
        self.config.validate()?;
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
            || challenge.issued_at > now.saturating_add(MAX_CHALLENGE_CLOCK_SKEW_SECONDS)
            || challenge.expires_at <= challenge.issued_at
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
