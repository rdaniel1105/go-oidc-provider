package handler

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
	"github.com/rdaniel1105/go-oidc-provider/internal/oidc"
)

// mintCIBATokensInput collects the values mintCIBATokens needs from the
// caller. The caller is responsible for having already verified the
// CIBARequest is legitimate (status = approved, client owns it, user
// exists); the helper just runs the cryptographic side.
type mintCIBATokensInput struct {
	// Client is the RP that owns the request.
	Client *domain.Client
	// User is the op_user the tokens will be issued for.
	User *domain.OPUser
	// Scope is the granted scope set, copied from the CIBARequest.
	Scope []string
	// AuthTime is the wall-clock moment the user proved themselves at
	// the approval ceremony (CIBARequest.ApprovedAt).
	AuthTime time.Time
	// Issuer is the OP issuer URL.
	Issuer string
	// AccessTTL bounds the access + ID token lifetime.
	AccessTTL time.Duration
	// RefreshTTL bounds the refresh-token lifetime.
	RefreshTTL time.Duration
}

// mintedTokens is the output of mintCIBATokens — the four strings the
// caller needs plus the expiry timestamps required to persist the
// refresh-token row.
type mintedTokens struct {
	AccessToken  string
	IDToken      string
	RefreshRaw   string
	RefreshHash  string
	IssuedAt     time.Time
	AccessExpiry time.Time
	RefreshExp   time.Time
}

// mintCIBATokens signs the access + ID tokens and generates the refresh
// token for a CIBA-approved request. The helper does NOT persist the
// refresh row; the caller decides when (after a successful push, after
// a poll redemption, etc.) so push failures don't leave orphan rows in
// Postgres.
func mintCIBATokens(_ context.Context, in mintCIBATokensInput, keys activeKeySource) (mintedTokens, error) {
	kid, priv, err := keys.Active()
	if err != nil {
		return mintedTokens{}, fmt.Errorf("active key: %w", err)
	}

	now := nowUTC()
	accessExpiry := now.Add(in.AccessTTL)

	accessToken, err := oidc.MintAccessToken(oidc.AccessTokenInput{
		Issuer:    in.Issuer,
		SubjectID: in.User.ID.String(),
		ClientID:  in.Client.ClientID,
		IssuedAt:  now,
		Expiry:    accessExpiry,
		Scope:     in.Scope,
	}, priv, kid)
	if err != nil {
		return mintedTokens{}, fmt.Errorf("mint access token: %w", err)
	}

	idToken, err := oidc.MintIDToken(oidc.IDTokenInput{
		Issuer:    in.Issuer,
		SubjectID: in.User.ID.String(),
		Audience:  in.Client.ClientID,
		IssuedAt:  now,
		Expiry:    accessExpiry,
		AuthTime:  in.AuthTime,
		ACR:       "urn:passkey",
		AMR:       []string{"webauthn", "user"},
		Scope:     in.Scope,
		Email:     in.User.Email,
		Name:      in.User.DisplayName,
	}, priv, kid)
	if err != nil {
		return mintedTokens{}, fmt.Errorf("mint id token: %w", err)
	}

	refreshRaw, refreshHash, err := oidc.NewRefreshToken()
	if err != nil {
		return mintedTokens{}, fmt.Errorf("new refresh token: %w", err)
	}

	return mintedTokens{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshRaw:   refreshRaw,
		RefreshHash:  refreshHash,
		IssuedAt:     now,
		AccessExpiry: accessExpiry,
		RefreshExp:   now.Add(in.RefreshTTL),
	}, nil
}

// persistCIBARefreshRow writes the refresh-token row for a fresh CIBA
// issuance: a new family_id, auth_time copied from the approval moment,
// and the supplied hash.
func persistCIBARefreshRow(
	ctx context.Context,
	store refreshTokenStore,
	client *domain.Client,
	user *domain.OPUser,
	scope []string,
	hash string,
	authTime time.Time,
	expiresAt time.Time,
) error {
	_, err := store.Create(ctx, &domain.RefreshToken{
		TokenHash: hash,
		ClientID:  client.ClientID,
		OPUserID:  user.ID,
		FamilyID:  uuid.New(),
		Scope:     scope,
		AuthTime:  authTime,
		ExpiresAt: expiresAt,
	})
	return err
}
