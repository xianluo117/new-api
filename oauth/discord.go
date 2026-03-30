package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
)

func init() {
	Register("discord", &DiscordProvider{})
}

// DiscordProvider implements OAuth for Discord
type DiscordProvider struct{}

type discordOAuthResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type discordUser struct {
	UID  string `json:"id"`
	ID   string `json:"username"`
	Name string `json:"global_name"`
}

// discordGuildMember represents a member of a Discord guild
type discordGuildMember struct {
	Roles []string `json:"roles"`
	User  *struct {
		ID string `json:"id"`
	} `json:"user,omitempty"`
}

// DiscordRoleError indicates the user does not have the required guild role
type DiscordRoleError struct{}

func (e *DiscordRoleError) Error() string {
	return "user does not have the required Discord guild role"
}

func (p *DiscordProvider) GetName() string {
	return "Discord"
}

func (p *DiscordProvider) IsEnabled() bool {
	return system_setting.GetDiscordSettings().Enabled
}

func (p *DiscordProvider) ExchangeToken(ctx context.Context, code string, c *gin.Context) (*OAuthToken, error) {
	if code == "" {
		return nil, NewOAuthError(i18n.MsgOAuthInvalidCode, nil)
	}

	logger.LogDebug(ctx, "[OAuth-Discord] ExchangeToken: code=%s...", code[:min(len(code), 10)])

	settings := system_setting.GetDiscordSettings()
	redirectUri := fmt.Sprintf("%s/oauth/discord", system_setting.ServerAddress)
	values := url.Values{}
	values.Set("client_id", settings.ClientId)
	values.Set("client_secret", settings.ClientSecret)
	values.Set("code", code)
	values.Set("grant_type", "authorization_code")
	values.Set("redirect_uri", redirectUri)

	logger.LogDebug(ctx, "[OAuth-Discord] ExchangeToken: redirect_uri=%s", redirectUri)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://discord.com/api/v10/oauth2/token", strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := http.Client{
		Timeout: 5 * time.Second,
	}
	res, err := client.Do(req)
	if err != nil {
		logger.LogError(ctx, fmt.Sprintf("[OAuth-Discord] ExchangeToken error: %s", err.Error()))
		return nil, NewOAuthErrorWithRaw(i18n.MsgOAuthConnectFailed, map[string]any{"Provider": "Discord"}, err.Error())
	}
	defer res.Body.Close()

	logger.LogDebug(ctx, "[OAuth-Discord] ExchangeToken response status: %d", res.StatusCode)

	var discordResponse discordOAuthResponse
	err = json.NewDecoder(res.Body).Decode(&discordResponse)
	if err != nil {
		logger.LogError(ctx, fmt.Sprintf("[OAuth-Discord] ExchangeToken decode error: %s", err.Error()))
		return nil, err
	}

	if discordResponse.AccessToken == "" {
		logger.LogError(ctx, "[OAuth-Discord] ExchangeToken failed: empty access token")
		return nil, NewOAuthError(i18n.MsgOAuthTokenFailed, map[string]any{"Provider": "Discord"})
	}

	logger.LogDebug(ctx, "[OAuth-Discord] ExchangeToken success: scope=%s", discordResponse.Scope)

	return &OAuthToken{
		AccessToken:  discordResponse.AccessToken,
		TokenType:    discordResponse.TokenType,
		RefreshToken: discordResponse.RefreshToken,
		ExpiresIn:    discordResponse.ExpiresIn,
		Scope:        discordResponse.Scope,
		IDToken:      discordResponse.IDToken,
	}, nil
}

func (p *DiscordProvider) GetUserInfo(ctx context.Context, token *OAuthToken) (*OAuthUser, error) {
	logger.LogDebug(ctx, "[OAuth-Discord] GetUserInfo: fetching user info")

	req, err := http.NewRequestWithContext(ctx, "GET", "https://discord.com/api/v10/users/@me", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	client := http.Client{
		Timeout: 5 * time.Second,
	}
	res, err := client.Do(req)
	if err != nil {
		logger.LogError(ctx, fmt.Sprintf("[OAuth-Discord] GetUserInfo error: %s", err.Error()))
		return nil, NewOAuthErrorWithRaw(i18n.MsgOAuthConnectFailed, map[string]any{"Provider": "Discord"}, err.Error())
	}
	defer res.Body.Close()

	logger.LogDebug(ctx, "[OAuth-Discord] GetUserInfo response status: %d", res.StatusCode)

	if res.StatusCode != http.StatusOK {
		logger.LogError(ctx, fmt.Sprintf("[OAuth-Discord] GetUserInfo failed: status=%d", res.StatusCode))
		return nil, NewOAuthError(i18n.MsgOAuthGetUserErr, nil)
	}

	var discordUser discordUser
	err = json.NewDecoder(res.Body).Decode(&discordUser)
	if err != nil {
		logger.LogError(ctx, fmt.Sprintf("[OAuth-Discord] GetUserInfo decode error: %s", err.Error()))
		return nil, err
	}

	if discordUser.UID == "" || discordUser.ID == "" {
		logger.LogError(ctx, "[OAuth-Discord] GetUserInfo failed: empty user fields")
		return nil, NewOAuthError(i18n.MsgOAuthUserInfoEmpty, map[string]any{"Provider": "Discord"})
	}

	logger.LogDebug(ctx, "[OAuth-Discord] GetUserInfo success: uid=%s, username=%s, name=%s", discordUser.UID, discordUser.ID, discordUser.Name)

	// Check guild role if configured
	if err := p.checkGuildRole(ctx, token, discordUser.UID); err != nil {
		return nil, err
	}

	return &OAuthUser{
		ProviderUserID: discordUser.UID,
		Username:       discordUser.ID,
		DisplayName:    discordUser.Name,
	}, nil
}

// checkGuildRole verifies the user has at least one of the required roles in the specified guild.
// If GuildId is not configured, this check is skipped.
// If GuildId is set but RoleIds is empty, only guild membership is checked.
func (p *DiscordProvider) checkGuildRole(ctx context.Context, token *OAuthToken, userID string) error {
	settings := system_setting.GetDiscordSettings()
	guildId := strings.TrimSpace(settings.GuildId)
	if guildId == "" {
		// No guild restriction configured, skip check
		return nil
	}

	logger.LogDebug(ctx, "[OAuth-Discord] checkGuildRole: guildId=%s, roleIds=%s", guildId, settings.RoleIds)

	// Fetch guild member info
	// GET /users/@me/guilds/{guild.id}/member
	apiURL := fmt.Sprintf("https://discord.com/api/v10/users/@me/guilds/%s/member", guildId)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	client := http.Client{Timeout: 5 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		logger.LogError(ctx, fmt.Sprintf("[OAuth-Discord] checkGuildRole request error: %s", err.Error()))
		return NewOAuthErrorWithRaw(i18n.MsgOAuthConnectFailed, map[string]any{"Provider": "Discord"}, err.Error())
	}
	defer res.Body.Close()

	logger.LogDebug(ctx, "[OAuth-Discord] checkGuildRole response status: %d", res.StatusCode)

	// 404 or 403 means user is not in the guild
	if res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusForbidden {
		logger.LogWarn(ctx, fmt.Sprintf("[OAuth-Discord] checkGuildRole: user %s is not a member of guild %s", userID, guildId))
		return &DiscordRoleError{}
	}

	if res.StatusCode != http.StatusOK {
		logger.LogError(ctx, fmt.Sprintf("[OAuth-Discord] checkGuildRole: unexpected status %d", res.StatusCode))
		return NewOAuthError(i18n.MsgOAuthGetUserErr, nil)
	}

	var member discordGuildMember
	if err := json.NewDecoder(res.Body).Decode(&member); err != nil {
		logger.LogError(ctx, fmt.Sprintf("[OAuth-Discord] checkGuildRole decode error: %s", err.Error()))
		return err
	}

	logger.LogDebug(ctx, "[OAuth-Discord] checkGuildRole: user roles=%v", member.Roles)

	// If no specific role IDs are required, just being in the guild is enough
	roleIdsStr := strings.TrimSpace(settings.RoleIds)
	if roleIdsStr == "" {
		logger.LogDebug(ctx, "[OAuth-Discord] checkGuildRole: no specific role required, guild membership check passed")
		return nil
	}

	// Parse required role IDs
	requiredRoles := strings.Split(roleIdsStr, ";")
	requiredRoleSet := make(map[string]bool, len(requiredRoles))
	for _, r := range requiredRoles {
		r = strings.TrimSpace(r)
		if r != "" {
			requiredRoleSet[r] = true
		}
	}

	// If after trimming there are no valid role IDs, skip role check
	if len(requiredRoleSet) == 0 {
		logger.LogDebug(ctx, "[OAuth-Discord] checkGuildRole: no valid role IDs configured, guild membership check passed")
		return nil
	}

	// Check if user has at least one of the required roles
	for _, userRole := range member.Roles {
		if requiredRoleSet[userRole] {
			logger.LogDebug(ctx, "[OAuth-Discord] checkGuildRole: user has required role %s", userRole)
			return nil
		}
	}

	logger.LogWarn(ctx, fmt.Sprintf("[OAuth-Discord] checkGuildRole: user %s does not have any required role in guild %s", userID, guildId))
	return &DiscordRoleError{}
}

func (p *DiscordProvider) IsUserIDTaken(providerUserID string) bool {
	return model.IsDiscordIdAlreadyTaken(providerUserID)
}

func (p *DiscordProvider) FillUserByProviderID(user *model.User, providerUserID string) error {
	user.DiscordId = providerUserID
	return user.FillUserByDiscordId()
}

func (p *DiscordProvider) SetProviderUserID(user *model.User, providerUserID string) {
	user.DiscordId = providerUserID
}

func (p *DiscordProvider) GetProviderPrefix() string {
	return "discord_"
}
