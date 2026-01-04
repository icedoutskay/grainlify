package handlers

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/jagadeesh/grainlify/backend/internal/auth"
	"github.com/jagadeesh/grainlify/backend/internal/config"
	"github.com/jagadeesh/grainlify/backend/internal/db"
	"github.com/jagadeesh/grainlify/backend/internal/github"
)

type AuthHandler struct {
	cfg config.Config
	db  *db.DB
}

func NewAuthHandler(cfg config.Config, d *db.DB) *AuthHandler {
	return &AuthHandler{cfg: cfg, db: d}
}

type nonceRequest struct {
	WalletType string `json:"wallet_type"`
	Address    string `json:"address"`
}

func (h *AuthHandler) Nonce() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if h.db == nil || h.db.Pool == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "db_not_configured"})
		}

		var req nonceRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_json"})
		}

		wType, err := auth.NormalizeWalletType(req.WalletType)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_wallet_type"})
		}
		addr, err := auth.NormalizeAddress(wType, req.Address)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_address"})
		}

		n, err := auth.CreateNonce(c.Context(), h.db.Pool, wType, addr, 10*time.Minute)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "nonce_create_failed"})
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"nonce":      n.Nonce,
			"message":    auth.LoginMessage(n.Nonce),
			"expires_at": n.ExpiresAt,
		})
	}
}

type verifyRequest struct {
	WalletType string `json:"wallet_type"`
	Address    string `json:"address"`
	Nonce      string `json:"nonce"`
	Signature  string `json:"signature"`
	PublicKey  string `json:"public_key,omitempty"`
}

func (h *AuthHandler) Verify() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if h.db == nil || h.db.Pool == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "db_not_configured"})
		}
		if h.cfg.JWTSecret == "" {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "jwt_not_configured"})
		}

		var req verifyRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_json"})
		}

		wType, err := auth.NormalizeWalletType(req.WalletType)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_wallet_type"})
		}
		addr, err := auth.NormalizeAddress(wType, req.Address)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_address"})
		}
		if req.Nonce == "" || req.Signature == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing_nonce_or_signature"})
		}

		// Be tolerant during early dev: accept both the current canonical message and the
		// legacy newline message (so signing tools that copied `\n` vs newline don't block you).
		msgs := []string{
			auth.LoginMessage(req.Nonce),
			auth.LegacyLoginMessage(req.Nonce),
		}
		var sigOK bool
		for _, msg := range msgs {
			if err := auth.VerifySignature(wType, addr, msg, req.Signature, req.PublicKey); err == nil {
				sigOK = true
				break
			}
		}
		if !sigOK {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_signature"})
		}

		res, err := auth.ConsumeNonceAndUpsertUser(c.Context(), h.db.Pool, wType, addr, req.Nonce, req.PublicKey)
		if err != nil {
			if err.Error() == "invalid_or_expired_nonce" {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_or_expired_nonce"})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "auth_failed"})
		}

		token, err := auth.IssueJWT(h.cfg.JWTSecret, res.User.ID, res.User.Role, res.Wallet.WalletType, res.Wallet.Address, 15*time.Minute)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token_issue_failed"})
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"token": token,
			"user":  res.User,
			"wallet": fiber.Map{
				"wallet_type": res.Wallet.WalletType,
				"address":     res.Wallet.Address,
			},
		})
	}
}

func (h *AuthHandler) Me() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if h.db == nil || h.db.Pool == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "db_not_configured"})
		}

		userIDStr, _ := c.Locals(auth.LocalUserID).(string)
		role, _ := c.Locals(auth.LocalRole).(string)
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_user"})
		}

		response := fiber.Map{
			"id":   userIDStr,
			"role": role,
		}

		// Try to get GitHub access token and fetch full profile
		linkedAccount, err := github.GetLinkedAccount(c.Context(), h.db.Pool, userID, h.cfg.TokenEncKeyB64)
		if err == nil {
			// Fetch full GitHub user profile
			gh := github.NewClient()
			ghUser, err := gh.GetUser(c.Context(), linkedAccount.AccessToken)
			if err == nil {
				githubMap := fiber.Map{
					"login":     ghUser.Login,
					"avatar_url": ghUser.AvatarURL,
				}
				// Add optional fields if available
				if ghUser.Name != "" {
					githubMap["name"] = ghUser.Name
				}
				if ghUser.Email != "" {
					githubMap["email"] = ghUser.Email
				}
				if ghUser.Location != "" {
					githubMap["location"] = ghUser.Location
				}
				if ghUser.Bio != "" {
					githubMap["bio"] = ghUser.Bio
				}
				if ghUser.Blog != "" {
					githubMap["website"] = ghUser.Blog
				}
				response["github"] = githubMap
			} else {
				// Fallback to database values if GitHub API fails
				var githubLogin *string
				var avatarURL *string
				_ = h.db.Pool.QueryRow(c.Context(), `
SELECT login, avatar_url
FROM github_accounts
WHERE user_id = $1
`, userID).Scan(&githubLogin, &avatarURL)
				if githubLogin != nil {
					githubMap := fiber.Map{
						"login": *githubLogin,
					}
					if avatarURL != nil && *avatarURL != "" {
						githubMap["avatar_url"] = *avatarURL
					}
					response["github"] = githubMap
				}
			}
		} else {
			// No GitHub account linked, try to get from database anyway
			var githubLogin *string
			var avatarURL *string
			_ = h.db.Pool.QueryRow(c.Context(), `
SELECT login, avatar_url
FROM github_accounts
WHERE user_id = $1
`, userID).Scan(&githubLogin, &avatarURL)
			if githubLogin != nil {
				githubMap := fiber.Map{
					"login": *githubLogin,
				}
				if avatarURL != nil && *avatarURL != "" {
					githubMap["avatar_url"] = *avatarURL
				}
				response["github"] = githubMap
			}
		}

		return c.Status(fiber.StatusOK).JSON(response)
	}
}


