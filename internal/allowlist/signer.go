package allowlist

// The allowlist's signer, compiled in the release workflow of
// digicatapult/fabai-allowlist, at a vX.Y.Z tag, through GitHub
// Actions' OIDC issuer.
const (
	SignerIssuer   = "https://token.actions.githubusercontent.com"
	SignerWorkflow = "https://github.com/digicatapult/fabai-allowlist/.github/workflows/release.yml"
	// SignerSANPattern is the certificate SAN: the workflow at a release tag.
	SignerSANPattern = `^https://github\.com/digicatapult/fabai-allowlist/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$`
)
