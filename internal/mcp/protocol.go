package mcp

import (
	"encoding/json"
	"slices"
	"strings"
)

// MCP protocol versions.
//
// 2026-07-28 is stateless: there is no initialize handshake, and every
// request names its protocol version and the client capabilities in
// params._meta. The older versions negotiate once through initialize and
// then send plain requests; they keep working unchanged.
const (
	// ProtocolVersionStateless is the newest MCP protocol version this
	// server speaks. It has no initialize handshake.
	ProtocolVersionStateless = "2026-07-28"

	// ProtocolVersionLatest is the newest version negotiated through
	// initialize. initialize echoes the client's requested version when it
	// is a handshake version this server supports, else answers with this.
	ProtocolVersionLatest = "2025-06-18"
)

// supportedProtocolVersions is the closed set of protocol versions this
// server accepts, newest first (the order server/discover reports).
var supportedProtocolVersions = []string{ProtocolVersionStateless, ProtocolVersionLatest, "2025-03-26", "2024-11-05"}

// Reserved _meta keys of the 2026-07-28 protocol.
const (
	metaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	metaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	metaServerInfo         = "io.modelcontextprotocol/serverInfo"
)

// Protocol error codes introduced by 2026-07-28.
const (
	codeHeaderMismatch             = -32020
	codeUnsupportedProtocolVersion = -32022
)

// resultTypeComplete marks a 2026-07-28 result as final. This server never
// returns partial or task results.
const resultTypeComplete = "complete"

// Cache hints of the 2026-07-28 list and discovery results: the tool set
// depends on this server's policy, so clients must not share it (private)
// and should re-fetch it rather than cache it (ttl 0).
const (
	listTTLMs      = 0
	listCacheScope = "private"
)

// handshakeVersion reports whether v is a supported version negotiated
// through initialize.
func handshakeVersion(v string) bool {
	return v != ProtocolVersionStateless && slices.Contains(supportedProtocolVersions, v)
}

// serverInstructions is the usage hint sent by initialize and
// server/discover. initialize clients see the same text as before
// 2026-07-28 support existed.
const serverInstructions = "Tools expose the skret secret manager for the resolved .skret.yaml environment. " +
	"Secret values are returned only by skret_get; skret_list returns key names only. " +
	"Write tools require mcp.allow_write: true in .skret.yaml (default off)."

// requestMeta is the part of any request's params this layer reads.
type requestMeta struct {
	Meta map[string]json.RawMessage `json:"_meta"`
}

// requestVersion reads the per-request protocol version from
// params._meta. It returns "" for a request that names none (an
// initialize-era client). A version that is present but malformed or
// unsupported is a protocol error, as is a 2026-07-28 request without its
// client capabilities. Params that are not an object are left to the
// method to reject.
func (s *Server) requestVersion(params json.RawMessage) (string, *rpcError) {
	if len(params) == 0 {
		return "", nil
	}
	var m requestMeta
	if err := json.Unmarshal(params, &m); err != nil {
		return "", nil
	}
	raw, ok := m.Meta[metaProtocolVersion]
	if !ok {
		return "", nil
	}
	var version string
	if err := json.Unmarshal(raw, &version); err != nil || version == "" {
		return "", &rpcError{Code: codeInvalidParams, Message: "invalid params: _meta " + metaProtocolVersion + " must be a protocol version string"}
	}
	if !slices.Contains(supportedProtocolVersions, version) {
		return "", &rpcError{
			Code:    codeUnsupportedProtocolVersion,
			Message: "Unsupported protocol version",
			Data: map[string]any{
				"supported": slices.Clone(supportedProtocolVersions),
				"requested": s.redact(version),
			},
		}
	}
	if version == ProtocolVersionStateless {
		var caps map[string]any
		raw, ok := m.Meta[metaClientCapabilities]
		if !ok || json.Unmarshal(raw, &caps) != nil || caps == nil {
			return "", &rpcError{Code: codeInvalidParams, Message: "invalid params: _meta " + metaClientCapabilities + " must be an object"}
		}
	}
	return version, nil
}

// dispatchStateless routes one 2026-07-28 request. Every result carries
// resultType and the server identity in _meta; there is no initialize or
// ping in this version.
func (s *Server) dispatchStateless(req *rpcRequest) (any, *rpcError) {
	switch req.Method {
	case "server/discover":
		return discoverResult{
			ResultType:        resultTypeComplete,
			SupportedVersions: slices.Clone(supportedProtocolVersions),
			Capabilities:      map[string]any{"tools": map[string]any{}},
			Instructions:      serverInstructions,
			TTLMs:             listTTLMs,
			CacheScope:        listCacheScope,
			Meta:              s.resultMeta(),
		}, nil
	case "tools/list":
		return statelessToolsResult{
			ResultType: resultTypeComplete,
			Tools:      s.visibleTools(),
			TTLMs:      listTTLMs,
			CacheScope: listCacheScope,
			Meta:       s.resultMeta(),
		}, nil
	case "tools/call":
		res, rpcErr := s.toolsCall(req.Params)
		if rpcErr != nil {
			return nil, rpcErr
		}
		res.ResultType = resultTypeComplete
		res.Meta = s.resultMeta()
		return res, nil
	}
	if strings.HasPrefix(req.Method, "notifications/") {
		return nil, nil
	}
	return nil, &rpcError{Code: codeMethodNotFound, Message: "method not found: " + req.Method}
}

// resultMeta is the _meta every 2026-07-28 result carries.
func (s *Server) resultMeta() map[string]any {
	return map[string]any{metaServerInfo: serverInfo{Name: ServerName, Version: s.opts.Version}}
}

// discoverResult is the 2026-07-28 server/discover result.
type discoverResult struct {
	ResultType        string         `json:"resultType"`
	SupportedVersions []string       `json:"supportedVersions"`
	Capabilities      map[string]any `json:"capabilities"`
	Instructions      string         `json:"instructions,omitempty"`
	TTLMs             int            `json:"ttlMs"`
	CacheScope        string         `json:"cacheScope"`
	Meta              map[string]any `json:"_meta"`
}

// statelessToolsResult is the 2026-07-28 tools/list result.
type statelessToolsResult struct {
	ResultType string         `json:"resultType"`
	Tools      []toolDesc     `json:"tools"`
	TTLMs      int            `json:"ttlMs"`
	CacheScope string         `json:"cacheScope"`
	Meta       map[string]any `json:"_meta"`
}
