package oci

import (
	"fmt"
	"strings"
)

// OCI secret names are flat, unique per vault, and limited to 1-255
// characters of letters, digits, periods, hyphens and underscores (see the
// CreateSecret API docs). skret keys are slash-delimited paths
// ("/myapp/prod/DATABASE_URL"), so the provider encodes each key into a
// legal secret name:
//
//	path "/myapp/prod" + key "/myapp/prod/DATABASE_URL"
//	  -> name "myapp-prod_DATABASE_URL"
//
// The configured path becomes the name prefix (its "/" separators become
// "-"), a single "_" separates prefix and leaf, and any "/" inside the leaf
// is encoded as "-". Decoding under a known prefix (secretKeyFor) is
// unambiguous; choosing paths that differ only by "/"-vs-"-" spelling
// within one vault makes those names collide, and OCI rejects the duplicate
// on create -- use distinct vaults for such paths.

// pathToken maps a normalized skret path to its secret-name prefix.
// Root paths ("", "/") have no token.
func pathToken(path string) string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return ""
	}
	return strings.ReplaceAll(trimmed, "/", "-")
}

// secretNameFor maps a skret key (full path-prefixed, bare leaf, or root
// form) to the OCI secret name it is stored under.
func secretNameFor(path, key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("oci: key is empty")
	}
	token := pathToken(path)
	var leaf string
	if token == "" {
		leaf = strings.TrimPrefix(key, "/")
	} else {
		rp := strings.TrimRight(path, "/")
		switch {
		case strings.HasPrefix(key, rp+"/"):
			leaf = key[len(rp)+1:]
		case key == rp:
			return "", fmt.Errorf("oci: key %q is the configured path itself, not a secret under it", key)
		case !strings.HasPrefix(key, "/"):
			// Bare leaf from a library caller; relative to the configured path.
			leaf = key
		default:
			return "", fmt.Errorf("oci: key %q is outside the configured path %q", key, path)
		}
	}
	leaf = strings.ReplaceAll(leaf, "/", "-")
	name := leaf
	if token != "" {
		name = token + "_" + leaf
	}
	if !validSecretName(name) {
		return "", fmt.Errorf("oci: key %q maps to invalid secret name %q (need 1-255 chars of letters, digits, '.', '-', '_')", key, name)
	}
	return name, nil
}

// secretKeyFor maps an OCI secret name back to the skret key it represents
// under pathPrefix. ok is false when the name does not belong to that
// prefix (it was stored under a different skret path in the same vault).
func secretKeyFor(pathPrefix, name string) (key string, ok bool) {
	rp := strings.TrimRight(pathPrefix, "/")
	if rp == "" {
		return name, true
	}
	prefix := pathToken(pathPrefix) + "_"
	if !strings.HasPrefix(name, prefix) {
		return "", false
	}
	leaf := name[len(prefix):]
	if leaf == "" {
		return "", false
	}
	return rp + "/" + leaf, true
}

// validSecretName reports whether name fits the OCI Vault secret-name rule:
// 1-255 characters of letters, digits, periods, hyphens and underscores.
func validSecretName(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	for i := range len(name) {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}
