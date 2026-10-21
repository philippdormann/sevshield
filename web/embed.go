package web

import "embed"

// FS holds the built SvelteKit static UI (web/build).
// Build it with: bun install --cwd web && bun run --cwd web build
//
//go:embed all:build
var FS embed.FS
