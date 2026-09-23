# Unpinned MCP server, client-config shape

Existence-proof DENY only. Not an attack-success-rate claim.

The artefact pin and post-checkout HEAD match. The manifest uses a
name-keyed `mcpServers` object: one stdio transport (`command`, `args`,
`env`, `cwd`) with a full-digest pin, and one `http` transport (`url`,
`headers`) with no pin. A transport without a full-digest pin is
`mcp_server_unpinned`. `verify_performed` stays true. Same deny class as
`eval/mcp_server_unpinned/`. No new deny reason.
