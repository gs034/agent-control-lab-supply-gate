# Unpinned MCP server

Existence-proof DENY only. Not an attack-success-rate claim.

The artefact pin and post-checkout HEAD match, but the declared manifest
lists an MCP server without a full-digest pin (`latest`). A manifest
cannot substitute a tag or a promise for a digest. The host path DENY with
`mcp_server_unpinned`; `verify_performed` stays true. Threat pattern:
unpinned MCP dependencies in agent harness setups (harness-scan class).
