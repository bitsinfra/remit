#!/usr/bin/env node
// Sender-side MCP helper (stdio): remit_describe, remit_check, remit_send.
import { RemitMcp } from "../src/mcp.ts";
new RemitMcp().serveStdio();
