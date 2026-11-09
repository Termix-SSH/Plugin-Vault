import type { Request, Response, Router } from "express";
import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import type { AuthSessions } from "./auth-session.js";
import type {
  ProfileInput,
  ProfileRow,
  ProfileStore,
} from "./profile-store.js";
import { sendResultPage } from "./result-page.js";
import { isProvider, PROVIDERS } from "./vault-client.js";

/**
 * The signer sends the browser back here without a Termix session: the
 * sign-in is matched by the state the signer issued.
 */
export const PUBLIC_PATHS = ["/oidc/callback"];

const providerError = `provider must be one of ${PROVIDERS.join(", ")}`;

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isHttpUrl(value: string): boolean {
  try {
    const { protocol } = new URL(value.trim());
    return protocol === "http:" || protocol === "https:";
  } catch {
    return false;
  }
}

function optional(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function formatProfile(row: ProfileRow, userId: string) {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    folder: row.folder,
    tags: row.tags ? row.tags.split(",").filter(Boolean) : [],
    provider: row.provider ?? "vault",
    vaultAddr: row.vaultAddr,
    vaultNamespace: row.vaultNamespace,
    oidcMount: row.oidcMount,
    oidcRole: row.oidcRole,
    sshMount: row.sshMount,
    sshRole: row.sshRole,
    validPrincipals: row.validPrincipals,
    keyType: row.keyType,
    shared: !!row.shared,
    owned: row.userId === userId,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function parseId(req: Request): number | null {
  const id = Number.parseInt(String(req.params.id), 10);
  return Number.isFinite(id) ? id : null;
}

export function registerRoutes(
  ctx: PluginContext,
  router: Router,
  profiles: ProfileStore,
  sessions: AuthSessions,
): void {
  const userId = () => ctx.currentActor() as string;

  /**
   * @openapi
   * /plugin-api/vault/oidc/callback:
   *   get:
   *     summary: OIDC callback
   *     description: Public. The redirect URI a Vault or OpenBao OIDC role allows. Matches the sign-in by the state the signer issued, has it sign the ephemeral key and tells the terminal to reconnect.
   *     tags: [SSH Certificate Signer]
   *     parameters:
   *       - in: query
   *         name: state
   *         schema:
   *           type: string
   *       - in: query
   *         name: code
   *         schema:
   *           type: string
   *       - in: query
   *         name: error
   *         schema:
   *           type: string
   *     responses:
   *       200:
   *         description: Signed in; an HTML page that closes itself.
   *       400:
   *         description: The sign-in failed or is no longer active.
   */
  router.get("/oidc/callback", async (req: Request, res: Response) => {
    const state = typeof req.query.state === "string" ? req.query.state : "";
    const code = typeof req.query.code === "string" ? req.query.code : "";
    const error = typeof req.query.error === "string" ? req.query.error : "";

    const reply = (ok: boolean, message: string) =>
      sendResultPage(res, ok ? 200 : 400, { ok, detail: message });

    if (error) return reply(false, `Sign-in returned: ${error}`);
    if (!state || !code) return reply(false, "Missing state or code.");
    const result = await sessions.complete(state, code);
    return reply(result.ok, result.message);
  });

  router.use("/profiles", ctx.rbac.require("use") as never);

  /**
   * @openapi
   * /plugin-api/vault/profiles:
   *   get:
   *     summary: List signer profiles
   *     description: The caller's own signer profiles and every shared one. Needs vault.use.
   *     tags: [SSH Certificate Signer]
   *     responses:
   *       200:
   *         description: Array of signer profile objects.
   *       403:
   *         description: Missing vault.use.
   */
  router.get("/profiles", async (_req: Request, res: Response) => {
    const rows = await profiles.listVisible(userId());
    res.json(rows.map((row) => formatProfile(row, userId())));
  });

  /**
   * @openapi
   * /plugin-api/vault/profiles:
   *   post:
   *     summary: Create a signer profile
   *     description: Creates a signer profile owned by the caller. Needs vault.use, and vault.share to mark it shared.
   *     tags: [SSH Certificate Signer]
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required: [name, vaultAddr, sshRole]
   *             properties:
   *               name:
   *                 type: string
   *               provider:
   *                 type: string
   *                 enum: [vault, openbao]
   *                 default: vault
   *               vaultAddr:
   *                 type: string
   *               vaultNamespace:
   *                 type: string
   *               oidcMount:
   *                 type: string
   *               oidcRole:
   *                 type: string
   *               sshMount:
   *                 type: string
   *               sshRole:
   *                 type: string
   *               validPrincipals:
   *                 type: string
   *               keyType:
   *                 type: string
   *               shared:
   *                 type: boolean
   *     responses:
   *       201:
   *         description: The created profile.
   *       400:
   *         description: Missing required fields or an unknown provider.
   *       403:
   *         description: Missing vault.use, or vault.share for a shared profile.
   */
  router.post("/profiles", async (req: Request, res: Response) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    if (
      !isNonEmptyString(body.name) ||
      !isNonEmptyString(body.vaultAddr) ||
      !isNonEmptyString(body.sshRole)
    ) {
      return res
        .status(400)
        .json({ error: "name, vaultAddr and sshRole are required" });
    }
    if (!isHttpUrl(body.vaultAddr)) {
      return res
        .status(400)
        .json({ error: "vaultAddr must be an http or https URL" });
    }
    if (body.provider !== undefined && !isProvider(body.provider)) {
      return res.status(400).json({ error: providerError });
    }
    const shared = !!body.shared;
    if (shared && !(await ctx.rbac.has("share"))) {
      return res
        .status(403)
        .json({ error: "You are not allowed to share signer profiles" });
    }
    const row = await profiles.create(userId(), {
      name: body.name.trim(),
      provider: isProvider(body.provider) ? body.provider : "vault",
      description: optional(body.description),
      folder: optional(body.folder),
      tags: Array.isArray(body.tags)
        ? body.tags.join(",")
        : typeof body.tags === "string"
          ? body.tags
          : "",
      vaultAddr: body.vaultAddr.trim(),
      vaultNamespace: optional(body.vaultNamespace),
      oidcMount: optional(body.oidcMount),
      oidcRole: optional(body.oidcRole),
      sshMount: optional(body.sshMount),
      sshRole: body.sshRole.trim(),
      validPrincipals: optional(body.validPrincipals),
      keyType: optional(body.keyType),
      shared,
    });
    res.status(201).json(formatProfile(row, userId()));
  });

  /**
   * @openapi
   * /plugin-api/vault/profiles/{id}:
   *   put:
   *     summary: Update a signer profile
   *     description: Only the owner may edit a profile. Needs vault.use, and vault.share to mark it shared.
   *     tags: [SSH Certificate Signer]
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: integer
   *     requestBody:
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *     responses:
   *       200:
   *         description: The updated profile.
   *       400:
   *         description: Invalid profile id or unknown provider.
   *       403:
   *         description: Not the owner, or sharing without vault.share.
   *       404:
   *         description: Profile not found.
   */
  router.put("/profiles/:id", async (req: Request, res: Response) => {
    const id = parseId(req);
    if (id === null)
      return res.status(400).json({ error: "Invalid profile id" });
    const existing = await profiles.findById(id);
    if (!existing) return res.status(404).json({ error: "Profile not found" });
    if (existing.userId !== userId()) {
      return res
        .status(403)
        .json({ error: "Only the owner can edit this profile" });
    }

    const body = (req.body ?? {}) as Record<string, unknown>;
    const fields: ProfileInput = {};
    if (isNonEmptyString(body.name)) fields.name = body.name.trim();
    if (body.description !== undefined)
      fields.description = optional(body.description);
    if (body.folder !== undefined) fields.folder = optional(body.folder);
    if (body.tags !== undefined) {
      fields.tags = Array.isArray(body.tags)
        ? body.tags.join(",")
        : typeof body.tags === "string"
          ? body.tags
          : "";
    }
    if (body.provider !== undefined) {
      if (!isProvider(body.provider)) {
        return res.status(400).json({ error: providerError });
      }
      fields.provider = body.provider;
    }
    if (isNonEmptyString(body.vaultAddr)) {
      if (!isHttpUrl(body.vaultAddr)) {
        return res
          .status(400)
          .json({ error: "vaultAddr must be an http or https URL" });
      }
      fields.vaultAddr = body.vaultAddr.trim();
    }
    if (body.vaultNamespace !== undefined)
      fields.vaultNamespace = optional(body.vaultNamespace);
    if (body.oidcMount !== undefined)
      fields.oidcMount = optional(body.oidcMount);
    if (body.oidcRole !== undefined) fields.oidcRole = optional(body.oidcRole);
    if (body.sshMount !== undefined) fields.sshMount = optional(body.sshMount);
    if (isNonEmptyString(body.sshRole)) fields.sshRole = body.sshRole.trim();
    if (body.validPrincipals !== undefined)
      fields.validPrincipals = optional(body.validPrincipals);
    if (body.keyType !== undefined) fields.keyType = optional(body.keyType);
    if (body.shared !== undefined) {
      if (body.shared && !(await ctx.rbac.has("share"))) {
        return res
          .status(403)
          .json({ error: "You are not allowed to share signer profiles" });
      }
      fields.shared = !!body.shared;
    }

    const updated = await profiles.update(id, fields);
    if (!updated) return res.status(404).json({ error: "Profile not found" });
    res.json(formatProfile(updated, userId()));
  });

  /**
   * @openapi
   * /plugin-api/vault/profiles/{id}:
   *   delete:
   *     summary: Delete a signer profile
   *     description: Deletes a profile and every certificate cached for it. Only the owner may delete it. Needs vault.use.
   *     tags: [SSH Certificate Signer]
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: integer
   *     responses:
   *       200:
   *         description: Deleted.
   *       400:
   *         description: Invalid profile id.
   *       403:
   *         description: Not the owner.
   *       404:
   *         description: Profile not found.
   */
  router.delete("/profiles/:id", async (req: Request, res: Response) => {
    const id = parseId(req);
    if (id === null)
      return res.status(400).json({ error: "Invalid profile id" });
    const existing = await profiles.findById(id);
    if (!existing) return res.status(404).json({ error: "Profile not found" });
    if (existing.userId !== userId()) {
      return res
        .status(403)
        .json({ error: "Only the owner can delete this profile" });
    }
    await profiles.remove(existing);
    res.json({ success: true });
  });
}
