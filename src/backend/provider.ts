import type {
  PluginContext,
  PluginSshAuthProvider,
  PluginSshHost,
} from "@termix-ssh/plugin-sdk/backend";
import { applyCertificateAuth } from "@termix-ssh/plugin-sdk/ssh-certs";
import type { AuthSessions, SignInSocket } from "./auth-session.js";
import {
  toConfig,
  type ProfileRow,
  type ProfileStore,
} from "./profile-store.js";
import type { TokenStore } from "./token-store.js";
import { normalizeAddr } from "./vault-client.js";

const AUTH_TYPE = "vault";

const REQUIRED_MESSAGE =
  "Vault SSH signer authentication required. Please open a Terminal connection first.";

const AUTH_FAILED_PATTERN = /All configured authentication methods failed/i;

/** The profile a host points at, from its host settings. */
async function profileForHost(
  ctx: PluginContext,
  profiles: ProfileStore,
  hostId: number,
): Promise<ProfileRow | null> {
  const raw = await ctx.settings.getHost<number | string>(hostId, "profileId");
  const id = Number(raw);
  if (!Number.isInteger(id) || id <= 0) return null;
  return profiles.findById(id);
}

/**
 * Whether a profile may point at a private or loopback Vault: a shared
 * profile, one whose owner may share profiles (admins by default), or one
 * whose host an admin listed in the private hosts setting. Anyone else could
 * otherwise aim the server at internal addresses.
 */
export async function mayReachPrivateVault(
  ctx: PluginContext,
  profile: Pick<ProfileRow, "userId" | "shared" | "vaultAddr">,
): Promise<boolean> {
  if (profile.shared) return true;
  if (await ctx.rbac.hasFor(profile.userId, "share")) return true;
  const raw = (await ctx.settings.getAll("admin")).privateHosts;
  if (typeof raw !== "string" || !raw.trim()) return false;
  let host: string;
  try {
    host = new URL(normalizeAddr(profile.vaultAddr)).hostname.toLowerCase();
  } catch {
    return false;
  }
  return raw
    .split(/[\r\n,]+/)
    .map((entry) => entry.trim().toLowerCase())
    .includes(host);
}

/**
 * Hosts with auth type "vault" connect with a certificate Vault signed for
 * the host's profile. Without one, the terminal is asked for a browser
 * sign-in ("vault_auth_required"), which startInteraction runs.
 */
export function createVaultProvider(
  ctx: PluginContext,
  profiles: ProfileStore,
  tokens: TokenStore,
  sessions: AuthSessions,
): PluginSshAuthProvider {
  return {
    type: AUTH_TYPE,
    labelKey: "hosts.filterAuthVault",
    needsUserInteraction: true,
    supportsBackground: false,
    interaction: AUTH_TYPE,
    prepare: async (config, host: PluginSshHost, env) => {
      const profile = await profileForHost(ctx, profiles, host.id);
      if (!profile) {
        return {
          status: "error",
          code: "failed",
          message: "Host has no Vault signer profile configured",
        };
      }
      const cert = await tokens.get(env.userId, profile.id);
      if (!cert) {
        env.log(
          "info",
          "No valid Vault certificate found, requesting authentication",
        );
        return {
          status: "interaction-required",
          interaction: AUTH_TYPE,
          message: REQUIRED_MESSAGE,
          flag: "requiresVaultAuth",
        };
      }
      try {
        await applyCertificateAuth(
          config as never,
          env.client as never,
          { privateKey: cert.privateKey, certificate: cert.sshCert },
          host.username,
        );
      } catch (error) {
        return {
          status: "error",
          code: "failed",
          message:
            "Vault SSH signer authentication failed: " +
            (error instanceof Error ? error.message : String(error)),
        };
      }
      env.log("info", "Using cached Vault-signed certificate");
      return { status: "ready" };
    },
    onAuthFailed: (host, env, context) => {
      if (!AUTH_FAILED_PATTERN.test(context.error.message)) return undefined;
      ctx.log.warn("Vault certificate authentication failed, forgetting it");
      void profileForHost(ctx, profiles, host.id)
        .then((profile) =>
          profile ? tokens.remove(env.userId, profile.id) : undefined,
        )
        .catch(() => undefined);
      return {
        status: "interaction-required",
        interaction: AUTH_TYPE,
        message:
          "Vault authentication failed or expired. Please authenticate again.",
      };
    },
    startInteraction: async (request) => {
      const profile = await profileForHost(ctx, profiles, request.hostId);
      if (!profile) {
        throw new Error("No Vault signer profile configured for this host");
      }
      await sessions.start({
        userId: request.userId,
        hostId: request.hostId,
        profile: {
          ...toConfig(profile),
          allowPrivate: await mayReachPrivateVault(ctx, profile),
        },
        socket: request.socket as SignInSocket,
        requestOrigin: request.requestOrigin,
      });
    },
    cancelInteraction: (request) => {
      sessions.cancel(request.userId, request.hostId, request.requestId);
    },
  };
}
