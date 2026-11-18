import type { ComponentType } from "react";
import type { TermixApp } from "@termix-ssh/plugin-sdk/frontend";
import { VaultAuthEditor } from "./VaultAuthEditor";
import { VaultOverlay } from "./VaultOverlay";
import { RedirectUriSetting } from "./RedirectUriSetting";

/** Only hosts that use this auth, or reach it through a jump host, need it. */
function needsSignIn(context: Record<string, unknown>, authType: string) {
  const host = context.host as
    { authType?: string; jumpHosts?: unknown[] } | undefined;
  return host?.authType === authType || (host?.jumpHosts?.length ?? 0) > 0;
}

export function activate(app: TermixApp): void {
  app.registerSshAuthEditor({
    authType: "vault",
    titleKey: "hosts.filterAuthVault",
    component: VaultAuthEditor,
  });

  // The signer sign-in while a terminal connects to a host that uses it.
  app.registerSlotContribution("terminal.overlay", {
    actionId: "vault.signIn",
    when: (context) => needsSignIn(context, "vault"),
    titleKey: "dialog.title",
    kind: "component",
    component: VaultOverlay as unknown as ComponentType<
      Record<string, unknown>
    >,
  });

  app.registerSettingsComponent("redirectUri", RedirectUriSetting);
}

export function deactivate(): void {
  // Registrations through app are disposed by core.
}
