import { useEffect, useRef, useState } from "react";
import { useTranslation } from "@termix-ssh/plugin-sdk/frontend";
import { VaultDialog, type SignInStage } from "./VaultDialog";

/** What the ssh-terminal plugin hands a "terminal.overlay" component. */
export interface TerminalOverlayProps {
  host: { id: number | string; [key: string]: unknown } | undefined;
  backgroundColor?: string;
  // In a frame this call crosses to the shell, so it answers with a Promise.
  subscribe: (
    listener: (message: { type: string; [key: string]: unknown }) => void,
  ) => (() => void) | Promise<() => void>;
  holdConnectTimeout: (held: boolean) => void;
  fail: (message: string) => void;
  disconnect: () => void;
  send: (type: string, data?: unknown) => void;
  connectPayload: () =>
    Record<string, unknown> | Promise<Record<string, unknown>>;
}

interface DialogState {
  stage: SignInStage;
  provider?: string;
  authUrl?: string;
  error?: string;
  hostId?: unknown;
  requestId?: string;
}

/** How long the dialog waits before giving up on the connection. */
const DIALOG_TIMEOUT_MS = 300_000;

/**
 * Runs the OIDC sign-in for a terminal: asks the server to start it, opens
 * the signer's auth URL when the user asks, and reconnects once the
 * certificate is signed.
 */
export function VaultOverlay({
  subscribe,
  holdConnectTimeout,
  fail,
  disconnect,
  send,
  connectPayload,
  backgroundColor,
}: TerminalOverlayProps) {
  const { t } = useTranslation();
  const [dialog, setDialog] = useState<DialogState | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const heldRef = useRef(false);
  // A second "auth required" after a sign-in means the certificate did not work.
  const failedRef = useRef(false);
  // The terminal replays what a late overlay missed, so skip repeats.
  const seenSeqRef = useRef(0);

  useEffect(() => {
    const clearTimer = () => {
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = null;
    };
    const hold = (held: boolean) => {
      if (heldRef.current === held) return;
      heldRef.current = held;
      holdConnectTimeout(held);
    };

    const subscribed = subscribe((message) => {
      if (typeof message.seq === "number") {
        if (message.seq <= seenSeqRef.current) return;
        seenSeqRef.current = message.seq;
      }
      switch (message.type) {
        case "vault_auth_required":
          hold(true);
          if (failedRef.current) {
            clearTimer();
            hold(false);
            setDialog({ stage: "error", error: t("dialog.failed") });
            fail(t("dialog.failed"));
          } else {
            failedRef.current = true;
            send("vault_start_auth", { hostId: message.hostId });
          }
          break;
        case "vault_auth_url":
          setDialog({
            stage: "chooser",
            authUrl: String(message.url ?? ""),
            provider:
              typeof message.provider === "string"
                ? message.provider
                : undefined,
            hostId: message.hostId,
            requestId:
              typeof message.requestId === "string"
                ? message.requestId
                : undefined,
          });
          clearTimer();
          timerRef.current = setTimeout(() => {
            setDialog(null);
            hold(false);
            disconnect();
          }, DIALOG_TIMEOUT_MS);
          break;
        case "vault_completed":
          clearTimer();
          setDialog(null);
          // In a frame this call crosses to the terminal and answers later.
          void Promise.resolve(connectPayload()).then((payload) =>
            send("vault_auth_completed", payload),
          );
          break;
        case "vault_error":
          failedRef.current = true;
          clearTimer();
          hold(false);
          setDialog((current) => ({
            ...current,
            stage: "error",
            error: String(message.error ?? ""),
          }));
          break;
        case "connected":
        case "sessionAttached":
          failedRef.current = false;
          hold(false);
          break;
        case "session_closed":
          clearTimer();
          setDialog(null);
          hold(false);
          break;
      }
    });

    return () => {
      void Promise.resolve(subscribed)
        .then((unsubscribe) => {
          if (typeof unsubscribe === "function") unsubscribe();
        })
        .catch(() => {});
      clearTimer();
      if (heldRef.current) {
        heldRef.current = false;
        holdConnectTimeout(false);
      }
    };
  }, [
    subscribe,
    holdConnectTimeout,
    fail,
    disconnect,
    send,
    connectPayload,
    t,
  ]);

  if (!dialog) return null;

  const close = () => {
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = null;
    if (dialog.stage !== "error") {
      send("vault_cancel", {
        hostId: dialog.hostId,
        requestId: dialog.requestId,
      });
    }
    setDialog(null);
    if (heldRef.current) {
      heldRef.current = false;
      holdConnectTimeout(false);
    }
  };

  return (
    <VaultDialog
      stage={dialog.stage}
      provider={dialog.provider}
      error={dialog.error}
      onCancel={close}
      onOpenUrl={() => {
        if (!dialog.authUrl) return;
        window.open(dialog.authUrl, "_blank", "noopener,noreferrer");
        setDialog((current) =>
          current ? { ...current, stage: "waiting" } : null,
        );
      }}
      backgroundColor={backgroundColor}
    />
  );
}
