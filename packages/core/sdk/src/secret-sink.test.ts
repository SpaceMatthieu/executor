import { describe, it, expect } from "vitest";
import { Effect } from "effect";
import {
  EnrollDeviceInput,
  EnrollDeviceOutput,
  SecretSinkRunOutput,
  SecretSinkSignalInput,
  findForbiddenSecrets,
  rejectIfSecretShaped,
} from "./secret-sink";
import { Schema } from "effect";

describe("secret-sink schemas and guards", () => {
  it("accepts an allowlisted tailscale.join signal", async () => {
    const valid = {
      action: "tailscale.join",
      hostname: "dynamik-ops-grokbot",
      tags: ["tag:grok-ops"],
      dryRun: true as const,
      authKeyFrom: {
        connection: "tailscale_api.user.dynamikTailscale",
        op: "keys.createKey",
        params: {
          tailnet: "-",
          body: {
            keyType: "auth",
            description: "grok-box-join",
            expirySeconds: 3600,
            capabilities: {
              devices: { create: { reusable: true, ephemeral: false, preauthorized: true, tags: ["tag:grok-ops"] } },
            },
          },
        },
      },
    };
    const decoded = await Schema.decodeUnknown(SecretSinkSignalInput)(valid);
    expect(decoded).toEqual(valid);
    expect(findForbiddenSecrets(valid)).toEqual([]);
    const reject = await Effect.runPromise(rejectIfSecretShaped(valid));
    expect(reject).toBeNull();
  });

  it("rejects non-dryRun (false) in FAKE-only phase", async () => {
    const invalid = {
      action: "tailscale.join",
      hostname: "box",
      tags: ["tag:grok-ops"],
      // @ts-expect-error - schema must reject false
      dryRun: false,
    };
    await expect(Schema.decodeUnknown(SecretSinkSignalInput)(invalid)).rejects.toBeTruthy();
  });

  it("rejects secret-shaped keys and values", async () => {
    const payload = {
      action: "tailscale.join",
      hostname: "box",
      tags: ["tag:grok-ops"],
      dryRun: true as const,
      // Top-level forbidden
      authKey: "tskey-abcdef123456",
      // Nested forbidden
      authKeyFrom: { onepassword: { item: "X", field: "credential" }, params: { bearerToken: "Bearer abc" } },
    } as unknown;
    const issues = findForbiddenSecrets(payload as any);
    expect(issues.some((s) => s.includes("authKey"))).toBe(true);
    expect(issues.some((s) => s.toLowerCase().includes("bearer"))).toBe(true);
    const reject = await Effect.runPromise(rejectIfSecretShaped(payload));
    expect(reject).not.toBeNull();
    if (reject && !reject.ok) {
      expect(reject.error.code).toBe("forbidden_secret_field");
      expect(reject.error.details).toBeTruthy();
    }
  });

  it("models enrollment as opaque credential reference only", async () => {
    const input = { deviceId: "dev-12345", fake: true as const };
    const decoded = await Schema.decodeUnknown(EnrollDeviceInput)(input);
    expect(decoded).toEqual(input);
    const out = await Schema.decodeUnknown(EnrollDeviceOutput)({
      ok: true,
      deviceId: input.deviceId,
      credentialId: `fake-credential:${input.deviceId}`,
    });
    expect(out.ok).toBe(true);
    expect(out.credentialId).toContain(input.deviceId);
  });

  it("documents runOnBox outputs without secrets", async () => {
    const out = await Schema.decodeUnknown(SecretSinkRunOutput)({
      joined: false,
      hostname: "box",
      dryRun: true as const,
      nodeOnline: false,
    });
    expect(out.joined).toBe(false);
    expect(out).not.toHaveProperty("authKey");
  });
});

