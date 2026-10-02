import { Effect, Schema } from "effect";
import { ToolResult } from "./tool-result";

// Shared allowlist schemas for secret-sink signals and enrollment.
export const SecretSinkActionSchema = Schema.Literal("tailscale.join");

export const TagSchema = Schema.String.pipe(
  Schema.pattern(/^tag:[a-z0-9:_-]+$/i, {
    message:
      "Tag must start with 'tag:' and contain only letters, numbers, colon, dash or underscore",
  }),
);

// `authKeyFrom` is intentionally modeled as a structured OR, but without any secret value
// fields. It describes where the server should mint/resolve the key from — never carries
// a `tskey-` or bearer token itself.
const AuthKeyFromConnectionSchema = Schema.Struct({
  connection: Schema.String, // e.g. "tailscale_api.user.dynamikTailscale"
  op: Schema.Literal("keys.createKey"),
  params: Schema.Unknown, // server-side params shape; MUST NOT include key material
});

const AuthKeyFromOnePasswordSchema = Schema.Struct({
  onepassword: Schema.Struct({
    item: Schema.String,
    field: Schema.String, // e.g. "credential"
  }),
});

export const SecretSinkSignalInput = Schema.Struct({
  action: SecretSinkActionSchema,
  hostname: Schema.String.pipe(
    Schema.minLength(1, { message: "hostname must be a non-empty string" }),
  ),
  tags: Schema.Array(TagSchema),
  dryRun: Schema.Boolean,
  // Optional: model-visible source of truth for where the server SHOULD mint/resolve a key.
  // This is metadata only; the model never sees key material.
  authKeyFrom: Schema.optional(Schema.Union(AuthKeyFromConnectionSchema, AuthKeyFromOnePasswordSchema)),
});

export const SecretSinkRunOutput = Schema.Struct({
  joined: Schema.Boolean,
  hostname: Schema.String,
  dryRun: Schema.Boolean,
  nodeOnline: Schema.optional(Schema.Boolean),
});

export const EnrollDeviceInput = Schema.Struct({
  deviceId: Schema.String.pipe(
    Schema.pattern(/^[a-z0-9:_-]+$/i, {
      message: "deviceId must be URL-safe (letters, numbers, colon, dash, underscore)",
    }),
  ),
  // For this FAKE-only scaffold we accept an explicit fake mode.
  fake: Schema.optional(Schema.Boolean),
});

export const EnrollDeviceOutput = Schema.Struct({
  ok: Schema.Boolean,
  deviceId: Schema.String,
  credentialId: Schema.String, // opaque reference only; never key material
});

// ---------------------------------------------------------------------------
// Secret-shaped key/value guardrails
// ---------------------------------------------------------------------------

// Property-name patterns that imply a credential value.
const FORBIDDEN_KEY_PATTERNS = [
  /(^|_)authkey$/i,
  /(^|_)secret(key)?$/i,
  /(^|_)token$/i,
  /(^|_)bearer(token)?$/i,
  /(^|_)password$/i,
  /(^|_)credential$/i,
  /^tskey$/i,
] as const;

// Value-shaped patterns that must never appear in signals.
const FORBIDDEN_VALUE_PATTERNS = [
  /^tskey-[a-z0-9]+/i, // Tailscale
  /^bearer\\s+.+/i, // HTTP Bearer tokens
  /^op:\\/\\//i, // 1Password CLI/item URI
] as const;

type Json = null | boolean | number | string | Json[] | { readonly [k: string]: Json };

export const findForbiddenSecrets = (payload: Json): string[] => {
  const errors: string[] = [];
  const visit = (node: Json, path: string[]) => {
    if (node === null) return;
    const where = path.length === 0 ? "$" : `$.${path.join(".")}`;

    if (typeof node === "string") {
      for (const re of FORBIDDEN_VALUE_PATTERNS) {
        if (re.test(node)) errors.push(`${where}: forbidden secret-shaped value`);
      }
      return;
    }
    if (typeof node === "number" || typeof node === "boolean") return;
    if (Array.isArray(node)) {
      node.forEach((v, i) => visit(v, [...path, String(i)]));
      return;
    }
    // Object
    for (const [k, v] of Object.entries(node)) {
      for (const re of FORBIDDEN_KEY_PATTERNS) {
        if (re.test(k)) {
          errors.push(`${where}.${k}: forbidden secret-shaped field name`);
        }
      }
      visit(v, [...path, k]);
    }
  };
  visit(payload, []);
  return errors;
};

export const rejectIfSecretShaped = <A>(payload: A) =>
  Effect.gen(function* () {
    const issues = findForbiddenSecrets(payload as Json);
    if (issues.length > 0) {
      return yield* Effect.succeed(
        ToolResult.fail({
          code: "forbidden_secret_field",
          message:
            "Secret-shaped fields/values are forbidden in secret-sink signals; never include authKey, tskey-*, bearer tokens, or raw credentials in GitHub-visible signals.",
          details: { issues },
        }),
      );
    }
    return yield* Effect.succeed(null);
  });

