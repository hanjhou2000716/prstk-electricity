import { createClient } from "npm:@supabase/supabase-js@2.102.0";

const projectUrl = Deno.env.get("SUPABASE_URL") ?? "";
const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const publishableKey = Deno.env.get("SUPABASE_PUBLISHABLE_KEY") ?? Deno.env.get("SUPABASE_ANON_KEY") ?? "";
const expectedPin = Deno.env.get("MANAGER_PIN") ?? "";
const allowedOrigin = Deno.env.get("ALLOWED_ORIGIN") ?? "https://hanjhou2000716.github.io";
const projectRef = new URL(projectUrl || "https://invalid.supabase.co").hostname.split(".")[0];
const managerEmail = `prstk-manager@${projectRef}.invalid`;

const admin = createClient(projectUrl, serviceKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});
const auth = createClient(projectUrl, publishableKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});

function json(body: unknown, status: number) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": allowedOrigin,
      "Access-Control-Allow-Headers": "authorization, apikey, content-type",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Vary": "Origin",
    },
  });
}

function sameSecret(a: string, b: string) {
  let mismatch = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) mismatch |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return mismatch === 0;
}

function freshPassword() {
  const bytes = crypto.getRandomValues(new Uint8Array(48));
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function ensureManagerUser(password: string) {
  const { data: listed, error: listError } = await admin.auth.admin.listUsers({ page: 1, perPage: 1000 });
  if (listError) throw listError;
  let user = listed.users.find((item) => item.email?.toLowerCase() === managerEmail.toLowerCase());
  if (!user) {
    const { data, error } = await admin.auth.admin.createUser({
      email: managerEmail,
      password,
      email_confirm: true,
    });
    if (error || !data.user) throw error ?? new Error("manager user creation failed");
    user = data.user;
  } else {
    const { data, error } = await admin.auth.admin.updateUserById(user.id, {
      password,
      email_confirm: true,
    });
    if (error || !data.user) throw error ?? new Error("manager credential update failed");
    user = data.user;
  }
  const { error: allowlistError } = await admin.rpc("prstk_bootstrap_manager", { p_user_id: user.id });
  if (allowlistError) throw allowlistError;
  return user;
}

Deno.serve(async (request) => {
  const origin = request.headers.get("Origin") ?? "";
  if (origin !== allowedOrigin) return new Response("Forbidden", { status: 403 });
  if (request.method === "OPTIONS") return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": allowedOrigin,
      "Access-Control-Allow-Headers": "authorization, apikey, content-type",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Vary": "Origin",
    },
  });
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  if (!/^\d{4}$/.test(expectedPin) || !projectUrl || !serviceKey || !publishableKey) {
    return json({ error: "login_not_configured" }, 503);
  }

  let pin = "";
  try {
    const body = await request.json();
    pin = typeof body?.pin === "string" ? body.pin : "";
  } catch {
    return json({ error: "invalid_request" }, 400);
  }
  if (!/^\d{4}$/.test(pin)) return json({ error: "invalid_pin_format" }, 400);

  const { data: allowed, error: limitError } = await admin.rpc("prstk_reserve_pin_attempt");
  if (limitError) return json({ error: "login_temporarily_unavailable" }, 503);
  if (allowed !== true) return json({ error: "too_many_attempts", retryAfterSeconds: 1800 }, 429);

  if (!sameSecret(pin, expectedPin)) {
    await admin.rpc("prstk_record_pin_login", { p_success: false });
    return json({ error: "invalid_credentials" }, 401);
  }
  await admin.rpc("prstk_record_pin_login", { p_success: true });

  try {
    const password = freshPassword();
    const user = await ensureManagerUser(password);
    const { data, error } = await auth.auth.signInWithPassword({ email: managerEmail, password });
    if (error || !data.session) throw error ?? new Error("manager session could not be created");
    return json({
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_at: data.session.expires_at,
      expires_in: data.session.expires_in,
      token_type: data.session.token_type,
    }, 200);
  } catch (error) {
    console.error("PRStK manager session provisioning failed", error);
    return json({ error: "login_temporarily_unavailable" }, 503);
  }
});

