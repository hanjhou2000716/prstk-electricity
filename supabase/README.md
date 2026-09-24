# PRStK Supabase setup

The public site stays on GitHub Pages. This migration and Edge Function use PRStK-prefixed objects inside the existing `prstk-lab` project so they do not change other app data. Never place real bills, backups, the manager PIN, or a Supabase service key in this repository.

## One-time service setup

1. Apply every SQL migration in `migrations/` in filename order to the Supabase project `prstk-lab`.
2. Deploy the `functions/manager-login` Edge Function with JWT verification disabled. The function checks the four-digit PIN itself before issuing a short-lived Supabase session; it creates and manages a private Supabase Auth user server-side.
3. In Supabase Edge Function secrets, set `MANAGER_PIN` to the four-digit manager PIN. Enter it only in the Supabase dashboard, never in this repository or chat. `ALLOWED_ORIGIN` defaults to `https://hanjhou2000716.github.io`; change it only if the site origin changes.
4. The public Supabase URL and publishable key are in `index.html`. Publishable keys are designed to appear in browser code; the service-role key is never used there. Anonymous database access is limited to reading the sanitized settlement projection.

Five incorrect PIN entries inside the 30-minute window pause login for 30 minutes. The authenticated manager session stays in page memory only and the workspace automatically locks after ten idle minutes.

## Data behavior

The private manager row holds the complete workspace and working draft. The public snapshot contains only final settlement dates, fixed room numbers, per-room usage, and payable amounts. It omits meter readings, fee breakdowns, notes, paid marks, drafts, and backup data. Both rows update in one transaction and carry a revision check so a second device cannot overwrite newer work.

On the first manager login, the app previews records already stored in that browser. The manager must confirm the one-time move to Supabase. Demo records are not migrated. The old browser copy is removed only after Supabase confirms the write; if migration is cancelled or fails, it remains available.
