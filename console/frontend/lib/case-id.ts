/** Canonical case ID pattern accepted by the backend (filesystem-safe slug). */
const CASE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** Display-only: dashes read as spaces; API payloads keep the slug form. */
export function displayCaseId(value: string): string {
  return value.replace(/-/g, " ");
}

/**
 * Normalize a human-entered case label into a backend-safe case ID.
 * Spaces become dashes; other invalid characters are stripped or collapsed.
 */
export function normalizeCaseId(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return "CASE-PENDING";

  let slug = trimmed.replace(/\s+/g, "-");
  slug = slug.replace(/[^A-Za-z0-9._-]+/g, "-");
  slug = slug.replace(/-+/g, "-").replace(/^[-_.]+|[-_.]+$/g, "");

  if (!slug) return "CASE-PENDING";
  if (!/^[A-Za-z0-9]/.test(slug)) slug = `CASE-${slug}`;
  if (slug.length > 128) slug = slug.slice(0, 128);
  return slug;
}

/** Suggest a new case ID (e.g. CASE-2026-A3F2). */
export function generateCaseId(): string {
  const year = new Date().getFullYear();
  const suffix = Math.random().toString(36).slice(2, 6).toUpperCase();
  return `CASE-${year}-${suffix}`;
}

export function validateCaseId(raw: string): { ok: true; normalized: string } | { ok: false; message: string } {
  const normalized = normalizeCaseId(raw);
  if (!CASE_ID_PATTERN.test(normalized)) {
    return {
      ok: false,
      message: "Case ID must start with a letter or number and use only letters, numbers, dashes, dots, or underscores.",
    };
  }
  return { ok: true, normalized };
}
