/**
 * Placeholder params for `next export` (VENTRA_STATIC_EXPORT=1).
 * FastAPI rewrites real IDs to these shells; client hooks read the browser URL.
 */
export const CASE_STATIC_PARAMS = [{ caseId: "_" }];
export const RUN_STATIC_PARAMS = [{ runId: "_" }];
export const DOCS_PROVIDER_PARAMS = [
  { provider: "aws" },
  { provider: "azure" },
  { provider: "gcp" },
];
/** Nested under [provider] — only the child segment key. */
export const DOCS_SECTION_PARAMS = [{ section: "overview" }, { section: "collectors" }];
export const DOCS_COLLECTOR_PARAMS = [{ collector: "_" }];
