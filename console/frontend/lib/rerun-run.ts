import { startRun, type AcquisitionBuild } from "./api";
import type { RunMeta } from "./types";

export type RunMetaWithRequest = RunMeta & {
  request?: AcquisitionBuild & Record<string, unknown>;
};

export function buildRerunBody(
  meta: RunMetaWithRequest,
): AcquisitionBuild & { auto_ingest?: boolean; connection_id?: string } {
  const req = meta.request as AcquisitionBuild | undefined;
  if (!req?.cloud || !req?.case_id) {
    throw new Error("This run has no saved configuration to re-run.");
  }
  return {
    ...req,
    auto_ingest: meta.auto_ingest ?? true,
    connection_id: meta.connection_id ?? req.connection_id ?? undefined,
  };
}

export async function rerunScan(meta: RunMetaWithRequest): Promise<{ run_id: string }> {
  return startRun(buildRerunBody(meta));
}
