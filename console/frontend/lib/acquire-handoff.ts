/** Tracks kits sent to clients so analysts see "awaiting upload" in Investigate. */

import type { DeploymentProfile } from "./deployment-profiles";
import type { HandoffMode } from "./handoff-modes";

const STORAGE_KEY = "ventra:kit-handoffs";

export type KitHandoffRecord = {
  caseId: string;
  cloud: string;
  collectors: string[];
  deploymentProfile: DeploymentProfile;
  builtAt: string;
  ventraVersion?: string;
  includeIam: boolean;
  handoffMode?: HandoffMode;
  transport?: string;
};

type HandoffStore = Record<string, KitHandoffRecord>;

function readStore(): HandoffStore {
  if (typeof window === "undefined") return {};
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as HandoffStore) : {};
  } catch {
    return {};
  }
}

function writeStore(store: HandoffStore): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
}

export function saveKitHandoff(record: KitHandoffRecord): void {
  const store = readStore();
  store[record.caseId.toUpperCase()] = { ...record, caseId: record.caseId.toUpperCase() };
  writeStore(store);
}

export function getKitHandoff(caseId: string): KitHandoffRecord | null {
  return readStore()[caseId.trim().toUpperCase()] ?? null;
}

export function clearKitHandoff(caseId: string): void {
  const key = caseId.trim().toUpperCase();
  const store = readStore();
  if (!store[key]) return;
  delete store[key];
  writeStore(store);
}

export function listPendingHandoffs(): KitHandoffRecord[] {
  return Object.values(readStore()).sort((a, b) => b.builtAt.localeCompare(a.builtAt));
}
