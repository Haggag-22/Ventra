export const LAST_CONNECTION_KEY = "ventra.last-connection";

export function readLastConnection(): string {
  if (typeof window === "undefined") return "";
  try {
    return localStorage.getItem(LAST_CONNECTION_KEY) || "";
  } catch {
    return "";
  }
}

export function writeLastConnection(connectionId: string): void {
  if (typeof window === "undefined") return;
  try {
    if (connectionId) localStorage.setItem(LAST_CONNECTION_KEY, connectionId);
    else localStorage.removeItem(LAST_CONNECTION_KEY);
  } catch {
    /* ignore */
  }
}
