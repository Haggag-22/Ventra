"use client";

import { Button } from "@/components/ui";
import { Plus } from "lucide-react";

type ProvidersPageHeaderProps = {
  onAdd: () => void;
};

export function ProvidersPageHeader({ onAdd }: ProvidersPageHeaderProps) {
  return (
    <div className="mb-8 flex items-start justify-between gap-4">
      <div>
        <h1 className="page-title">Providers</h1>
        <p className="page-subtitle">
          Manage cloud accounts used for server-side collection. Credentials stay on the Ventra
          server — no secrets are stored in the browser.
        </p>
      </div>
      <Button
        variant="primary-dark"
        icon={Plus}
        className="shrink-0 bg-accent text-accent-fg hover:bg-accent/90"
        onClick={onAdd}
      >
        Add Provider
      </Button>
    </div>
  );
}
