"use client";

import { isPlatformVisibleInUi } from "@/lib/catalog";
import { deleteConnection, listConnections, testConnection } from "@/lib/api";
import { ProviderWizard } from "@/components/providers/provider-wizard";
import { ProvidersPageHeader } from "@/components/providers/providers-page-header";
import { ProvidersTable } from "@/components/providers/providers-table";
import {
  isProviderConnected,
  isProviderFailed,
  isProviderUntested,
} from "@/components/providers/types";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import type { Connection } from "@/lib/api";

export default function ProvidersPage() {
  const qc = useQueryClient();
  const providers = useQuery({ queryKey: ["config", "connections"], queryFn: listConnections });
  const [wizardOpen, setWizardOpen] = useState(false);
  const [editing, setEditing] = useState<Connection | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);

  const connections = useMemo(
    () => (providers.data?.connections ?? []).filter((c) => isPlatformVisibleInUi(c.platform)),
    [providers.data],
  );

  const metrics = useMemo(() => {
    const list = connections;
    const connected = list.filter(isProviderConnected).length;
    const untested = list.filter(isProviderUntested).length;
    const failed = list.filter(isProviderFailed).length;
    return { total: list.length, connected, untested, failed };
  }, [connections]);

  const delMut = useMutation({
    mutationFn: deleteConnection,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["config", "connections"] }),
  });

  const testMut = useMutation({
    mutationFn: async (id: string) => {
      setTestingId(id);
      return testConnection(id);
    },
    onSettled: () => {
      setTestingId(null);
      qc.invalidateQueries({ queryKey: ["config", "connections"] });
    },
  });

  function openAdd() {
    setEditing(null);
    setWizardOpen(true);
  }

  function openEdit(conn: Connection) {
    setEditing(conn);
    setWizardOpen(true);
  }

  function closeWizard() {
    setWizardOpen(false);
    setEditing(null);
  }

  function handleDelete(conn: Connection) {
    if (confirm(`Delete provider "${conn.name}"?`)) {
      delMut.mutate(conn.id);
    }
  }

  return (
    <div className="page-shell">
      <ProvidersPageHeader
        onAdd={openAdd}
        total={metrics.total}
        connected={metrics.connected}
        untested={metrics.untested}
        failed={metrics.failed}
      />

      <ProvidersTable
        connections={connections}
        loading={providers.isLoading}
        testingId={testingId}
        onAdd={openAdd}
        onEdit={openEdit}
        onTest={(id) => testMut.mutate(id)}
        onDelete={handleDelete}
      />

      <ProviderWizard open={wizardOpen} onClose={closeWizard} editing={editing} />
    </div>
  );
}
