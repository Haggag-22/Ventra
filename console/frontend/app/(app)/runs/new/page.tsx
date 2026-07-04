"use client";

import { Button, Card, EmptyState } from "@/components/ui";
import { readLastConnection } from "@/lib/provider-storage";
import { ACQUIRE_HREF } from "@/lib/routes";
import { Boxes, Play } from "lucide-react";
import Link from "next/link";
import { useMemo } from "react";

export default function NewRunPage() {
  const acquireRunHref = useMemo(() => {
    const connectionId = readLastConnection();
    return connectionId
      ? `${ACQUIRE_HREF}?mode=run&connection=${encodeURIComponent(connectionId)}`
      : `${ACQUIRE_HREF}?mode=run`;
  }, []);

  return (
    <div className="px-6 py-8">
      <div className="mb-6">
        <h1 className="text-lg font-semibold">New collection run</h1>
        <p className="mt-1 text-sm text-fg-subtle">
          Configure artifacts and a cloud provider on Acquire, then execute collection on the Ventra
          server.
        </p>
      </div>

      <Card className="max-w-xl p-6">
        <EmptyState
          icon={Play}
          title="Run from Acquire"
          description={
            <>
              Pick collectors and an optional provider on Acquire, then use{" "}
              <strong className="font-medium text-fg">Run collection</strong> to start a live run.
            </>
          }
          action={
            <div className="flex flex-wrap justify-center gap-2">
              <Link href={acquireRunHref}>
                <Button variant="primary-dark" icon={Play} className="bg-accent text-accent-fg hover:bg-accent/90">
                  Open Acquire (run mode)
                </Button>
              </Link>
              <Link href={ACQUIRE_HREF}>
                <Button variant="secondary" icon={Boxes}>
                  Download kit instead
                </Button>
              </Link>
            </div>
          }
        />
      </Card>
    </div>
  );
}
