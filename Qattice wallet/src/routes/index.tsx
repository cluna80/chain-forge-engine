import { createFileRoute } from "@tanstack/react-router";
import { QatticeApp } from "@/components/qattice/app";

export const Route = createFileRoute("/")({ component: Home });

function Home() {
  return <QatticeApp />;
}
