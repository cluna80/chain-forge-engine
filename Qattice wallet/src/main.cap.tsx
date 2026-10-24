import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QatticeApp } from "@/components/qattice/app";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("No #root element");
createRoot(root).render(
  <StrictMode>
    <QatticeApp />
  </StrictMode>,
);
