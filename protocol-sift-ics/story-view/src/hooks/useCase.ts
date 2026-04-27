import { useEffect, useState } from "react";
import type { CaseData } from "../types";
import { loadCase } from "../data/loader";

interface State {
  status: "loading" | "ready" | "error";
  data?: CaseData;
  error?: string;
}

let cached: CaseData | null = null;

export function useCase(): State {
  const [state, setState] = useState<State>(
    cached ? { status: "ready", data: cached } : { status: "loading" }
  );

  useEffect(() => {
    if (cached) return;
    let cancelled = false;
    loadCase()
      .then((data) => {
        cached = data;
        if (!cancelled) setState({ status: "ready", data });
      })
      .catch((err: Error) => {
        if (!cancelled) setState({ status: "error", error: err.message });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}
