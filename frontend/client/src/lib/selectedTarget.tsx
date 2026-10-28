import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import type { ScanLevel } from "@/lib/liveEngine";

export type SelectedTarget = {
  target: string;
  scopeId: string;
  profiles: string[];
  nmapLevel: ScanLevel;
  subfinderLevel: ScanLevel;
  selectedAt: string;
};

type SelectedTargetContextValue = {
  selection: SelectedTarget | null;
  revision: number;
  select: (selection: SelectedTarget) => void;
  clear: () => void;
  refresh: () => void;
};

const STORAGE_KEY = "zerotrace.selectedTarget.v1";

function loadSelection(): SelectedTarget | null {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<SelectedTarget>;
    if (
      typeof parsed.target !== "string"
      || typeof parsed.scopeId !== "string"
      || !Array.isArray(parsed.profiles)
    ) {
      return null;
    }
    return {
      target: parsed.target,
      scopeId: parsed.scopeId,
      profiles: parsed.profiles.filter((item): item is string => typeof item === "string"),
      nmapLevel: parsed.nmapLevel === "medium" || parsed.nmapLevel === "high" || parsed.nmapLevel === "deep"
        ? parsed.nmapLevel
        : "normal",
      subfinderLevel: parsed.subfinderLevel === "medium" || parsed.subfinderLevel === "high" || parsed.subfinderLevel === "deep"
        ? parsed.subfinderLevel
        : "normal",
      selectedAt: typeof parsed.selectedAt === "string" ? parsed.selectedAt : new Date().toISOString(),
    };
  } catch {
    return null;
  }
}

const SelectedTargetContext = createContext<SelectedTargetContextValue | null>(null);

export function SelectedTargetProvider({ children }: { children: ReactNode }) {
  const [selection, setSelection] = useState<SelectedTarget | null>(() => loadSelection());
  const [revision, setRevision] = useState(0);

  const select = useCallback((next: SelectedTarget) => {
    setSelection(next);
    setRevision((value) => value + 1);
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      // Local storage can be unavailable in hardened browser profiles.
    }
  }, []);

  const clear = useCallback(() => {
    setSelection(null);
    setRevision((value) => value + 1);
    try {
      window.localStorage.removeItem(STORAGE_KEY);
    } catch {
      // Ignore storage failures; the in-memory selection is still cleared.
    }
  }, []);

  const refresh = useCallback(() => setRevision((value) => value + 1), []);

  const value = useMemo(
    () => ({ selection, revision, select, clear, refresh }),
    [selection, revision, select, clear, refresh],
  );

  return (
    <SelectedTargetContext.Provider value={value}>
      {children}
    </SelectedTargetContext.Provider>
  );
}

export function useSelectedTarget(): SelectedTargetContextValue {
  const context = useContext(SelectedTargetContext);
  if (!context) {
    throw new Error("useSelectedTarget must be used inside SelectedTargetProvider");
  }
  return context;
}
