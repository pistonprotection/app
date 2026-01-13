import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useMemo,
} from "react";
import { authClient } from "@/lib/auth-client";

/**
 * Organization context for tracking the currently active organization.
 *
 * This replaces the incorrect usage of user.id as organizationId throughout
 * the dashboard pages. The organization hooks from better-auth provide:
 * - useActiveOrganization(): The currently selected organization
 * - useListOrganizations(): All organizations the user belongs to
 */

interface OrganizationContextValue {
  /**
   * The currently active organization ID.
   * Falls back to null if no organization is active (personal workspace).
   */
  organizationId: string | null;

  /**
   * The currently active organization object, or null if none selected.
   */
  activeOrganization: ReturnType<
    typeof authClient.useActiveOrganization
  >["data"];

  /**
   * All organizations the user has access to.
   */
  organizations: ReturnType<typeof authClient.useListOrganizations>["data"];

  /**
   * Loading state for organizations data.
   */
  isLoading: boolean;

  /**
   * Error state for organizations data.
   */
  error: Error | null;

  /**
   * Set the active organization.
   */
  setActiveOrganization: (organizationId: string) => Promise<void>;
}

const OrganizationContext = createContext<OrganizationContextValue | null>(
  null,
);

export function OrganizationProvider({ children }: { children: ReactNode }) {
  const activeOrgQuery = authClient.useActiveOrganization();
  const listOrgsQuery = authClient.useListOrganizations();

  const setActiveOrganization = useCallback(async (organizationId: string) => {
    await authClient.organization.setActive({ organizationId });
  }, []);

  const value = useMemo<OrganizationContextValue>(
    () => ({
      organizationId: activeOrgQuery.data?.id ?? null,
      activeOrganization: activeOrgQuery.data,
      organizations: listOrgsQuery.data,
      isLoading: activeOrgQuery.isPending || listOrgsQuery.isPending,
      error: activeOrgQuery.error ?? listOrgsQuery.error ?? null,
      setActiveOrganization,
    }),
    [
      activeOrgQuery.data,
      activeOrgQuery.isPending,
      activeOrgQuery.error,
      listOrgsQuery.data,
      listOrgsQuery.isPending,
      listOrgsQuery.error,
      setActiveOrganization,
    ],
  );

  return (
    <OrganizationContext.Provider value={value}>
      {children}
    </OrganizationContext.Provider>
  );
}

/**
 * Hook to access organization context.
 *
 * @returns Organization context with active organization ID and helpers.
 * @throws Error if used outside OrganizationProvider.
 *
 * @example
 * ```tsx
 * function MyComponent() {
 *   const { organizationId, isLoading } = useOrganization();
 *
 *   if (isLoading) return <Spinner />;
 *   if (!organizationId) return <SelectOrganization />;
 *
 *   // Use organizationId for API calls
 *   const { data } = useQuery(api.getData({ organizationId }));
 * }
 * ```
 */
export function useOrganization(): OrganizationContextValue {
  const context = useContext(OrganizationContext);
  if (!context) {
    throw new Error(
      "useOrganization must be used within an OrganizationProvider",
    );
  }
  return context;
}

/**
 * Hook to get just the organization ID with a fallback for API calls.
 * Returns an empty string if no organization is selected, which is safe
 * for most API calls (they will return empty results).
 *
 * @returns The active organization ID or empty string.
 */
export function useOrganizationId(): string {
  const { organizationId } = useOrganization();
  return organizationId ?? "";
}
