// Type declarations for packages without TypeScript definitions

declare module "@fontsource-variable/inter" {
  // This module has no exports, it's imported for side effects (CSS injection)
}

declare module "@tanstack/react-start/api" {
  export function createAPIFileRoute<TPath extends string>(
    path: TPath
  ): <TRoutes extends Record<string, (ctx: { request: Request }) => Promise<Response>>>(
    routes: TRoutes
  ) => { APIRoute: TRoutes };
}
