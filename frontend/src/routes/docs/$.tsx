// @ts-nocheck
// TODO: Server function types and data access need fixing
import { createFileRoute, Link, notFound } from "@tanstack/react-router";
import { createServerFn } from "@tanstack/react-start";
import { ArrowLeft, ArrowRight, Book, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { source } from "@/lib/source";

export const Route = createFileRoute("/docs/$")({
  component: DocsPageComponent,
  loader: async ({ params }) => {
    const data = await loader({ data: params._splat?.split("/") ?? [] });
    return data;
  },
  head: ({ loaderData }) => ({
    meta: [
      {
        title: `${loaderData?.title ?? "Documentation"} - PistonProtection`,
      },
      {
        name: "description",
        content: loaderData?.description ?? "PistonProtection documentation",
      },
    ],
  }),
});

const loader = createServerFn({
  method: "GET",
})
  .inputValidator((slugs: string[]) => slugs)
  .handler(async ({ data: slugs }) => {
    const page = source.getPage(slugs);
    if (!page) throw notFound();

    // Get the page tree for navigation
    const tree = source.getPageTree();

    // Get all pages for prev/next navigation
    const pages = source.getPages();
    const currentIndex = pages.findIndex((p) => p.path === page.path);
    const prevPage = currentIndex > 0 ? pages[currentIndex - 1] : null;
    const nextPage =
      currentIndex < pages.length - 1 ? pages[currentIndex + 1] : null;

    return {
      path: page.path,
      url: page.url,
      title: page.data.title,
      description: page.data.description,
      content: page.data.body,
      toc: page.data.toc,
      tree: tree as object,
      prevPage: prevPage
        ? { url: prevPage.url, title: prevPage.data.title }
        : null,
      nextPage: nextPage
        ? { url: nextPage.url, title: nextPage.data.title }
        : null,
    };
  });

function DocsPageComponent() {
  const data = Route.useLoaderData();
  const MDXContent = data.content;

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto flex h-14 items-center px-4">
          <Link to="/" className="flex items-center gap-2 font-semibold">
            <Book className="h-5 w-5 text-primary" />
            <span>PistonProtection Docs</span>
          </Link>
          <div className="ml-auto flex items-center gap-4">
            <Link to="/">
              <Button variant="ghost" size="sm">
                Home
              </Button>
            </Link>
            <a
              href="https://github.com/pistonprotection/app"
              target="_blank"
              rel="noopener noreferrer"
            >
              <Button variant="ghost" size="sm">
                GitHub
                <ExternalLink className="ml-1 h-3 w-3" />
              </Button>
            </a>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-4">
        <div className="flex gap-8 py-8">
          {/* Sidebar */}
          <aside className="hidden w-64 shrink-0 lg:block">
            <nav className="sticky top-20">
              <DocsSidebar tree={data.tree} currentPath={data.url} />
            </nav>
          </aside>

          {/* Main content */}
          <main className="min-w-0 flex-1">
            <article className="prose prose-neutral dark:prose-invert max-w-none">
              <h1>{data.title}</h1>
              {data.description && (
                <p className="lead text-muted-foreground">{data.description}</p>
              )}
              <Separator className="my-6" />
              <MDXContent components={mdxComponents} />
            </article>

            {/* Prev/Next navigation */}
            <div className="mt-12 flex items-center justify-between border-t pt-6">
              {data.prevPage ? (
                <Link to={data.prevPage.url}>
                  <Button variant="ghost" className="gap-2">
                    <ArrowLeft className="h-4 w-4" />
                    {data.prevPage.title}
                  </Button>
                </Link>
              ) : (
                <div />
              )}
              {data.nextPage ? (
                <Link to={data.nextPage.url}>
                  <Button variant="ghost" className="gap-2">
                    {data.nextPage.title}
                    <ArrowRight className="h-4 w-4" />
                  </Button>
                </Link>
              ) : (
                <div />
              )}
            </div>
          </main>

          {/* Table of contents */}
          {data.toc && data.toc.length > 0 && (
            <aside className="hidden w-56 shrink-0 xl:block">
              <div className="sticky top-20">
                <h4 className="mb-4 text-sm font-semibold">On this page</h4>
                <TableOfContents toc={data.toc} />
              </div>
            </aside>
          )}
        </div>
      </div>
    </div>
  );
}

// Custom MDX components
const mdxComponents = {
  h1: (props: React.HTMLAttributes<HTMLHeadingElement>) => (
    <h1 className="scroll-m-20 text-4xl font-bold tracking-tight" {...props} />
  ),
  h2: (props: React.HTMLAttributes<HTMLHeadingElement>) => (
    <h2
      className="scroll-m-20 border-b pb-2 text-3xl font-semibold tracking-tight mt-10 first:mt-0"
      {...props}
    />
  ),
  h3: (props: React.HTMLAttributes<HTMLHeadingElement>) => (
    <h3
      className="scroll-m-20 text-2xl font-semibold tracking-tight mt-8"
      {...props}
    />
  ),
  h4: (props: React.HTMLAttributes<HTMLHeadingElement>) => (
    <h4
      className="scroll-m-20 text-xl font-semibold tracking-tight mt-6"
      {...props}
    />
  ),
  p: (props: React.HTMLAttributes<HTMLParagraphElement>) => (
    <p className="leading-7 [&:not(:first-child)]:mt-6" {...props} />
  ),
  a: (props: React.AnchorHTMLAttributes<HTMLAnchorElement>) => (
    <a
      className="font-medium text-primary underline underline-offset-4"
      {...props}
    />
  ),
  ul: (props: React.HTMLAttributes<HTMLUListElement>) => (
    <ul className="my-6 ml-6 list-disc [&>li]:mt-2" {...props} />
  ),
  ol: (props: React.HTMLAttributes<HTMLOListElement>) => (
    <ol className="my-6 ml-6 list-decimal [&>li]:mt-2" {...props} />
  ),
  li: (props: React.HTMLAttributes<HTMLLIElement>) => <li {...props} />,
  blockquote: (props: React.HTMLAttributes<HTMLQuoteElement>) => (
    <blockquote className="mt-6 border-l-2 pl-6 italic" {...props} />
  ),
  code: (props: React.HTMLAttributes<HTMLElement>) => (
    <code
      className="relative rounded bg-muted px-[0.3rem] py-[0.2rem] font-mono text-sm"
      {...props}
    />
  ),
  pre: (props: React.HTMLAttributes<HTMLPreElement>) => (
    <pre
      className="mb-4 mt-6 overflow-x-auto rounded-lg bg-muted p-4"
      {...props}
    />
  ),
  table: (props: React.HTMLAttributes<HTMLTableElement>) => (
    <div className="my-6 w-full overflow-y-auto">
      <table className="w-full" {...props} />
    </div>
  ),
  tr: (props: React.HTMLAttributes<HTMLTableRowElement>) => (
    <tr className="m-0 border-t p-0 even:bg-muted" {...props} />
  ),
  th: (props: React.HTMLAttributes<HTMLTableCellElement>) => (
    <th
      className="border px-4 py-2 text-left font-bold [&[align=center]]:text-center [&[align=right]]:text-right"
      {...props}
    />
  ),
  td: (props: React.HTMLAttributes<HTMLTableCellElement>) => (
    <td
      className="border px-4 py-2 text-left [&[align=center]]:text-center [&[align=right]]:text-right"
      {...props}
    />
  ),
  Cards: ({ children }: { children: React.ReactNode }) => (
    <div className="grid gap-4 md:grid-cols-2 not-prose my-6">{children}</div>
  ),
  Card: ({
    title,
    description,
    href,
  }: {
    title: string;
    description?: string;
    href: string;
  }) => (
    <Link to={href}>
      <Card className="h-full hover:border-primary/50 transition-colors">
        <CardHeader>
          <CardTitle className="text-lg">{title}</CardTitle>
          {description && <CardDescription>{description}</CardDescription>}
        </CardHeader>
      </Card>
    </Link>
  ),
};

function DocsSidebar({
  tree,
  currentPath,
}: {
  tree: object;
  currentPath: string;
}) {
  const renderTree = (items: any[], level = 0) => {
    return items.map((item, index) => {
      if (item.type === "separator") {
        return (
          <div key={index} className="mt-6 first:mt-0">
            <h4 className="mb-2 text-sm font-semibold">{item.name}</h4>
          </div>
        );
      }

      if (item.type === "folder") {
        return (
          <div key={index} className="mb-2">
            <div className="mb-1 text-sm font-medium text-muted-foreground">
              {item.name}
            </div>
            <div className="ml-2 border-l pl-2">
              {item.children && renderTree(item.children, level + 1)}
            </div>
          </div>
        );
      }

      const isActive = item.url === currentPath;
      return (
        <Link
          key={index}
          to={item.url}
          className={`block py-1 text-sm transition-colors ${
            isActive
              ? "font-medium text-primary"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          {item.name}
        </Link>
      );
    });
  };

  return <div>{renderTree((tree as any).children || [])}</div>;
}

function TableOfContents({ toc }: { toc: any[] }) {
  return (
    <nav className="space-y-1 text-sm">
      {toc.map((item, index) => (
        <a
          key={index}
          href={`#${item.url}`}
          className={`block text-muted-foreground hover:text-foreground transition-colors ${
            item.depth === 3 ? "pl-4" : ""
          }`}
        >
          {item.title}
        </a>
      ))}
    </nav>
  );
}
