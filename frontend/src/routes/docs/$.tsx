import { createFileRoute, Link, notFound } from "@tanstack/react-router";
import { createServerFn } from "@tanstack/react-start";
import { DocsLayout } from "@/components/docs/docs-layout";
import { getMDXComponents } from "@/components/docs/mdx-components";
import { getAllPages, getPageBySlug, getPageTree, source } from "@/lib/source";

// Type definitions for page tree nodes
interface PageTreeNode {
  type: "page" | "folder" | "separator";
  name: string;
  url?: string;
  children?: PageTreeNode[];
}

interface PageTreeRoot {
  children: PageTreeNode[];
}

interface PageData {
  url: string;
  title: string;
  description?: string;
}

interface DocsPageData {
  path: string;
  url: string;
  title: string;
  description: string | null;
  toc: Array<{ title: string; url: string; depth: number }>;
  tree: PageTreeRoot;
  prevPage: { url: string; title: string } | null;
  nextPage: { url: string; title: string } | null;
  allPages: PageData[];
}

// Serialize the page tree (remove non-serializable data)
function serializeTree(tree: unknown): PageTreeRoot {
  if (!tree || typeof tree !== "object") {
    return { children: [] };
  }

  const treeObj = tree as { children?: unknown[] };

  const serializeNode = (node: unknown): PageTreeNode | null => {
    if (!node || typeof node !== "object") return null;
    const n = node as Record<string, unknown>;

    if (n.type === "separator") {
      return {
        type: "separator",
        name: String(n.name || ""),
      };
    }

    if (n.type === "folder") {
      return {
        type: "folder",
        name: String(n.name || ""),
        url: n.url ? String(n.url) : undefined,
        children: Array.isArray(n.children)
          ? n.children
              .map(serializeNode)
              .filter((c): c is PageTreeNode => c !== null)
          : [],
      };
    }

    return {
      type: "page",
      name: String(n.name || ""),
      url: n.url ? String(n.url) : undefined,
    };
  };

  return {
    children: Array.isArray(treeObj.children)
      ? treeObj.children
          .map(serializeNode)
          .filter((c): c is PageTreeNode => c !== null)
      : [],
  };
}

const getDocsPage = createServerFn({ method: "GET" }).handler(
  async (ctx): Promise<DocsPageData> => {
    const slugs = (ctx.data as string[] | undefined) ?? [];
    const page = getPageBySlug(slugs.length > 0 ? slugs : undefined);

    if (!page) {
      throw notFound();
    }

    // Get the page tree for navigation
    const tree = getPageTree();
    const serializedTree = serializeTree(tree);

    // Get all pages for prev/next navigation and search
    const pages = getAllPages();
    const currentIndex = pages.findIndex((p) => p.url === page.url);
    const prevPage = currentIndex > 0 ? pages[currentIndex - 1] : null;
    const nextPage =
      currentIndex < pages.length - 1 ? pages[currentIndex + 1] : null;

    // Create a list of all pages for search
    const allPagesData = pages.map((p) => ({
      url: p.url,
      title: p.data.title,
      description: p.data.description || undefined,
    }));

    return {
      path: page.url,
      url: page.url,
      title: page.data.title,
      description: page.data.description || null,
      toc: (page.data.toc || []) as Array<{
        title: string;
        url: string;
        depth: number;
      }>,
      tree: serializedTree,
      prevPage: prevPage
        ? { url: prevPage.url, title: prevPage.data.title }
        : null,
      nextPage: nextPage
        ? { url: nextPage.url, title: nextPage.data.title }
        : null,
      allPages: allPagesData,
    };
  },
);

export const Route = createFileRoute("/docs/$")({
  component: DocsPageComponent,
  loader: async ({ params }) => {
    const slugs = params._splat?.split("/").filter(Boolean) ?? [];
    const data = await getDocsPage({ data: slugs as unknown as undefined });
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

function DocsPageComponent() {
  const data = Route.useLoaderData();
  const params = Route.useParams();
  const slugs = params._splat?.split("/").filter(Boolean) ?? [];

  // Get the page to render MDX content on client
  const page = source.getPage(slugs.length > 0 ? slugs : undefined);

  if (!data || !page) {
    return (
      <DocsLayout
        tree={{ children: [] }}
        currentPath="/docs"
        title="Page Not Found"
        description="The page you are looking for does not exist."
        allPages={[]}
      >
        <p>This documentation page could not be found.</p>
        <p className="mt-4">
          <Link
            to="/docs/$"
            params={{ _splat: "" }}
            className="text-primary underline"
          >
            Go to documentation home
          </Link>
        </p>
      </DocsLayout>
    );
  }

  const MDXContent = page.data.body;

  return (
    <DocsLayout
      tree={data.tree}
      currentPath={data.url}
      title={data.title}
      description={data.description || undefined}
      toc={data.toc}
      prevPage={data.prevPage}
      nextPage={data.nextPage}
      allPages={data.allPages}
    >
      <MDXContent components={getMDXComponents()} />
    </DocsLayout>
  );
}
