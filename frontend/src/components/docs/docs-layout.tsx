import { Link } from "@tanstack/react-router";
import {
  Book,
  ChevronRight,
  ExternalLink,
  Menu,
  Search,
  X,
} from "lucide-react";
import { useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";

interface TreeNode {
  type: "page" | "folder" | "separator";
  name: string;
  url?: string;
  children?: TreeNode[];
}

interface DocsLayoutProps {
  children: React.ReactNode;
  tree: { children: TreeNode[] };
  currentPath: string;
  title: string;
  description?: string;
  toc?: Array<{ title: string; url: string; depth: number }>;
  prevPage?: { url: string; title: string } | null;
  nextPage?: { url: string; title: string } | null;
  allPages?: Array<{ url: string; title: string; description?: string }>;
}

export function DocsLayout({
  children,
  tree,
  currentPath,
  title,
  description,
  toc,
  prevPage,
  nextPage,
  allPages = [],
}: DocsLayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  const filteredPages = useMemo(() => {
    if (!searchQuery.trim()) return [];
    const query = searchQuery.toLowerCase();
    return allPages.filter(
      (page) =>
        page.title.toLowerCase().includes(query) ||
        page.description?.toLowerCase().includes(query),
    );
  }, [searchQuery, allPages]);

  const handleSearchSelect = () => {
    setSearchOpen(false);
    setSearchQuery("");
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto flex h-14 items-center px-4">
          {/* Mobile menu button */}
          <Button
            variant="ghost"
            size="icon"
            className="lg:hidden mr-2"
            onClick={() => setSidebarOpen(true)}
          >
            <Menu className="h-5 w-5" />
          </Button>

          <Link to="/" className="flex items-center gap-2 font-semibold">
            <Book className="h-5 w-5 text-primary" />
            <span>PistonProtection</span>
          </Link>

          <div className="ml-4 text-sm text-muted-foreground hidden sm:block">
            Documentation
          </div>

          <div className="ml-auto flex items-center gap-2">
            {/* Search button */}
            <Button
              variant="outline"
              size="sm"
              className="hidden md:flex gap-2 text-muted-foreground"
              onClick={() => setSearchOpen(true)}
            >
              <Search className="h-4 w-4" />
              <span>Search docs...</span>
              <kbd className="pointer-events-none hidden h-5 select-none items-center gap-1 rounded border bg-muted px-1.5 font-mono text-xs font-medium text-muted-foreground sm:flex">
                <span className="text-xs">Ctrl</span>K
              </kbd>
            </Button>

            <Button
              variant="ghost"
              size="icon"
              className="md:hidden"
              onClick={() => setSearchOpen(true)}
            >
              <Search className="h-5 w-5" />
            </Button>

            <Link to="/dashboard">
              <Button variant="ghost" size="sm">
                Dashboard
              </Button>
            </Link>

            <a
              href="https://github.com/pistonprotection/app"
              target="_blank"
              rel="noopener noreferrer"
            >
              <Button variant="ghost" size="sm" className="hidden sm:flex">
                GitHub
                <ExternalLink className="ml-1 h-3 w-3" />
              </Button>
            </a>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-4">
        <div className="flex gap-8 py-8">
          {/* Desktop Sidebar */}
          <aside className="hidden w-64 shrink-0 lg:block">
            <nav className="sticky top-20 max-h-[calc(100vh-6rem)] overflow-y-auto">
              <DocsSidebar tree={tree} currentPath={currentPath} />
            </nav>
          </aside>

          {/* Mobile Sidebar */}
          {sidebarOpen && (
            <div className="fixed inset-0 z-50 lg:hidden">
              <button
                type="button"
                className="fixed inset-0 bg-background/80 backdrop-blur-sm cursor-default"
                onClick={() => setSidebarOpen(false)}
                aria-label="Close sidebar"
              />
              <div className="fixed inset-y-0 left-0 w-72 bg-background border-r p-6 shadow-lg">
                <div className="flex items-center justify-between mb-6">
                  <span className="font-semibold">Navigation</span>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => setSidebarOpen(false)}
                  >
                    <X className="h-5 w-5" />
                  </Button>
                </div>
                <DocsSidebar
                  tree={tree}
                  currentPath={currentPath}
                  onNavigate={() => setSidebarOpen(false)}
                />
              </div>
            </div>
          )}

          {/* Main content */}
          <main className="min-w-0 flex-1">
            <article className="prose prose-neutral dark:prose-invert max-w-none">
              <h1 className="scroll-m-20 text-4xl font-bold tracking-tight">
                {title}
              </h1>
              {description && (
                <p className="text-xl text-muted-foreground mt-2 mb-6">
                  {description}
                </p>
              )}
              <Separator className="my-6" />
              {children}
            </article>

            {/* Prev/Next navigation */}
            <div className="mt-12 flex items-center justify-between border-t pt-6">
              {prevPage ? (
                <Link to={prevPage.url}>
                  <Button variant="ghost" className="gap-2">
                    <ChevronRight className="h-4 w-4 rotate-180" />
                    <span className="hidden sm:inline">{prevPage.title}</span>
                    <span className="sm:hidden">Previous</span>
                  </Button>
                </Link>
              ) : (
                <div />
              )}
              {nextPage ? (
                <Link to={nextPage.url}>
                  <Button variant="ghost" className="gap-2">
                    <span className="hidden sm:inline">{nextPage.title}</span>
                    <span className="sm:hidden">Next</span>
                    <ChevronRight className="h-4 w-4" />
                  </Button>
                </Link>
              ) : (
                <div />
              )}
            </div>
          </main>

          {/* Table of contents */}
          {toc && toc.length > 0 && (
            <aside className="hidden w-56 shrink-0 xl:block">
              <div className="sticky top-20">
                <h4 className="mb-4 text-sm font-semibold">On this page</h4>
                <TableOfContents toc={toc} />
              </div>
            </aside>
          )}
        </div>
      </div>

      {/* Search Dialog */}
      <Dialog open={searchOpen} onOpenChange={setSearchOpen}>
        <DialogContent className="sm:max-w-[550px]">
          <DialogHeader>
            <DialogTitle>Search Documentation</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <Input
              placeholder="Search pages..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              autoFocus
            />
            <div className="max-h-[300px] overflow-y-auto">
              {searchQuery.trim() === "" ? (
                <p className="text-sm text-muted-foreground py-6 text-center">
                  Type to search documentation...
                </p>
              ) : filteredPages.length === 0 ? (
                <p className="text-sm text-muted-foreground py-6 text-center">
                  No results found for "{searchQuery}"
                </p>
              ) : (
                <div className="space-y-1">
                  {filteredPages.map((page) => (
                    <Link
                      key={page.url}
                      to={page.url}
                      onClick={handleSearchSelect}
                      className="block rounded-lg border p-3 hover:bg-accent transition-colors"
                    >
                      <div className="font-medium">{page.title}</div>
                      {page.description && (
                        <div className="text-sm text-muted-foreground mt-1 line-clamp-2">
                          {page.description}
                        </div>
                      )}
                    </Link>
                  ))}
                </div>
              )}
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function DocsSidebar({
  tree,
  currentPath,
  onNavigate,
}: {
  tree: { children: TreeNode[] };
  currentPath: string;
  onNavigate?: () => void;
}) {
  const renderTree = (items: TreeNode[], level = 0) => {
    return items.map((item, index) => {
      if (item.type === "separator") {
        return (
          <div key={`sep-${index}`} className="mt-6 first:mt-0">
            <h4 className="mb-2 text-sm font-semibold text-foreground">
              {item.name}
            </h4>
          </div>
        );
      }

      if (item.type === "folder") {
        return (
          <div key={`folder-${index}-${item.name}`} className="mb-3">
            {item.url ? (
              <Link
                to={item.url}
                onClick={onNavigate}
                className={`block mb-1 text-sm font-medium transition-colors ${
                  currentPath === item.url
                    ? "text-primary"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {item.name}
              </Link>
            ) : (
              <div className="mb-1 text-sm font-medium text-muted-foreground">
                {item.name}
              </div>
            )}
            {item.children && item.children.length > 0 && (
              <div className="ml-3 border-l pl-3">
                {renderTree(item.children, level + 1)}
              </div>
            )}
          </div>
        );
      }

      const isActive = item.url === currentPath;
      return (
        <Link
          key={`page-${index}-${item.url}`}
          to={item.url || "#"}
          onClick={onNavigate}
          className={`block py-1.5 text-sm transition-colors ${
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

  return <div className="space-y-1">{renderTree(tree.children || [])}</div>;
}

function TableOfContents({
  toc,
}: {
  toc: Array<{ title: string; url: string; depth: number }>;
}) {
  return (
    <nav className="space-y-1 text-sm">
      {toc.map((item, index) => (
        <a
          key={index}
          href={`#${item.url}`}
          className={`block text-muted-foreground hover:text-foreground transition-colors py-1 ${
            item.depth === 3 ? "pl-4" : item.depth === 4 ? "pl-8" : ""
          }`}
        >
          {item.title}
        </a>
      ))}
    </nav>
  );
}
