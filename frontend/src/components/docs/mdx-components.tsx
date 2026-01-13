import { Link } from "@tanstack/react-router";
import type { MDXComponents } from "mdx/types";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export const mdxComponents: MDXComponents = {
  h1: (props: React.HTMLAttributes<HTMLHeadingElement>) => (
    <h1 className="scroll-m-20 text-4xl font-bold tracking-tight" {...props} />
  ),
  h2: (props: React.HTMLAttributes<HTMLHeadingElement>) => (
    <h2
      id={props.children?.toString().toLowerCase().replace(/\s+/g, "-")}
      className="scroll-m-20 border-b pb-2 text-3xl font-semibold tracking-tight mt-10 first:mt-0"
      {...props}
    />
  ),
  h3: (props: React.HTMLAttributes<HTMLHeadingElement>) => (
    <h3
      id={props.children?.toString().toLowerCase().replace(/\s+/g, "-")}
      className="scroll-m-20 text-2xl font-semibold tracking-tight mt-8"
      {...props}
    />
  ),
  h4: (props: React.HTMLAttributes<HTMLHeadingElement>) => (
    <h4
      id={props.children?.toString().toLowerCase().replace(/\s+/g, "-")}
      className="scroll-m-20 text-xl font-semibold tracking-tight mt-6"
      {...props}
    />
  ),
  p: (props: React.HTMLAttributes<HTMLParagraphElement>) => (
    <p className="leading-7 [&:not(:first-child)]:mt-6" {...props} />
  ),
  a: (props: React.AnchorHTMLAttributes<HTMLAnchorElement>) => {
    const href = props.href || "";
    const isExternal = href.startsWith("http") || href.startsWith("//");

    if (isExternal) {
      return (
        <a
          className="font-medium text-primary underline underline-offset-4 hover:text-primary/80"
          target="_blank"
          rel="noopener noreferrer"
          {...props}
        />
      );
    }

    return (
      <Link
        to={href}
        className="font-medium text-primary underline underline-offset-4 hover:text-primary/80"
      >
        {props.children}
      </Link>
    );
  },
  ul: (props: React.HTMLAttributes<HTMLUListElement>) => (
    <ul className="my-6 ml-6 list-disc [&>li]:mt-2" {...props} />
  ),
  ol: (props: React.HTMLAttributes<HTMLOListElement>) => (
    <ol className="my-6 ml-6 list-decimal [&>li]:mt-2" {...props} />
  ),
  li: (props: React.HTMLAttributes<HTMLLIElement>) => (
    <li className="leading-7" {...props} />
  ),
  blockquote: (props: React.HTMLAttributes<HTMLQuoteElement>) => (
    <blockquote
      className="mt-6 border-l-4 border-primary/30 pl-6 italic text-muted-foreground"
      {...props}
    />
  ),
  code: (props: React.HTMLAttributes<HTMLElement>) => (
    <code
      className="relative rounded bg-muted px-[0.3rem] py-[0.2rem] font-mono text-sm"
      {...props}
    />
  ),
  pre: (props: React.HTMLAttributes<HTMLPreElement>) => (
    <pre
      className="mb-4 mt-6 overflow-x-auto rounded-lg bg-muted p-4 border"
      {...props}
    />
  ),
  table: (props: React.HTMLAttributes<HTMLTableElement>) => (
    <div className="my-6 w-full overflow-y-auto">
      <table className="w-full border-collapse" {...props} />
    </div>
  ),
  tr: (props: React.HTMLAttributes<HTMLTableRowElement>) => (
    <tr className="m-0 border-t p-0 even:bg-muted/50" {...props} />
  ),
  th: (props: React.HTMLAttributes<HTMLTableCellElement>) => (
    <th
      className="border px-4 py-2 text-left font-bold [&[align=center]]:text-center [&[align=right]]:text-right bg-muted"
      {...props}
    />
  ),
  td: (props: React.HTMLAttributes<HTMLTableCellElement>) => (
    <td
      className="border px-4 py-2 text-left [&[align=center]]:text-center [&[align=right]]:text-right"
      {...props}
    />
  ),
  hr: (props: React.HTMLAttributes<HTMLHRElement>) => (
    <hr className="my-8 border-border" {...props} />
  ),
  img: (props: React.ImgHTMLAttributes<HTMLImageElement>) => (
    <img className="rounded-lg border my-6" alt="" {...props} />
  ),
  // Custom components for documentation
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
    <Link to={href} className="no-underline">
      <Card className="h-full hover:border-primary/50 hover:bg-accent/50 transition-all cursor-pointer">
        <CardHeader>
          <CardTitle className="text-lg">{title}</CardTitle>
          {description && (
            <CardDescription className="text-sm">{description}</CardDescription>
          )}
        </CardHeader>
      </Card>
    </Link>
  ),
  Callout: ({
    type = "info",
    title,
    children,
  }: {
    type?: "info" | "warning" | "error" | "tip";
    title?: string;
    children: React.ReactNode;
  }) => {
    const styles = {
      info: "border-blue-500/50 bg-blue-500/10",
      warning: "border-yellow-500/50 bg-yellow-500/10",
      error: "border-red-500/50 bg-red-500/10",
      tip: "border-green-500/50 bg-green-500/10",
    };

    return (
      <div className={`my-6 rounded-lg border-l-4 p-4 ${styles[type]}`}>
        {title && <div className="font-semibold mb-2">{title}</div>}
        <div className="text-sm">{children}</div>
      </div>
    );
  },
  Step: ({
    step,
    title,
    children,
  }: {
    step: number;
    title: string;
    children: React.ReactNode;
  }) => (
    <div className="my-6 flex gap-4">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary text-primary-foreground text-sm font-bold">
        {step}
      </div>
      <div className="flex-1">
        <h4 className="font-semibold mb-2">{title}</h4>
        <div className="text-muted-foreground">{children}</div>
      </div>
    </div>
  ),
  Tabs: ({ children }: { children: React.ReactNode }) => (
    <div className="my-6 not-prose">{children}</div>
  ),
  TabsList: ({ children }: { children: React.ReactNode }) => (
    <div className="flex border-b mb-4">{children}</div>
  ),
  TabsTrigger: ({
    value,
    children,
  }: {
    value: string;
    children: React.ReactNode;
  }) => (
    <button
      type="button"
      className="px-4 py-2 text-sm font-medium border-b-2 border-transparent hover:border-primary/50 data-[state=active]:border-primary transition-colors"
      data-value={value}
    >
      {children}
    </button>
  ),
  TabsContent: ({
    value,
    children,
  }: {
    value: string;
    children: React.ReactNode;
  }) => <div data-value={value}>{children}</div>,
};

export function getMDXComponents(overrides?: Partial<MDXComponents>) {
  return {
    ...mdxComponents,
    ...overrides,
  } as MDXComponents;
}
