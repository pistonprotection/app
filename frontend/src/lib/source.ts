import { type InferPageType, loader } from "fumadocs-core/source";
import { icons } from "lucide-react";
import { createElement } from "react";
import { docs } from "../../.source/server";

export const source = loader({
  baseUrl: "/docs",
  source: docs.toFumadocsSource(),
  icon(icon) {
    if (!icon) {
      return;
    }
    if (icon in icons) return createElement(icons[icon as keyof typeof icons]);
  },
});

export type Page = InferPageType<typeof source>;

export function getPageTree() {
  return source.pageTree;
}

export function getAllPages() {
  return source.getPages();
}

export function getPageBySlug(slugs: string[] | undefined) {
  return source.getPage(slugs);
}
