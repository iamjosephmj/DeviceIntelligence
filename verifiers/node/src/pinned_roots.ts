import { readFileSync } from "node:fs";
import { X509Certificate } from "node:crypto";

export function parse(text: string): X509Certificate[] {
  const out: X509Certificate[] = [];
  for (const line of text.split("\n")) {
    const s = line.trim();
    if (s && !s.startsWith("#")) out.push(new X509Certificate(s));
  }
  return out;
}

export function default(): X509Certificate[] {
  const p = new URL("../resources/pinned-roots.txt", import.meta.url).pathname;
  return parse(readFileSync(p, "utf8"));
}
