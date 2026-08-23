import { customAlphabet } from "nanoid";
import { z } from "zod";

// Unambiguous lowercase alphabet: DNS/hostnames are case-insensitive, so
// token ids must survive lowercasing. Excludes 0/O/1/I/l lookalikes.
const nanoid = customAlphabet("23456789abcdefghjkmnpqrstuvwxyz", 12);

export function newTokenId(): string {
  return nanoid();
}

export function newId(prefix: string): string {
  return `${prefix}_${nanoid()}`;
}

export function newAgentKey(): string {
  return `fdk_${customAlphabet(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    40,
  )()}`;
}
