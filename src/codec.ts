import { ExtData, decode as msgpackDecode, encode as msgpackEncode } from "@msgpack/msgpack";
import pako from "pako";

const BASE64_CHUNK_RE = /[A-Za-z0-9+/=\r\n]{32,}/g;

export interface SaveTextParts {
  prefix: string;
  payload: string;
  suffix: string;
}

function isBase64Text(value: string): boolean {
  return value.length > 0 && /^[A-Za-z0-9+/=]+$/.test(value);
}

function normalizeBase64(value: string): string {
  return value.replace(/\s+/g, "");
}

export function extractSavePayload(raw: string): SaveTextParts {
  const compact = normalizeBase64(raw.trim());
  if (compact.length >= 32 && isBase64Text(compact)) {
    return {
      prefix: "",
      payload: compact,
      suffix: "",
    };
  }

  const candidates = Array.from(raw.matchAll(BASE64_CHUNK_RE));
  let best: RegExpMatchArray | null = null;
  let bestLength = 0;

  for (const candidate of candidates) {
    const segment = normalizeBase64(candidate[0]);
    if (!segment || !isBase64Text(segment)) {
      continue;
    }
    if (segment.length > bestLength) {
      best = candidate;
      bestLength = segment.length;
    }
  }

  if (!best || best.index == null) {
    throw new Error("Could not find a valid base64 payload in input text.");
  }

  return {
    prefix: raw.slice(0, best.index),
    payload: normalizeBase64(best[0]),
    suffix: raw.slice(best.index + best[0].length),
  };
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  const chunkSize = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

export function decodeSaveText(raw: string): { value: unknown; parts: SaveTextParts } {
  const parts = extractSavePayload(raw);
  const compressed = base64ToBytes(parts.payload);
  const packed = pako.inflate(compressed);
  const value = msgpackDecode(packed);
  return { value, parts };
}

export function encodeSaveText(value: unknown, parts?: SaveTextParts): string {
  const packed = msgpackEncode(value);
  const compressed = pako.deflate(packed, { level: 9 });
  const payload = bytesToBase64(compressed);
  if (!parts) {
    return payload;
  }
  return `${parts.prefix}${payload}${parts.suffix}`;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object") {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

export function toJsonFriendly(value: unknown): unknown {
  if (typeof value === "bigint") {
    return { $bigint: value.toString() };
  }

  if (value instanceof Uint8Array) {
    return { $binary: bytesToBase64(value) };
  }

  if (value instanceof ExtData) {
    const extBytes = typeof value.data === "function" ? value.data(0) : value.data;
    return {
      $ext: {
        type: value.type,
        data: bytesToBase64(extBytes),
      },
    };
  }

  if (value instanceof Map) {
    const pairs: unknown[] = [];
    for (const [key, val] of value.entries()) {
      pairs.push([toJsonFriendly(key), toJsonFriendly(val)]);
    }
    return { $map: pairs };
  }

  if (Array.isArray(value)) {
    return value.map((item) => toJsonFriendly(item));
  }

  if (isPlainObject(value)) {
    const output: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value)) {
      output[key] = toJsonFriendly(val);
    }
    return output;
  }

  return value;
}

export function fromJsonFriendly(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => fromJsonFriendly(item));
  }

  if (isPlainObject(value)) {
    const keys = Object.keys(value);

    if (keys.length === 1 && keys[0] === "$binary") {
      const payload = value.$binary;
      if (typeof payload !== "string") {
        throw new Error("$binary must be a base64 string.");
      }
      return base64ToBytes(payload);
    }

    if (keys.length === 1 && keys[0] === "$bigint") {
      const payload = value.$bigint;
      if (typeof payload !== "string") {
        throw new Error("$bigint must be a decimal string.");
      }
      return BigInt(payload);
    }

    if (keys.length === 1 && keys[0] === "$ext") {
      const extObj = value.$ext;
      if (!isPlainObject(extObj)) {
        throw new Error("$ext must be an object.");
      }
      const type = extObj.type;
      const data = extObj.data;
      if (typeof type !== "number" || !Number.isFinite(type)) {
        throw new Error("$ext.type must be a number.");
      }
      if (typeof data !== "string") {
        throw new Error("$ext.data must be a base64 string.");
      }
      return new ExtData(type, base64ToBytes(data));
    }

    if (keys.length === 1 && keys[0] === "$map") {
      const mapPayload = value.$map;
      if (!Array.isArray(mapPayload)) {
        throw new Error("$map must be an array of [key, value] pairs.");
      }
      const out = new Map<unknown, unknown>();
      for (const pair of mapPayload) {
        if (!Array.isArray(pair) || pair.length !== 2) {
          throw new Error("$map pair must be [key, value].");
        }
        out.set(fromJsonFriendly(pair[0]), fromJsonFriendly(pair[1]));
      }
      return out;
    }

    const outObj: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value)) {
      outObj[key] = fromJsonFriendly(val);
    }
    return outObj;
  }

  return value;
}
