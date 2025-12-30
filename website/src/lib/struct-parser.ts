import type {
  TypeInfo,
  TypeMember,
  ScalarTypeMember,
  ArrayTypeMember,
  StructTypeMember,
} from "../types/typeinfo";

export type ParsedValue =
  | { kind: "scalar"; value: number | bigint }
  | {
      kind: "string";
      value: string;
      rawBytes: number[];
      displayMode: "string" | "hex";
    }
  | { kind: "array"; elements: ParsedValue[] }
  | { kind: "struct"; fields: ParsedField[] };

export interface ParsedField {
  name: string;
  type: string;
  value: ParsedValue;
  offset: number;
  size: number;
}

export interface ParseResult {
  success: boolean;
  parsed?: ParsedField[];
  error?: string;
}

function readLittleEndian(
  view: DataView,
  offset: number,
  size: number,
  unsigned: boolean
): number | bigint {
  switch (size) {
    case 1:
      return unsigned ? view.getUint8(offset) : view.getInt8(offset);
    case 2:
      return unsigned
        ? view.getUint16(offset, true)
        : view.getInt16(offset, true);
    case 4:
      return unsigned
        ? view.getUint32(offset, true)
        : view.getInt32(offset, true);
    case 8:
      return unsigned
        ? view.getBigUint64(offset, true)
        : view.getBigInt64(offset, true);
    default:
      throw new Error(`Unsupported scalar size: ${size}`);
  }
}

function charArrayToString(bytes: number[]): string {
  const decoder = new TextDecoder("utf-8", { fatal: false });
  let result = "";

  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0) {
      result += "\\0";
    } else {
      const decoded = decoder.decode(new Uint8Array([bytes[i]]));
      result += decoded === "\ufffd" ? `\\x${bytes[i].toString(16).padStart(2, "0")}` : decoded;
    }
  }

  return result;
}

function parseScalar(view: DataView, member: ScalarTypeMember): ParsedValue {
  const value = readLittleEndian(
    view,
    member.offset,
    member.size,
    member.unsigned || false
  );
  return { kind: "scalar", value };
}

function parseArray(
  view: DataView,
  member: ArrayTypeMember,
  typeRegistry: { [name: string]: TypeInfo }
): ParsedValue {
  if (member.type === "char") {
    const bytes: number[] = [];
    for (let i = 0; i < member.element_count; i++) {
      bytes.push(view.getUint8(member.offset + i));
    }
    return {
      kind: "string",
      value: charArrayToString(bytes),
      rawBytes: bytes,
      displayMode: "string",
    };
  }

  const elementTypeInfo = typeRegistry[member.type];
  if (!elementTypeInfo) {
    return {
      kind: "array",
      elements: [],
    };
  }

  const elements: ParsedValue[] = [];
  const elementSize = elementTypeInfo.size;

  for (let i = 0; i < member.element_count; i++) {
    const elementOffset = member.offset + i * elementSize;

    if (elementTypeInfo.kind === "scalar") {
      const value = readLittleEndian(
        view,
        elementOffset,
        elementSize,
        (elementTypeInfo as ScalarTypeMember).unsigned || false
      );
      elements.push({ kind: "scalar", value });
    } else if (elementTypeInfo.kind === "struct") {
      const nestedFields = parseMembers(
        view,
        (elementTypeInfo as StructTypeMember).members,
        typeRegistry,
        elementOffset
      );
      elements.push({ kind: "struct", fields: nestedFields });
    }
  }

  return { kind: "array", elements };
}

function parseNestedStruct(
  view: DataView,
  member: StructTypeMember,
  typeRegistry: { [name: string]: TypeInfo }
): ParsedValue {
  const fields = parseMembers(
    view,
    member.members,
    typeRegistry,
    member.offset
  );
  return { kind: "struct", fields };
}

function parseMembers(
  view: DataView,
  members: TypeMember[],
  typeRegistry: { [name: string]: TypeInfo },
  baseOffset: number = 0
): ParsedField[] {
  const result: ParsedField[] = [];

  for (const member of members) {
    const absoluteOffset = baseOffset + member.offset;

    let value: ParsedValue;

    if (member.kind === "scalar") {
      const adjustedMember = { ...member, offset: absoluteOffset };
      value = parseScalar(view, adjustedMember as ScalarTypeMember);
    } else if (member.kind === "array") {
      const adjustedMember = { ...member, offset: absoluteOffset };
      value = parseArray(view, adjustedMember as ArrayTypeMember, typeRegistry);
    } else if (member.kind === "struct") {
      const adjustedMember = { ...member, offset: absoluteOffset };
      value = parseNestedStruct(
        view,
        adjustedMember as StructTypeMember,
        typeRegistry
      );
    } else {
      continue;
    }

    result.push({
      name: member.name,
      type: member.type,
      value,
      offset: member.offset,
      size: member.size,
    });
  }

  return result;
}

export function parseStruct(
  data: number[],
  typeInfo: TypeInfo,
  typeRegistry: { [name: string]: TypeInfo }
): ParseResult {
  if (data.length < typeInfo.size) {
    return {
      success: false,
      error: `Data too short: expected ${typeInfo.size} bytes, got ${data.length}`,
    };
  }

  if (typeInfo.kind !== "struct") {
    return {
      success: false,
      error: `Type '${typeInfo.name}' is not a struct (kind: ${typeInfo.kind})`,
    };
  }

  const uint8Array = new Uint8Array(data);
  const view = new DataView(uint8Array.buffer);

  const parsed = parseMembers(view, typeInfo.members, typeRegistry);

  return {
    success: true,
    parsed,
  };
}
