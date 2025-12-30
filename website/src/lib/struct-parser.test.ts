import { describe, it, expect } from "vitest";
import { parseStruct } from "./struct-parser";
import type { TypeInfo } from "../types/typeinfo";

describe("struct-parser", () => {
  it("should parse event struct with pid, ppid, and comm (without prefix)", () => {
    // Input data without the 2-byte prefix
    const data = [
      99, 0, 0, 0, // pid: 99 (little-endian u32)
      11, 0, 0, 0, // ppid: 11 (little-endian u32)
      116, 114, 117, 101, // "true" in ASCII
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // remaining nulls (16 bytes total)
    ];

    // TypeInfo for struct event
    const eventTypeInfo: TypeInfo = {
      kind: "struct",
      name: "event",
      size: 24,
      align: 4,
      members: [
        {
          kind: "scalar",
          name: "pid",
          type: "__u32",
          offset: 0,
          size: 4,
          align: 4,
          unsigned: true,
        },
        {
          kind: "scalar",
          name: "ppid",
          type: "__u32",
          offset: 4,
          size: 4,
          align: 4,
          unsigned: true,
        },
        {
          kind: "array",
          name: "comm",
          type: "char",
          offset: 8,
          size: 16,
          align: 1,
          element_count: 16,
        },
      ],
    };

    const typeRegistry = { event: eventTypeInfo };

    // Parse the struct
    const result = parseStruct(data, eventTypeInfo, typeRegistry);

    // Assert success
    expect(result.success).toBe(true);
    expect(result.parsed).toBeDefined();

    // Assert field count
    expect(result.parsed!.length).toBe(3);

    // Assert pid field
    const pidField = result.parsed![0];
    expect(pidField.name).toBe("pid");
    expect(pidField.value.kind).toBe("scalar");
    if (pidField.value.kind === "scalar") {
      expect(pidField.value.value).toBe(99);
    }

    // Assert ppid field
    const ppidField = result.parsed![1];
    expect(ppidField.name).toBe("ppid");
    expect(ppidField.value.kind).toBe("scalar");
    if (ppidField.value.kind === "scalar") {
      expect(ppidField.value.value).toBe(11);
    }

    // Assert comm field
    const commField = result.parsed![2];
    expect(commField.name).toBe("comm");
    expect(commField.value.kind).toBe("string");
    if (commField.value.kind === "string") {
      expect(commField.value.value).toBe("true\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0");
      expect(commField.value.rawBytes).toEqual([
        116, 114, 117, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      ]);
      expect(commField.value.displayMode).toBe("string");
    }
  });

  it("should handle data that is too short", () => {
    const data = [1, 2, 3]; // Too short

    const eventTypeInfo: TypeInfo = {
      kind: "struct",
      name: "event",
      size: 24,
      align: 4,
      members: [],
    };

    const result = parseStruct(data, eventTypeInfo, {});

    expect(result.success).toBe(false);
    expect(result.error).toContain("Data too short");
  });

  it("should handle non-struct types", () => {
    const data = [1, 2, 3, 4];

    const scalarTypeInfo: TypeInfo = {
      kind: "scalar",
      name: "int",
      type: "int",
      size: 4,
      align: 4,
      offset: 0,
      unsigned: false,
    };

    const result = parseStruct(data, scalarTypeInfo, {});

    expect(result.success).toBe(false);
    expect(result.error).toContain("is not a struct");
  });
});
