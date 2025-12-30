import type { DebTypeInfo } from "../types/debtypeinfo";

class DebTypeRegistry {
  private registry: DebTypeInfo[] = [];

  set(debTypeInfo: DebTypeInfo[]) {
    this.registry = debTypeInfo;
  }

  get(): DebTypeInfo[] {
    return this.registry;
  }

  findByTypeName(typeName: string): DebTypeInfo | undefined {
    return this.registry.find((item) => item.type_name === typeName);
  }

  findByTypeConstant(typeConstant: number): DebTypeInfo | undefined {
    return this.registry.find((item) => item.type_constant === typeConstant);
  }

  findByCounter(counter: number): DebTypeInfo | undefined {
    return this.registry.find((item) => item.counter === counter);
  }

  clear() {
    this.registry = [];
  }
}

export const debTypeRegistry = new DebTypeRegistry();
