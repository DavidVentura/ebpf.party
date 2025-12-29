interface BaseTypeMember {
  name: string;
  type: string;
  offset: number;
  size: number;
}

interface StructTypeMember extends BaseTypeMember {
  kind: 'struct';
  members: TypeMember[];
}

interface ArrayTypeMember extends BaseTypeMember {
  kind: 'array';
  element_count: number;
}

interface ScalarTypeMember extends BaseTypeMember {
  kind: 'scalar';
  unsigned?: boolean;
}

export type TypeMember = StructTypeMember | ArrayTypeMember | ScalarTypeMember;

interface BaseTypeInfo {
  name: string;
  size: number;
  align: number;
}

interface StructTypeInfo extends BaseTypeInfo {
  kind: 'struct';
  members: TypeMember[];
}

interface ArrayTypeInfo extends BaseTypeInfo {
  kind: 'array';
  element_count: number;
}

interface ScalarTypeInfo extends BaseTypeInfo {
  kind: 'scalar';
  unsigned?: boolean;
}

export type TypeInfo = StructTypeInfo | ArrayTypeInfo | ScalarTypeInfo;
