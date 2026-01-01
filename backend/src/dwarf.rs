use gimli::{AttributeValue, EndianArcSlice, LittleEndian, Reader};
use object::{Object, ObjectSection, ObjectSymbol};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DwarfDebugInfo {
    pub functions: Vec<FunctionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub function_name: String,
    pub section_name: String,
    pub stack_vars: Vec<StackVar>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackVar {
    pub name: String,
    pub type_info: String,
    pub offset: u64,
    pub size: Option<u64>,
    pub is_parameter: bool,
}

#[derive(Debug)]
struct SectionInfo {
    name: String,
    index: usize,
}

pub fn parse_dwarf_debug_info(elf_data: &[u8]) -> Result<DwarfDebugInfo, String> {
    let elf_file =
        object::File::parse(elf_data).map_err(|e| format!("Failed to parse ELF: {}", e))?;

    let tp_sections = build_section_map(&elf_file);

    if tp_sections.is_empty() {
        return Ok(DwarfDebugInfo { functions: vec![] });
    }

    let func_to_section = build_function_to_section_map(&elf_file);

    let load_section =
        |id: gimli::SectionId| -> Result<EndianArcSlice<LittleEndian>, gimli::Error> {
            let data = elf_file
                .section_by_name(id.name())
                .and_then(|section| section.uncompressed_data().ok())
                .unwrap_or(std::borrow::Cow::Borrowed(&[][..]));
            Ok(EndianArcSlice::new(Arc::from(&*data), LittleEndian))
        };

    let dwarf = gimli::Dwarf::load(load_section)
        .map_err(|e| format!("Failed to load DWARF sections: {}", e))?;

    let functions = parse_functions(&dwarf, &tp_sections, &func_to_section)?;

    Ok(DwarfDebugInfo { functions })
}

fn build_section_map(elf: &object::File) -> Vec<SectionInfo> {
    elf.sections()
        .filter_map(|section| {
            section.name().ok().and_then(|name| {
                if name.starts_with("tp/") {
                    Some(SectionInfo {
                        name: name.to_string(),
                        index: section.index().0,
                    })
                } else {
                    None
                }
            })
        })
        .collect()
}

use std::collections::HashMap;

fn build_function_to_section_map(elf: &object::File) -> HashMap<String, usize> {
    let mut map = HashMap::new();

    for symbol in elf.symbols() {
        if symbol.kind() == object::SymbolKind::Text {
            if let (Ok(name), object::SymbolSection::Section(section_idx)) =
                (symbol.name(), symbol.section())
            {
                map.insert(name.to_string(), section_idx.0);
            }
        }
    }

    map
}

fn parse_functions(
    dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
    tp_sections: &[SectionInfo],
    func_to_section: &HashMap<String, usize>,
) -> Result<Vec<FunctionInfo>, String> {
    let mut functions = Vec::new();

    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let unit = dwarf
            .unit(header)
            .map_err(|e| format!("Failed to parse unit: {}", e))?;

        let mut entries = unit.entries();
        while let Ok(Some((_, entry))) = entries.next_dfs() {
            if entry.tag() == gimli::DW_TAG_subprogram {
                if let Some(func_info) =
                    parse_function(dwarf, &unit, &mut entries, tp_sections, func_to_section)?
                {
                    functions.push(func_info);
                }
            }
        }
    }

    Ok(functions)
}

fn parse_function(
    dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
    unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
    entries: &mut gimli::EntriesCursor<EndianArcSlice<LittleEndian>>,
    tp_sections: &[SectionInfo],
    func_to_section: &HashMap<String, usize>,
) -> Result<Option<FunctionInfo>, String> {
    let entry = entries.current().ok_or("No current entry")?;

    let function_name = get_attr_string(entry, gimli::DW_AT_name, dwarf, unit)
        .unwrap_or_else(|_| "unnamed_function".to_string());

    let section_idx = match func_to_section.get(&function_name) {
        Some(idx) => *idx,
        None => return Ok(None),
    };

    let section_name = match tp_sections.iter().find(|s| s.index == section_idx) {
        Some(sec) => sec.name.clone(),
        None => return Ok(None),
    };

    let stack_vars = parse_variables(dwarf, unit, entries)?;

    Ok(Some(FunctionInfo {
        function_name,
        section_name,
        stack_vars,
    }))
}

fn parse_variables(
    dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
    unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
    entries: &mut gimli::EntriesCursor<EndianArcSlice<LittleEndian>>,
) -> Result<Vec<StackVar>, String> {
    let mut variables = Vec::new();
    let mut depth = 0;

    while let Ok(Some((delta, entry))) = entries.next_dfs() {
        depth += delta;
        if depth <= 0 {
            break;
        }

        let is_param = entry.tag() == gimli::DW_TAG_formal_parameter;
        let is_var = entry.tag() == gimli::DW_TAG_variable;

        if is_param || is_var {
            let name = get_attr_string(entry, gimli::DW_AT_name, dwarf, unit)
                .unwrap_or_else(|_| "unnamed".to_string());

            let (type_info, mut size) =
                if let Ok(Some(type_ref)) = get_attr_ref(entry, gimli::DW_AT_type) {
                    resolve_type(dwarf, unit, type_ref)
                        .unwrap_or_else(|_| ("unknown".to_string(), None))
                } else {
                    ("void".to_string(), None)
                };

            // If type didn't provide size, check if variable itself has byte_size
            if size.is_none() {
                size = get_attr_udata(entry, gimli::DW_AT_byte_size).ok();
            }

            // Only include variables with stack locations
            let offset = if let Ok(Some(loc_attr)) = entry.attr_value(gimli::DW_AT_location) {
                match extract_stack_offset(loc_attr, unit) {
                    Some(off) => off,
                    None => continue, // No stack offset (in register, etc.)
                }
            } else {
                continue; // No location attribute (optimized out)
            };

            variables.push(StackVar {
                name,
                type_info,
                offset,
                size,
                is_parameter: is_param,
            });
        }
    }

    variables.sort_by_key(|v| v.offset);

    Ok(variables)
}

fn resolve_type(
    dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
    unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
    type_offset: gimli::UnitOffset,
) -> Result<(String, Option<u64>), String> {
    let mut entries = unit
        .entries_at_offset(type_offset)
        .map_err(|e| format!("Failed to get type entry: {}", e))?;

    let (_, entry) = entries
        .next_dfs()
        .map_err(|e| format!("Failed to read entry: {}", e))?
        .ok_or("No type entry found")?;

    match entry.tag() {
        gimli::DW_TAG_base_type => {
            let name = get_attr_string(entry, gimli::DW_AT_name, dwarf, unit)?;
            let size = get_attr_udata(entry, gimli::DW_AT_byte_size).ok();
            Ok((name, size))
        }
        gimli::DW_TAG_pointer_type => {
            if let Some(pointee_offset) = get_attr_ref(entry, gimli::DW_AT_type)? {
                let (pointee_type, _) = resolve_type(dwarf, unit, pointee_offset)?;
                Ok((format!("*{}", pointee_type), Some(8)))
            } else {
                Ok(("*void".to_string(), Some(8)))
            }
        }
        gimli::DW_TAG_structure_type => {
            let name = get_attr_string(entry, gimli::DW_AT_name, dwarf, unit)
                .unwrap_or_else(|_| "anonymous_struct".to_string());
            let size = get_attr_udata(entry, gimli::DW_AT_byte_size).ok();

            /*
            let mut members = Vec::new();
            let mut depth = 0;

            while let Ok(Some((delta, member_entry))) = entries.next_dfs() {
                depth += delta;
                if depth <= 0 {
                    break;
                }

                if member_entry.tag() == gimli::DW_TAG_member {
                    let member_name = get_attr_string(member_entry, gimli::DW_AT_name, dwarf, unit)
                        .unwrap_or_else(|_| "unnamed".to_string());
                    let member_offset =
                        get_attr_udata(member_entry, gimli::DW_AT_data_member_location).ok();

                    if let Some(member_type_offset) = get_attr_ref(member_entry, gimli::DW_AT_type)?
                    {
                        let (member_type, _) = resolve_type(dwarf, unit, member_type_offset)?;
                        if let Some(off) = member_offset {
                            members.push(format!("  +{}: {}", off, member_type));
                        } else {
                            members.push(format!("  {}: {}", member_name, member_type));
                        }
                    }
                }
            }
            */

            let type_str = format!("struct {}", name);

            Ok((type_str, size))
        }
        gimli::DW_TAG_array_type => {
            if let Some(element_type_offset) = get_attr_ref(entry, gimli::DW_AT_type)? {
                let (element_type, element_size) = resolve_type(dwarf, unit, element_type_offset)?;

                // Try to get array size from the array type itself
                let array_byte_size = get_attr_udata(entry, gimli::DW_AT_byte_size).ok();

                let mut count = None;
                let mut depth = 0;

                // Look for subrange children
                while let Ok(Some((delta, child))) = entries.next_dfs() {
                    depth += delta;
                    if depth <= 0 {
                        break;
                    }

                    if child.tag() == gimli::DW_TAG_subrange_type {
                        // Try to get count or upper_bound as a constant value
                        // DW_AT_count can be encoded in various forms (Data1-8, Udata)
                        count = child
                            .attr_value(gimli::DW_AT_count)
                            .ok()
                            .and_then(|opt| opt)
                            .and_then(|attr| match attr {
                                AttributeValue::Udata(n) => Some(n),
                                AttributeValue::Data1(n) => Some(n as u64),
                                AttributeValue::Data2(n) => Some(n as u64),
                                AttributeValue::Data4(n) => Some(n as u64),
                                AttributeValue::Data8(n) => Some(n),
                                _ => None,
                            })
                            .or_else(|| {
                                child
                                    .attr_value(gimli::DW_AT_upper_bound)
                                    .ok()
                                    .and_then(|opt| opt)
                                    .and_then(|attr| match attr {
                                        AttributeValue::Udata(n) => Some(n + 1),
                                        AttributeValue::Data1(n) => Some(n as u64 + 1),
                                        AttributeValue::Data2(n) => Some(n as u64 + 1),
                                        AttributeValue::Data4(n) => Some(n as u64 + 1),
                                        AttributeValue::Data8(n) => Some(n + 1),
                                        _ => None,
                                    })
                            });
                        break;
                    }
                }

                // If no count from subrange, try to calculate from byte size
                if count.is_none() {
                    if let (Some(total_bytes), Some(elem_size)) = (array_byte_size, element_size) {
                        if elem_size > 0 {
                            count = Some(total_bytes / elem_size);
                        }
                    }
                }

                if let Some(n) = count {
                    let total_size = element_size.and_then(|es| Some(es * n));
                    Ok((format!("{}[{}]", element_type, n), total_size))
                } else {
                    Ok((format!("{}[]", element_type), None))
                }
            } else {
                Ok(("unknown[]".to_string(), None))
            }
        }
        gimli::DW_TAG_typedef => {
            let name = get_attr_string(entry, gimli::DW_AT_name, dwarf, unit)?;
            if let Some(underlying_offset) = get_attr_ref(entry, gimli::DW_AT_type)? {
                let (underlying, size) = resolve_type(dwarf, unit, underlying_offset)?;
                Ok((format!("{} ({})", name, underlying), size))
            } else {
                Ok((name, None))
            }
        }
        gimli::DW_TAG_const_type => {
            if let Some(base_offset) = get_attr_ref(entry, gimli::DW_AT_type)? {
                let (base_type, size) = resolve_type(dwarf, unit, base_offset)?;
                Ok((format!("const {}", base_type), size))
            } else {
                Ok(("const void".to_string(), None))
            }
        }
        gimli::DW_TAG_volatile_type => {
            if let Some(base_offset) = get_attr_ref(entry, gimli::DW_AT_type)? {
                let (base_type, size) = resolve_type(dwarf, unit, base_offset)?;
                Ok((format!("volatile {}", base_type), size))
            } else {
                Ok(("volatile void".to_string(), None))
            }
        }
        _ => Ok((format!("unknown_type(tag=0x{:x})", entry.tag().0), None)),
    }
}

fn extract_stack_offset<R: Reader>(
    location_attr: AttributeValue<R>,
    unit: &gimli::Unit<R>,
) -> Option<u64> {
    match location_attr {
        AttributeValue::Exprloc(expr) => {
            let mut operations = expr.operations(unit.encoding());
            while let Ok(Some(op)) = operations.next() {
                match op {
                    gimli::Operation::FrameOffset { offset } => {
                        return Some(offset.unsigned_abs());
                    }
                    _ => continue,
                }
            }
            None
        }
        _ => None,
    }
}

fn get_attr_string<R: Reader>(
    entry: &gimli::DebuggingInformationEntry<R>,
    attr: gimli::DwAt,
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
) -> Result<String, String> {
    if let Some(attr_value) = entry
        .attr_value(attr)
        .map_err(|e| format!("Failed to get attribute: {}", e))?
    {
        let string = dwarf
            .attr_string(unit, attr_value)
            .map_err(|e| format!("Failed to get string: {}", e))?;
        Ok(string
            .to_string_lossy()
            .map_err(|e| format!("Failed to convert string: {}", e))?
            .into_owned())
    } else {
        Err("Attribute not found".to_string())
    }
}

fn get_attr_udata<R: Reader>(
    entry: &gimli::DebuggingInformationEntry<R>,
    attr: gimli::DwAt,
) -> Result<u64, String> {
    if let Some(AttributeValue::Udata(value)) = entry
        .attr_value(attr)
        .map_err(|e| format!("Failed to get attribute: {}", e))?
    {
        Ok(value)
    } else {
        Err("Attribute not found or wrong type".to_string())
    }
}

fn get_attr_ref<R: Reader>(
    entry: &gimli::DebuggingInformationEntry<R>,
    attr: gimli::DwAt,
) -> Result<Option<gimli::UnitOffset<R::Offset>>, String> {
    match entry
        .attr_value(attr)
        .map_err(|e| format!("Failed to get attribute: {}", e))?
    {
        Some(AttributeValue::UnitRef(offset)) => Ok(Some(offset)),
        None => Ok(None),
        _ => Ok(None),
    }
}
