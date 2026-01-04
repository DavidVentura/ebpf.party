use backend::dwarf::parse_dwarf_debug_info;
use std::fs;

#[test]
fn test_simple_stack_parsing() {
    let elf_data = fs::read("tests/data/simple_stack.o").unwrap();

    let result = parse_dwarf_debug_info(elf_data.as_slice()).expect("Failed to parse DWARF");

    // Print the results for debugging
    for func in &result.functions {
        println!(
            "Function: {} in section {}",
            func.function_name, func.section_name
        );
        for var in &func.stack_vars {
            println!(
                "  {} {}: {} (offset: {:?}, size: {:?}, param: {})",
                if var.is_parameter { "param" } else { "var  " },
                var.name,
                var.type_info,
                var.offset,
                var.size,
                var.is_parameter
            );
        }
    }

    // Find the handle_exec function
    let handle_exec = result
        .functions
        .iter()
        .find(|f| f.function_name == "handle_exec")
        .expect("Expected to find handle_exec function");

    // Assert exact expected structure
    assert_eq!(handle_exec.function_name, "handle_exec");
    assert_eq!(handle_exec.section_name, "tp/sched/sched_process_exec");
    assert_eq!(
        handle_exec.stack_vars.len(),
        1,
        "Only variables with stack locations should be included"
    );

    // Assert process_name variable (only one with stack location)
    assert_eq!(handle_exec.stack_vars[0].name, "process_name");
    assert_eq!(handle_exec.stack_vars[0].type_info, "char[16]");
    assert_eq!(handle_exec.stack_vars[0].offset, 8);
    assert_eq!(handle_exec.stack_vars[0].size, Some(16));
    assert_eq!(handle_exec.stack_vars[0].is_parameter, false);
}

#[test]
fn test_blah_parsing() {
    let elf_data = fs::read("tests/data/blah.o").unwrap();

    let result = parse_dwarf_debug_info(elf_data.as_slice()).expect("Failed to parse DWARF");

    // Print the results for debugging
    for func in &result.functions {
        println!(
            "Function: {} in section {}",
            func.function_name, func.section_name
        );
        for var in &func.stack_vars {
            println!(
                "  {} {}: {} (offset: {}, size: {:?}, param: {})",
                if var.is_parameter { "param" } else { "var  " },
                var.name,
                var.type_info,
                var.offset,
                var.size,
                var.is_parameter
            );
        }
    }
}
