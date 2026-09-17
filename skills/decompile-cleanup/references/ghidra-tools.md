<tools_overview>
Quick reference for all Ghidra MCP tools relevant to decompile cleanup. Grouped by workflow phase.
</tools_overview>

<discovery_tools>
**Finding and navigating to functions:**

- `ghidra_get_current_function` -- get the function the user has selected in Ghidra
- `ghidra_get_current_address` -- get the address the user has selected
- `ghidra_get_function_by_address(address)` -- look up a function at a specific address
- `ghidra_search_functions_by_name(query)` -- find functions whose name contains a substring
- `ghidra_list_functions` -- list all functions in the binary
- `ghidra_list_methods(offset, limit)` -- paginated list of all function names
</discovery_tools>

<decompilation_tools>
**Getting decompiled and disassembled output:**

- `ghidra_decompile_function(name)` -- decompile by function name, returns C pseudocode
- `ghidra_decompile_function_by_address(address)` -- decompile by address
- `ghidra_disassemble_function(address)` -- get assembly listing (address: instruction; comment)
</decompilation_tools>

<xref_tools>
**Cross-references -- essential for understanding context:**

- `ghidra_get_function_xrefs(name, offset, limit)` -- all references TO a named function (who calls it)
- `ghidra_get_xrefs_to(address, offset, limit)` -- all references TO an address
- `ghidra_get_xrefs_from(address, offset, limit)` -- all references FROM an address (what it calls)
</xref_tools>

<data_tools>
**Strings, data, imports, exports:**

- `ghidra_list_strings(filter, offset, limit)` -- defined strings with addresses; use filter to narrow
- `ghidra_list_data_items(offset, limit)` -- labeled data values
- `ghidra_list_imports(offset, limit)` -- imported symbols (DLL functions the binary calls)
- `ghidra_list_exports(offset, limit)` -- exported symbols
- `ghidra_list_segments(offset, limit)` -- memory segments (.text, .data, .rdata, etc.)
</data_tools>

<naming_tools>
**Renaming functions, variables, and data:**

- `ghidra_rename_function(old_name, new_name)` -- rename a function by its current name
- `ghidra_rename_function_by_address(function_address, new_name)` -- rename by address
- `ghidra_rename_variable(function_name, old_name, new_name)` -- rename a local variable within a function
- `ghidra_rename_data(address, new_name)` -- rename a data label at an address
</naming_tools>

<typing_tools>
**Setting types and prototypes:**

- `ghidra_set_function_prototype(function_address, prototype)` -- set the full function signature (return type, name, parameter types and names). This is the most powerful tool: it sets parameter names and types in one call.
- `ghidra_set_local_variable_type(function_address, variable_name, new_type)` -- change a local variable's type
</typing_tools>

<comment_tools>
**Adding documentation:**

- `ghidra_set_decompiler_comment(address, comment)` -- add a comment visible in the decompiler pseudocode view
- `ghidra_set_disassembly_comment(address, comment)` -- add a comment visible in the disassembly listing view

For cleanup work, prefer decompiler comments since the user is reading pseudocode.
</comment_tools>

<structure_tools>
**Namespaces and classes:**

- `ghidra_list_namespaces(offset, limit)` -- non-global namespaces
- `ghidra_list_classes(offset, limit)` -- class/namespace names (useful for identifying C++ class methods)
</structure_tools>

<recommended_order>
For a typical cleanup pass, call tools in this order:

1. `ghidra_decompile_function` -- get the raw code
2. `ghidra_get_function_xrefs` + `ghidra_get_xrefs_from` -- understand context
3. `ghidra_list_strings` (with filter) -- find referenced strings
4. *Analyze and decide on names*
5. `ghidra_rename_function` -- rename the function first
6. `ghidra_set_function_prototype` -- set return type, param names and types
7. `ghidra_rename_variable` (repeat) -- rename each local
8. `ghidra_set_local_variable_type` (repeat) -- fix mistyped locals
9. `ghidra_set_decompiler_comment` -- add function-level and inline comments
10. `ghidra_decompile_function` -- re-decompile to verify
</recommended_order>
