<tools_overview>
Quick reference for the Ghidra MCP tools relevant to decompile cleanup. Grouped by workflow phase. All tools are exposed with a `ghidra_` prefix.
</tools_overview>

<discovery_tools>
**Finding and navigating to functions:**

- `ghidra_get_current_function` -- get the function the user has selected in Ghidra
- `ghidra_get_current_address` -- get the address the user has selected
- `ghidra_get_function_by_address(address)` -- look up a function at a specific address
- `ghidra_search_functions_by_name(query, offset, limit)` -- find functions whose name contains a substring
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

- `ghidra_list_strings(offset, limit, filter)` -- defined strings with addresses; use filter to narrow
- `ghidra_list_data_items(offset, limit)` -- labeled data values
- `ghidra_get_data_at(address)` -- type, size, label, value and containing item for one data item
- `ghidra_read_bytes(address, length)` -- raw bytes as a hex string
- `ghidra_list_imports(offset, limit)` -- imported symbols (DLL functions the binary calls)
- `ghidra_list_exports(offset, limit)` -- exported symbols
- `ghidra_list_segments(offset, limit)` -- memory segments (.text, .data, .rdata, etc.)
</data_tools>

<naming_tools>
**Renaming functions, variables, and data:**

- `ghidra_rename_function(old_name, new_name)` -- rename a function by its current name
- `ghidra_rename_function_by_address(function_address, new_name)` -- rename by address
- `ghidra_rename_variable(function_name, old_name, new_name)` -- rename a local variable, function identified by name
- `ghidra_rename_variable_by_address(function_address, old_name, new_name)` -- same, function identified by address (use when the name is ambiguous or just changed)
- `ghidra_rename_data(address, new_name)` -- rename a data label at an address
- `ghidra_batch_rename_functions(renames)` -- one transaction; each item `{"address": "0x...", "new_name": "..."}`
- `ghidra_batch_rename_data(renames)` -- one transaction; each item `{"address": "0x...", "new_name": "..."}`
</naming_tools>

<typing_tools>
**Setting types and prototypes:**

- `ghidra_set_function_prototype(function_address, prototype)` -- set the full function signature (return type, name, parameter types and names). This is the most powerful tool: it sets parameter names and types in one call.
- `ghidra_set_local_variable_type(function_address, variable_name, new_type)` -- change a local variable's type
- `ghidra_search_data_types(query, kind, offset, limit)` -- look up existing types before inventing one. `kind` is one of `function_definition`, `struct`, `enum`, `typedef`, `pointer`, `union`, `all`. Returns summaries only.
- `ghidra_get_data_type_details(name)` -- full fields/members/parameters of a single type
</typing_tools>

<comment_tools>
**Adding documentation:**

- `ghidra_set_comment(address, comment, comment_type)` -- set a comment of any type at an address. `comment_type` is one of:
  - `pre` -- shown before the code unit, i.e. the comment the decompiler view displays. **Use this for cleanup work.**
  - `eol` -- end-of-line comment in the disassembly listing
  - `post` -- shown after the code unit
  - `plate` -- block header / divider
  - `repeatable` -- propagates through references
- `ghidra_batch_set_comments(comments, comment_type)` -- set many comments in one transaction. Each item `{"address": "0x...", "comment": "text"}`. Here `comment_type` also accepts the aliases `decompiler` (= `pre`, the default) and `disassembly` (= `eol`).

There is no `set_decompiler_comment` / `set_disassembly_comment` tool -- use `ghidra_set_comment` with the appropriate `comment_type`.
</comment_tools>

<structure_tools>
**Namespaces, classes, and data types:**

- `ghidra_list_namespaces(offset, limit)` -- non-global namespaces
- `ghidra_list_classes(offset, limit)` -- class/namespace names (useful for identifying C++ class methods)
- `ghidra_rename_namespace(old_name, new_name)` / `ghidra_rename_class(old_name, new_name)` -- rename a namespace or class symbol. Does NOT rename a struct of the same name.
- `ghidra_create_struct(name, fields, category_path)` -- create a struct; each field `{"name": ..., "type": ..., "size": optional}`
- `ghidra_add_struct_field(struct_name, field_name, field_type, offset, size, comment, overwrite)` -- add one field in place, preserving struct identity
- `ghidra_add_struct_fields(struct_name, fields, overwrite)` -- add several fields in one transaction
- `ghidra_update_struct_field(struct_name, field_name, new_type, new_name)` -- retype/rename an existing field. `field_name` may be a name, an auto-generated name like `field1_0x4`, or a hex offset like `0x4`.
- `ghidra_delete_struct_field(struct_name, field_name, shrink)` -- remove a field; `shrink=False` (default) keeps later offsets stable
- `ghidra_apply_struct(address, struct_name)` -- stamp a struct over memory at an address
- `ghidra_create_enum(name, values, size, category_path)` -- each value `{"name": ..., "value": 0}`
- `ghidra_create_function_definition(name, return_type, parameters, calling_convention, category_path)` -- reusable function signature type, e.g. for vtable function pointers
- `ghidra_rename_data_type(old_name, new_name)` / `ghidra_rename_struct(old_name, new_name)` -- rename a type everywhere it is used
- `ghidra_move_data_type(data_type_name, category_path)` -- move a type to another category (created if absent)

Prefer editing an existing struct in place over recreating it -- recreating breaks references from variables and applied data.
</structure_tools>

<definition_tools>
**Defining code and data (use with care -- these modify the program's layout):**

- `ghidra_define_data(address, data_type, label)` -- define a data item; type may be `byte`/`word`/`dword`/`qword`/`float`/`double`/`pointer`/`char` or any type in the data type manager
- `ghidra_define_data_batch(items)` -- many definitions in one transaction
- `ghidra_clear_data(address, size)` -- undefine data; omit `size` to clear a single item
- `ghidra_create_function(address, name)` -- create a function at an address (renames if one already exists)
- `ghidra_batch_create_function(functions)` -- each item `{"address": "0x...", "name": "optional"}`
- `ghidra_create_label(address, name, namespace)` -- add a label at any address, including undefined bytes
- `ghidra_set_primary_label(address, name)` -- replace the primary label; deletes existing user labels at that address
- `ghidra_batch_set_primary_labels(labels)` -- each item `{"address": "0x...", "name": "..."}`
</definition_tools>

<recommended_order>
For a typical cleanup pass, call tools in this order:

1. `ghidra_decompile_function` -- get the raw code
2. `ghidra_get_function_xrefs` + `ghidra_get_xrefs_from` -- understand context
3. `ghidra_list_strings` (with filter) -- find referenced strings
4. `ghidra_search_data_types` -- check whether the types you want already exist
5. *Analyze and decide on names*
6. `ghidra_rename_function` -- rename the function first
7. `ghidra_set_function_prototype` -- set return type, param names and types
8. `ghidra_rename_variable` (repeat) -- rename each local
9. `ghidra_set_local_variable_type` (repeat) -- fix mistyped locals
10. `ghidra_set_comment(comment_type="pre")`, or `ghidra_batch_set_comments` for several at once -- add function-level and inline comments
11. `ghidra_decompile_function` -- re-decompile to verify
</recommended_order>

<batching_note>
Whenever you have more than a couple of comments, renames or data definitions to apply, prefer the `batch_*` variants. They run as a single transaction, so a failure rolls the whole set back rather than leaving the program half-edited.
</batching_note>
