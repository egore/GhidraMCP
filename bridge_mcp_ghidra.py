# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

def safe_post_json(endpoint: str, json_data) -> str:
    """
    Perform a POST request with a JSON body.
    """
    import json
    try:
        url = urljoin(ghidra_server_url, endpoint)
        body = json.dumps(json_data) if not isinstance(json_data, str) else json_data
        response = requests.post(url, data=body.encode("utf-8"),
                                 headers={"Content-Type": "application/json"},
                                 timeout=30)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def search_data_types(query: str = None, kind: str = "all", offset: int = 0, limit: int = 100) -> list:
    """
    Search for data types in the Data Type Manager by name and/or kind.

    Returns only summary information (kind, path, name, size) for each match.
    To get the fields of a struct, members of an enum, or other details,
    use get_data_type_details() with the name from these results.

    Args:
        query: Optional substring to match in data type names (case-insensitive).
               If omitted, all data types of the requested kind are returned.
        kind: Filter by data type kind. One of:
              "function_definition", "struct", "enum", "typedef",
              "pointer", "union", "all" (default: "all")
        offset: Pagination offset (default: 0)
        limit: Maximum number of results to return (default: 100)

    Returns:
        List of matching data types with their kind, path, name, and size.
    """
    params = {"offset": offset, "limit": limit}
    if query:
        params["query"] = query
    if kind:
        params["kind"] = kind
    return safe_get("search_data_types", params)

@mcp.tool()
def get_data_type_details(name: str) -> str:
    """
    Get detailed information about a data type by name, including its
    fields (for structs/unions), members (for enums), parameters (for
    function definitions), or base type (for typedefs).

    Args:
        name: Name of the data type to look up (e.g. "MyStruct", "DWORD")

    Returns:
        Detailed description of the data type including all fields/members.
    """
    if not name:
        return "Error: name is required"
    return "\n".join(safe_get("get_data_type_details", {"name": name}))

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_comment(address: str, comment: str, comment_type: str) -> str:
    """
    Set a comment of any type at a given address.

    comment_type must be one of:
      - "eol"        – End-of-line comment in disassembly
      - "pre"        – Pre comment (shown before the code unit / in decompiler)
      - "post"       – Post comment (shown after the code unit)
      - "plate"      – Plate comment (block header / divider)
      - "repeatable" – Repeatable comment (propagates through references)
    """
    return safe_post("set_comment", {
        "address": address,
        "comment": comment,
        "comment_type": comment_type
    })

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def clear_data(address: str, size: int = None) -> str:
    """
    Clear (undefine) data at an address, reverting bytes to undefined state.
    If size is omitted, clears the single data item at that address.
    """
    data = {"address": address}
    if size is not None:
        data["size"] = str(size)
    return safe_post("clear_data", data)

@mcp.tool()
def define_data(address: str, data_type: str, label: str = None) -> str:
    """
    Create a data definition at an address. Supported types: byte, word, dword, qword,
    float, double, pointer, char, or any type in the data type manager.
    Optionally assign a label/symbol name.
    """
    data = {"address": address, "data_type": data_type}
    if label:
        data["label"] = label
    return safe_post("define_data", data)

@mcp.tool()
def define_data_batch(items: list[dict]) -> str:
    """
    Create multiple data definitions in a single transaction.
    Each item: {"address": "0x...", "data_type": "dword", "label": "optional_name"}
    """
    return safe_post_json("define_data_batch", items)

@mcp.tool()
def read_bytes(address: str, length: int) -> str:
    """
    Read raw bytes from memory at a given address. Returns hex-encoded string.
    """
    return safe_get("read_bytes", {"address": address, "length": length})

@mcp.tool()
def get_data_at(address: str) -> str:
    """
    Get detailed info about the data item at a specific address:
    type, size, label, value, and containing item info.
    """
    return safe_get("get_data_at", {"address": address})

@mcp.tool()
def batch_rename_functions(renames: list[dict]) -> str:
    """
    Rename multiple functions in one transaction.
    Each item: {"address": "0x...", "new_name": "MyFunction"}
    """
    return safe_post_json("batch_rename_functions", renames)

@mcp.tool()
def batch_set_comments(comments: list[dict], comment_type: str = "decompiler") -> str:
    """
    Set multiple comments in one transaction.
    comment_type must be one of:
      - "eol" or "disassembly"  – End-of-line comment in disassembly
      - "pre" or "decompiler"   – Pre comment (shown before the code unit / in decompiler)  [default]
      - "post"                  – Post comment (shown after the code unit)
      - "plate"                 – Plate comment (block header / divider)
      - "repeatable"            – Repeatable comment (propagates through references)
    Each comment: {"address": "0x...", "comment": "text"}
    """
    return safe_post_json("batch_set_comments", {
        "comment_type": comment_type,
        "comments": comments
    })

@mcp.tool()
def create_label(address: str, name: str, namespace: str = None) -> str:
    """
    Create a label/symbol at any address (code, data, or undefined bytes).
    """
    data = {"address": address, "name": name}
    if namespace:
        data["namespace"] = namespace
    return safe_post("create_label", data)

@mcp.tool()
def create_enum(name: str, values: list[dict], size: int = 4, category_path: str = None) -> str:
    """
    Create an enum data type. Each value: {"name": "MEMBER_NAME", "value": 0}

    Parameters:
        name: Name of the enum
        values: List of value dicts with "name" and "value" keys
        size: Size in bytes (default: 4)
        category_path: Optional category path in the data type manager (e.g. "/MyCategory")
    """
    payload = {
        "name": name,
        "size": size,
        "values": values
    }
    if category_path is not None:
        payload["category_path"] = category_path
    return safe_post_json("create_enum", payload)

@mcp.tool()
def create_struct(name: str, fields: list[dict], category_path: str = None) -> str:
    """
    Create a structure data type.
    Each field: {"name": "field_name", "type": "int", "size": 4}
    If size is omitted, the type's natural size is used.

    Parameters:
        name: Name of the struct
        fields: List of field dicts with "name", "type", and optional "size" keys
        category_path: Optional category path in the data type manager (e.g. "/MyCategory")
    """
    payload = {
        "name": name,
        "fields": fields
    }
    if category_path is not None:
        payload["category_path"] = category_path
    return safe_post_json("create_struct", payload)

@mcp.tool()
def create_function_definition(name: str, return_type: str = "void", parameters: list[dict] = None,
                               calling_convention: str = None, category_path: str = None) -> str:
    """
    Create a function definition data type in the Data Type Manager.
    This is a reusable type (like a typedef for a function signature) that can be
    referenced by struct fields, e.g. as function pointers in VTable structures.

    Parameters:
        name: Name of the function definition type (e.g. "MyCallback")
        return_type: Return type (default "void")
        parameters: List of parameter dicts, each with "name" and "type" keys.
                    Example: [{"name": "self", "type": "void *"}, {"name": "count", "type": "int"}]
        calling_convention: Optional calling convention (e.g. "__stdcall", "__thiscall")
        category_path: Optional category path in the data type manager (e.g. "/VTables")
    """
    payload = {"name": name, "return_type": return_type}
    if parameters is not None:
        payload["parameters"] = parameters
    if calling_convention is not None:
        payload["calling_convention"] = calling_convention
    if category_path is not None:
        payload["category_path"] = category_path
    return safe_post_json("create_function_definition", payload)

@mcp.tool()
def apply_struct(address: str, struct_name: str) -> str:
    """
    Apply a previously created struct type at a memory address.
    Clears existing data at the address range and stamps the struct.
    """
    return safe_post("apply_struct", {"address": address, "struct_name": struct_name})

@mcp.tool()
def rename_variable_by_address(function_address: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function, identified by the function's address.
    """
    return safe_post("rename_variable", {
        "function_address": function_address,
        "old_name": old_name,
        "new_name": new_name
    })

@mcp.tool()
def update_struct_field(struct_name: str, field_name: str, new_type: str = None, new_name: str = None) -> str:
    """
    Update the data type and/or name of a field in an existing structure.
    At least one of new_type or new_name must be provided.

    field_name can be:
      - An explicit field name (e.g. "myField")
      - An auto-generated field name (e.g. "field1_0x4") for unnamed fields
      - A hex offset (e.g. "0x4") to match a field by its offset in the struct
    """
    if new_type is None and new_name is None:
        return "Error: at least one of new_type or new_name must be provided"
    payload = {
        "struct_name": struct_name,
        "field_name": field_name,
    }
    if new_type is not None:
        payload["new_type"] = new_type
    if new_name is not None:
        payload["new_name"] = new_name
    return safe_post_json("update_struct_field", payload)

@mcp.tool()
def rename_data_type(old_name: str, new_name: str) -> str:
    """
    Rename an existing data type (struct, enum, typedef, union, function
    definition, etc.) in the Data Type Manager.

    The type is looked up by its current name across all categories. Renaming
    updates the type everywhere it is used (struct fields, variables, etc.).
    """
    return safe_post("rename_data_type", {"old_name": old_name, "new_name": new_name})

@mcp.tool()
def move_data_type(data_type_name: str, category_path: str) -> str:
    """
    Move an existing data type (struct, enum, typedef, union, function
    definition, etc.) to a different category in the Data Type Manager.

    The category is created automatically if it does not exist.

    Parameters:
        data_type_name: Name of the data type to move (looked up across all categories)
        category_path: Target category path (e.g. "/MyCategory", "/VTables/IDirect3D")
    """
    return safe_post("move_data_type", {"data_type_name": data_type_name, "category_path": category_path})

@mcp.tool()
def rename_struct(old_name: str, new_name: str) -> str:
    """
    Rename an existing structure data type. Convenience alias for
    rename_data_type that works specifically with structs.
    """
    return safe_post("rename_data_type", {"old_name": old_name, "new_name": new_name})

@mcp.tool()
def batch_rename_data(renames: list[dict]) -> str:
    """
    Rename multiple data labels in one transaction.
    Each item: {"address": "0x...", "new_name": "MyLabel"}
    """
    return safe_post_json("batch_rename_data", renames)

@mcp.tool()
def batch_create_function(functions: list[dict]) -> str:
    """
    Create multiple functions in one transaction.
    Each item: {"address": "0x...", "name": "optional_name"}
    If a function already exists at the address and name is provided, it is renamed.
    """
    return safe_post_json("batch_create_function", functions)

@mcp.tool()
def create_function(address: str, name: str = None) -> str:
    """
    Create a new function at the given address. Optionally provide a name.
    If a function already exists and a name is given, it will be renamed.
    """
    data = {"address": address}
    if name:
        data["name"] = name
    return safe_post("create_function", data)

@mcp.tool()
def set_primary_label(address: str, name: str) -> str:
    """
    Set (or replace) the primary label at an address.
    All existing user-defined labels at the address are deleted first.
    """
    return safe_post("set_primary_label", {"address": address, "name": name})

@mcp.tool()
def batch_set_primary_labels(labels: list[dict]) -> str:
    """
    Set primary labels at multiple addresses in one transaction.
    Each item: {"address": "0x...", "name": "MyLabel"}
    Existing user-defined labels at each address are deleted first.
    """
    return safe_post_json("batch_set_primary_labels", labels)

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

