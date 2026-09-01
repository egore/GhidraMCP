---
name: decompile-cleanup
description: Clean up Ghidra decompiled functions by renaming functions, parameters, and local variables to meaningful names, and adding non-obvious documentation. Use when asked to "clean up decompiled code", "rename decompiled function", "annotate decompiled code", "decompile cleanup", "reverse engineer this function", or when working with Ghidra output that needs human-readable names.
---

<objective>
Transform raw Ghidra decompiler output into readable, well-documented C/C++ code. Analyzes decompiled functions to infer purpose from control flow, API calls, string references, and data patterns -- then applies meaningful names to the function, its parameters, and local variables. Adds concise documentation that captures non-obvious intent, not trivial rewording. Recognizes Win32 API, MFC framework, and C++ standard library patterns to use idiomatic naming.

**Requires the Ghidra MCP server to be connected.**
</objective>

<quick_start>
When the user points you to a function (by name or address):

1. Decompile it with `ghidra_decompile_function` or `ghidra_decompile_function_by_address`
2. Gather xref context (callers, callees, strings)
3. Analyze the code to understand its purpose
4. Apply all renames, type fixes, and comments via the Ghidra MCP tools
5. Re-decompile and present the cleaned-up result

See `<process>` for the detailed workflow.
</quick_start>

<context>
Ghidra's decompiler produces syntactically valid C but uses auto-generated names:
- Functions: `FUN_140001a20`, `thunk_FUN_...`
- Parameters: `param_1`, `param_2`, ...
- Locals: `local_18`, `uVar3`, `iVar1`, ...

These names carry zero semantic meaning. The goal is to recover developer intent by reading the code's behavior -- what APIs it calls, what strings it references, what structures it manipulates, and how control flows.
</context>

<process>

**Step 1: Obtain the decompiled code**

Use the function name or address provided by the user:

```
ghidra_decompile_function(name="FUN_140001a20")
  -- or --
ghidra_decompile_function_by_address(address="0x140001a20")
```

If the user says "current function", use `ghidra_get_current_function` first.

**Step 2: Gather cross-reference context**

Before renaming, gather surrounding context to improve accuracy:

- **Callers**: `ghidra_get_function_xrefs(name="FUN_140001a20")` -- who calls this function and why?
- **Callees**: `ghidra_get_xrefs_from(address="0x140001a20")` -- what does this function call?
- **Strings**: `ghidra_list_strings(filter="...")` -- any relevant string literals referenced nearby?
- **Imports**: check if it wraps or delegates to known API functions

This cross-reference pass often reveals the function's role more clearly than the body alone.

**Step 3: Analyze and determine purpose**

Read the decompiled body and cross-references. Identify:

- **What API families are used?** (Win32 file I/O, registry, networking, GDI, MFC message handling, COM, C++ STL containers, etc.)
- **What is the return value?** (BOOL success/fail, HRESULT, pointer to allocated object, count, etc.)
- **What do parameters represent?** (trace how each `param_N` is used -- passed to which APIs, cast to what types, compared against what)
- **What do locals hold?** (loop counters, intermediate results, handles, buffers, status codes, iterators)
- **What is the overall intent?** (initialization, cleanup, parsing, serialization, UI update, validation, etc.)

**Step 4: Choose names**

Apply these naming conventions:

- **Functions**: verb phrase describing action. Use PascalCase for Win32/MFC style, snake_case if the binary appears to be plain C/Linux. Examples: `InitializeConnectionPool`, `ParseConfigSection`, `OnButtonClicked`, `ValidateUserInput`.
- **Parameters**: descriptive noun/noun-phrase matching their role. Prefix with established conventions when applicable (`lpsz`, `dw`, `h`, `p`, `cb`, `n` for Win32 Hungarian where the codebase already uses it -- but prefer clear names over mechanical prefixes). Examples: `filePath`, `bufferSize`, `hParentWnd`, `pOutputStream`.
- **Locals**: short, contextual names. Loop indices can be `i`, `j`. Others should reflect what they hold: `bytesRead`, `status`, `hFile`, `errorCode`, `entryCount`.

See `references/naming-conventions.md` for Win32/MFC/STL pattern recognition.

**Step 5: Apply renames via Ghidra MCP**

Execute renames in this order to avoid confusion:

1. **Rename the function:**
   ```
   ghidra_rename_function(old_name="FUN_140001a20", new_name="ParseConfigFile")
   ```

2. **Set the function prototype** (fixes parameter names and types together):
   ```
   ghidra_set_function_prototype(
     function_address="0x140001a20",
     prototype="BOOL ParseConfigFile(LPCWSTR filePath, Config *pConfigOut)"
   )
   ```

3. **Rename local variables:**
   ```
   ghidra_rename_variable(
     function_name="ParseConfigFile",
     old_name="local_18",
     new_name="bytesRead"
   )
   ```
   Repeat for each local variable worth renaming. Skip trivially short-lived temps only if they are truly insignificant.

4. **Set local variable types** where the decompiler inferred incorrectly:
   ```
   ghidra_set_local_variable_type(
     function_address="0x140001a20",
     variable_name="bytesRead",
     new_type="DWORD"
   )
   ```

**Step 6: Add documentation**

Add comments that explain **why**, not **what**:

- **Function-level comment** (at the function's entry address): summarize purpose, preconditions, return semantics, and any non-obvious side effects.
  ```
  ghidra_set_comment(
    address="0x140001a20",
    comment="Parses the INI-style config file at filePath into pConfigOut. Returns FALSE if the file is missing or malformed.",
    comment_type="pre"
  )
  ```

- **Inline comments** at key decision points -- not on every line:
  ```
  ghidra_set_comment(
    address="0x140001a5c",
    comment="Fall back to default config if the override section is absent",
    comment_type="pre"
  )
  ```

  `comment_type="pre"` is what the decompiler view shows. When adding several comments at once, use `ghidra_batch_set_comments` instead -- it applies them in a single transaction:
  ```
  ghidra_batch_set_comments(
    comments=[
      {"address": "0x140001a20", "comment": "Parses the INI-style config file..."},
      {"address": "0x140001a5c", "comment": "Fall back to default config..."}
    ],
    comment_type="decompiler"
  )
  ```

**What to document:**
- Non-obvious control flow (why a particular branch exists)
- Error handling strategy (what happens on failure, what gets cleaned up)
- Magic numbers and bitmask meanings
- Implicit preconditions or postconditions
- Lock/unlock patterns, reference count semantics
- COM AddRef/Release ownership rules

**What NOT to document:**
- "Increment i" on `i++`
- "Call CreateFile" on `CreateFile(...)`
- "Return result" on `return result`
- Anything a competent C/C++ reader already sees

**Step 7: Verify the result**

Decompile the function again to confirm the cleaned-up output reads well:
```
ghidra_decompile_function(name="ParseConfigFile")
```

Present the before/after to the user.
</process>

<anti_patterns>
<pitfall name="over_documenting">
Do NOT add a comment to every line. Only comment where intent is non-obvious. The renamed variables and function name should carry most of the meaning.
</pitfall>

<pitfall name="wrong_abstraction_level">
Do NOT guess high-level architectural roles ("this is the main authentication module") from a single function. Stay grounded in what the code demonstrably does.
</pitfall>

<pitfall name="ignoring_context">
Do NOT rename in isolation. Always check xrefs -- a function named `FUN_140005000` that is only called from `WM_PAINT` handlers is likely a drawing/render routine. The call sites are essential clues.
</pitfall>

<pitfall name="mechanical_prefixes">
Do NOT blindly apply Hungarian notation. Use it only when the surrounding codebase already does, or when the type prefix genuinely aids comprehension (e.g., `hWnd`, `lpBuffer`, `cbSize` are conventional and useful in Win32 code).
</pitfall>
</anti_patterns>

<examples>
<example number="1">
**Before:**
```c
void FUN_14000a230(int param_1, undefined8 param_2, int param_3) {
  int iVar1;
  undefined8 local_28;
  local_28 = CreateFileW(param_2, 0x80000000, 1, 0, 3, 0x80, 0);
  if (local_28 != -1) {
    iVar1 = GetFileSize(local_28, 0);
    if (param_3 < iVar1) {
      iVar1 = param_3;
    }
    ReadFile(local_28, param_1, iVar1, &param_3, 0);
    CloseHandle(local_28);
  }
}
```

**After:**
```c
// Reads up to maxBytes from filePath into buffer. Silently no-ops if file cannot be opened.
void ReadFileIntoBuffer(LPVOID buffer, LPCWSTR filePath, DWORD maxBytes) {
  HANDLE hFile;
  DWORD fileSize;
  hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile != INVALID_HANDLE_VALUE) {
    fileSize = GetFileSize(hFile, NULL);
    if (maxBytes < fileSize) {
      fileSize = maxBytes;  // Cap read to caller's buffer size
    }
    ReadFile(hFile, buffer, fileSize, &maxBytes, NULL);
    CloseHandle(hFile);
  }
}
```
</example>
</examples>

<reference_guides>
- **Ghidra MCP tools**: [references/ghidra-tools.md](references/ghidra-tools.md) -- all available Ghidra tools and when to use each
- **Naming conventions**: [references/naming-conventions.md](references/naming-conventions.md) -- Win32, MFC, STL, and COM naming patterns
</reference_guides>

<success_criteria>
Cleanup is complete when:
- [ ] Function has a descriptive name reflecting its action
- [ ] All parameters have meaningful names and correct types where inferrable
- [ ] Local variables have contextual names (not `local_XX` or `uVarN`)
- [ ] Function prototype is set with proper types and names
- [ ] Non-obvious logic has concise comments explaining **why**
- [ ] No trivial/obvious comments were added
- [ ] Final decompiled output was re-read to confirm readability
- [ ] Before/after shown to the user
</success_criteria>
