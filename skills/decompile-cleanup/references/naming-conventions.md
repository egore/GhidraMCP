<overview>
Naming patterns for recognizing and naming elements in decompiled Win32, MFC, COM, and C++ standard library code. Use these to choose idiomatic names that a developer familiar with these APIs would expect.
</overview>

<win32_api_patterns>

**Handle types and their conventional prefixes:**

| Type | Prefix | Example variable name |
|------|--------|-----------------------|
| HANDLE | `h` | `hFile`, `hProcess`, `hEvent`, `hThread` |
| HWND | `hWnd` | `hWnd`, `hParentWnd`, `hDialog` |
| HDC | `hDC` | `hDC`, `hMemDC`, `hPaintDC` |
| HMODULE | `hModule` | `hModule`, `hInstance` |
| HKEY | `hKey` | `hKey`, `hRegKey`, `hSubKey` |
| HRESULT | `hr` | `hr`, `hrResult` |
| HMENU | `hMenu` | `hMenu`, `hPopupMenu` |
| HBITMAP | `hBitmap` | `hBitmap`, `hOldBitmap` |
| HFONT | `hFont` | `hFont`, `hOldFont` |
| HBRUSH | `hBrush` | `hBrush`, `hBackgroundBrush` |
| HICON | `hIcon` | `hIcon`, `hSmallIcon` |
| HCURSOR | `hCursor` | `hCursor` |
| SOCKET | `sock` | `sock`, `listenSock`, `clientSock` |

**Common Win32 parameter/variable prefixes:**

| Prefix | Meaning | Example |
|--------|---------|---------|
| `lp` | Long pointer (to anything) | `lpBuffer`, `lpOverlapped` |
| `lpsz` | Long pointer to string, zero-terminated | `lpszClassName`, `lpszWindowName` |
| `dw` | DWORD (32-bit unsigned) | `dwFlags`, `dwStyle`, `dwSize` |
| `cb` | Count of bytes | `cbBuffer`, `cbData`, `cbSize` |
| `n` / `c` | Count / number of items | `nItems`, `cChildren`, `nCmdShow` |
| `b` / `f` | Boolean / flag | `bSuccess`, `fEnabled` |
| `w` | WORD (16-bit unsigned) | `wParam`, `wCommand` |
| `p` | Pointer | `pData`, `pContext`, `pNext` |
| `sz` | Zero-terminated string (char array) | `szBuffer`, `szFileName` |
| `wsz` | Wide zero-terminated string | `wszPath` |

**Common Win32 function naming patterns:**

| Pattern | Likely purpose |
|---------|----------------|
| `Create*` / `Open*` | Resource acquisition (file, window, key, etc.) |
| `Close*` / `Destroy*` / `Delete*` | Resource release |
| `Get*` / `Query*` | Retrieve a value |
| `Set*` | Modify a value |
| `Register*` / `Unregister*` | Register/unregister callbacks, classes, etc. |
| `Enable*` / `Disable*` | Toggle feature on/off |
| `Find*` / `Search*` | Locate something |
| `Enum*` | Enumerate a collection via callback |
| `Load*` / `Save*` | Persistence |
| `Init*` / `Shutdown*` | Lifecycle |
| `Send*` / `Post*` | Message passing |
| `Wait*` | Synchronization |
| `Lock*` / `Unlock*` | Mutual exclusion |
| `Alloc*` / `Free*` | Memory management |

**Common Win32 magic constants to recognize:**

- `0x80000000` = `GENERIC_READ`
- `0x40000000` = `GENERIC_WRITE`
- `0xC0000000` = `GENERIC_READ | GENERIC_WRITE`
- `0xFFFFFFFF` or `-1` (as HANDLE) = `INVALID_HANDLE_VALUE`
- `0x80` (file attr) = `FILE_ATTRIBUTE_NORMAL`
- `3` (creation disposition) = `OPEN_EXISTING`
- `1` (creation disposition) = `CREATE_NEW`
- `2` (creation disposition) = `CREATE_ALWAYS`
- `4` (creation disposition) = `OPEN_ALWAYS`
- `0x104` = `MAX_PATH` (260)
</win32_api_patterns>

<mfc_patterns>

**MFC class naming:**
- Classes prefixed with `C`: `CWnd`, `CDialog`, `CString`, `CFile`, `CArray`, `CMap`
- Member variables prefixed with `m_`: `m_hWnd`, `m_pDocument`, `m_strTitle`
- Pointer to parent class: `m_pParent`, `m_pOwner`

**MFC message handler naming:**
- `On` + message name: `OnPaint`, `OnCreate`, `OnDestroy`, `OnSize`, `OnTimer`
- `On` + command: `OnFileOpen`, `OnEditCopy`, `OnHelpAbout`
- `OnBtn` / `OnButton` + action: `OnBtnSave`, `OnButtonClicked`

**MFC virtual overrides:**
- `DoDataExchange(CDataExchange* pDX)` -- dialog data exchange
- `PreTranslateMessage(MSG* pMsg)` -- message pre-processing
- `OnInitDialog()` -- dialog initialization
- `Serialize(CArchive& ar)` -- serialization
- `OnDraw(CDC* pDC)` -- view drawing
- `GetDocument()` -- returns the document pointer

**MFC common parameter names:**
- `pDC` -- device context pointer
- `pDX` -- data exchange pointer
- `pMsg` -- message pointer
- `pWnd` -- window pointer
- `pDoc` -- document pointer
- `nID` -- control/resource ID
- `nChar` -- character code
- `nFlags` -- modifier flags
- `point` -- CPoint screen/client coords
- `rect` -- CRect bounding rectangle
</mfc_patterns>

<cpp_stl_patterns>

**Recognizing STL containers in decompiled code:**

STL containers are typically mangled and appear as complex types. Look for:
- Repeated pointer-chasing with node structures: likely `std::list`, `std::map`, `std::set`
- Contiguous buffer with size/capacity members: likely `std::vector`
- Reference-counted buffer with small buffer optimization: likely `std::string`
- Hash table structure (array of buckets + linked nodes): likely `std::unordered_map`

**Naming STL-related variables:**
- Vector: `items`, `entries`, `elements` -- name by content not container
- Map: `configMap`, `lookupTable`, `nameToIndex`
- String: name by content: `fileName`, `errorMessage`, `configLine`
- Iterator: `it`, `iter`, or the noun form: `currentEntry`, `nextItem`
- Size/count: `count`, `numEntries`, `size`

**STL algorithm patterns:**
- Linear scan with comparison: `std::find`, `std::find_if`
- Sorting: `std::sort`, `std::stable_sort`
- Copy loops: `std::copy`, `std::transform`
- Accumulation: `std::accumulate`, `std::reduce`
</cpp_stl_patterns>

<com_patterns>

**COM interface patterns:**

- Interface pointers: prefix with `p` + interface name: `pUnknown`, `pStream`, `pFactory`
- `QueryInterface` / `AddRef` / `Release` -- IUnknown methods
- `CoCreateInstance`, `CoInitialize`, `CoUninitialize` -- COM lifecycle
- HRESULT checking: `SUCCEEDED(hr)`, `FAILED(hr)`
- `CLSID`, `IID` -- class and interface identifiers

**COM naming:**
- Variables holding COM pointers: `pFactory`, `pDevice`, `pContext`
- Return codes: `hr`, `hrResult`
- Reference counting locals: `refCount`, `cRef`
- GUIDs: `clsid`, `iid`, `riid`
</com_patterns>

<function_naming_strategy>

When choosing a function name, use this priority order:

1. **Known API wrapper**: if the function is a thin wrapper around a single API call, name it by what it wraps with context. E.g., a wrapper around `RegOpenKeyEx` that always opens `HKEY_LOCAL_MACHINE\Software\MyApp` becomes `OpenAppRegistryKey`.

2. **Action on resource**: verb + noun describing the operation and target. `ReadConfigFile`, `UpdateWindowTitle`, `ValidateInputBuffer`, `SendHeartbeatPacket`.

3. **Event handler**: if called from a message map or callback table, name by the event. `OnWindowCreated`, `HandleTimerExpired`, `ProcessCommandLine`.

4. **Lifecycle**: if it initializes or tears down state, name accordingly. `InitializeSubsystem`, `CleanupResources`, `ResetState`.

5. **Predicate / query**: if it returns a boolean or value without side effects. `IsConnectionAlive`, `GetItemCount`, `HasPermission`.

Avoid generic names like `ProcessData`, `DoWork`, `HandleStuff` unless the function genuinely does something generic.
</function_naming_strategy>
