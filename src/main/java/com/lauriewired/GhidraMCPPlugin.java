package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.InvalidNameException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.GenericCallingConvention;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.options.Options;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        server.createContext("/search_data_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String query = qparams.get("query");
            String kind = qparams.get("kind");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchDataTypes(query, kind, offset, limit));
        });

        server.createContext("/get_data_type_details", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            sendResponse(exchange, getDataTypeDetails(name));
        });

        // New API endpoints based on requirements
        
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            sendResponse(exchange, listFunctions());
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/set_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            String commentTypeStr = params.get("comment_type");
            int commentType = resolveCommentType(commentTypeStr);
            if (commentType < 0) {
                sendResponse(exchange, "Invalid comment_type: " + commentTypeStr +
                    ". Supported: eol, pre, post, plate, repeatable");
                return;
            }
            boolean success = setCommentAtAddress(address, comment, commentType, "Set " + commentTypeStr + " comment");
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        server.createContext("/clear_data", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String size = params.get("size");
            String result = clearData(address, size);
            sendResponse(exchange, result);
        });

        server.createContext("/define_data", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String dataType = params.get("data_type");
            String label = params.get("label");
            String result = defineData(address, dataType, label);
            sendResponse(exchange, result);
        });

        server.createContext("/define_data_batch", exchange -> {
            String body = readRequestBody(exchange);
            String result = defineDataBatch(body);
            sendResponse(exchange, result);
        });

        server.createContext("/read_bytes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String length = qparams.get("length");
            String result = readBytes(address, length);
            sendResponse(exchange, result);
        });

        server.createContext("/get_data_at", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String result = getDataAt(address);
            sendResponse(exchange, result);
        });

        server.createContext("/batch_rename_functions", exchange -> {
            String body = readRequestBody(exchange);
            String result = batchRenameFunctions(body);
            sendResponse(exchange, result);
        });

        // Batch version of /renameData: JSON array of {address, new_name} objects.
        server.createContext("/batch_rename_data", exchange -> {
            String body = readRequestBody(exchange);
            String result = batchRenameData(body);
            sendResponse(exchange, result);
        });

        // Batch version of /create_function: JSON array of {address, name?} objects.
        // Each entry becomes a USER_DEFINED function; if a function already exists at the
        // address and `name` is provided, it is renamed instead.
        server.createContext("/batch_create_function", exchange -> {
            String body = readRequestBody(exchange);
            String result = batchCreateFunction(body);
            sendResponse(exchange, result);
        });

        server.createContext("/batch_set_comments", exchange -> {
            String body = readRequestBody(exchange);
            String result = batchSetComments(body);
            sendResponse(exchange, result);
        });

        server.createContext("/create_label", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            String namespace = params.get("namespace");
            String result = createLabel(address, name, namespace);
            sendResponse(exchange, result);
        });

        server.createContext("/create_enum", exchange -> {
            String body = readRequestBody(exchange);
            String result = createEnum(body);
            sendResponse(exchange, result);
        });

        server.createContext("/create_struct", exchange -> {
            String body = readRequestBody(exchange);
            String result = createStruct(body);
            sendResponse(exchange, result);
        });

        server.createContext("/create_function_definition", exchange -> {
            String body = readRequestBody(exchange);
            String result = createFunctionDefinition(body);
            sendResponse(exchange, result);
        });

        server.createContext("/update_struct_field", exchange -> {
            String body = readRequestBody(exchange);
            String result = updateStructField(body);
            sendResponse(exchange, result);
        });

        // Add one or more new fields to an existing struct, in place, without
        // having to recreate (and thereby unlink) the struct.
        server.createContext("/add_struct_fields", exchange -> {
            String body = readRequestBody(exchange);
            String result = addStructFields(body);
            sendResponse(exchange, result);
        });

        // Remove a field from an existing struct, in place.
        server.createContext("/delete_struct_field", exchange -> {
            String body = readRequestBody(exchange);
            String result = deleteStructField(body);
            sendResponse(exchange, result);
        });

        // Rename a data type (struct, enum, typedef, union, function definition, etc.)
        // POST params: old_name, new_name
        server.createContext("/rename_data_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String oldName = params.get("old_name");
            String newName = params.get("new_name");
            String result = renameDataType(oldName, newName);
            sendResponse(exchange, result);
        });

        // Move a data type to a different category.
        // POST params: data_type_name, category_path
        server.createContext("/move_data_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String dataTypeName = params.get("data_type_name");
            String categoryPath = params.get("category_path");
            String result = moveDataType(dataTypeName, categoryPath);
            sendResponse(exchange, result);
        });

        // Rename a class/namespace symbol in the symbol table.
        // POST params: old_name, new_name
        server.createContext("/rename_namespace", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String oldName = params.get("old_name");
            String newName = params.get("new_name");
            String result = renameNamespace(oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/apply_struct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String structName = params.get("struct_name");
            String result = applyStruct(address, structName);
            sendResponse(exchange, result);
        });

        server.createContext("/create_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            String result = createFunctionAtAddress(address, name);
            sendResponse(exchange, result);
        });

        // Set (or rename) the primary label at an address, deleting all other labels there first.
        // POST params: address, name
        server.createContext("/set_primary_label", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            String result = setPrimaryLabel(address, name);
            sendResponse(exchange, result);
        });

        // Batch version: JSON array of {address, name} objects — all done in one transaction.
        server.createContext("/batch_set_primary_labels", exchange -> {
            String body = readRequestBody(exchange);
            String result = batchSetPrimaryLabels(body);
            sendResponse(exchange, result);
        });

        server.createContext("/rename_variable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String oldName = params.get("old_name");
            String newName = params.get("new_name");
            String result = renameVariableByAddress(functionAddress, oldName, newName);
            sendResponse(exchange, result);
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }

    /**
     * Search for data types in the Data Type Manager, optionally filtered by kind and name.
     *
     * @param query  Optional substring to match against the data type name (case-insensitive).
     *               If null or empty, all data types of the requested kind are returned.
     * @param kind   One of: "function_definition", "struct", "enum", "typedef", "pointer", "all".
     *               If null or empty, defaults to "all".
     * @param offset Pagination offset
     * @param limit  Pagination limit
     */
    private String searchDataTypes(String query, String kind, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        if (kind == null || kind.isEmpty()) kind = "all";
        String kindLower = kind.toLowerCase();

        DataTypeManager dtm = program.getDataTypeManager();
        Iterator<DataType> allTypes = dtm.getAllDataTypes();

        List<String> matches = new ArrayList<>();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();

            // Filter by kind
            if (!matchesKind(dt, kindLower)) continue;

            // Filter by name substring (case-insensitive)
            if (query != null && !query.isEmpty()) {
                if (!dt.getName().toLowerCase().contains(query.toLowerCase())) continue;
            }

            matches.add(formatDataTypeEntry(dt));
        }

        Collections.sort(matches);

        if (matches.isEmpty()) {
            String msg = "No data types found";
            if (query != null && !query.isEmpty()) msg += " matching '" + query + "'";
            if (!"all".equals(kindLower)) msg += " of kind '" + kind + "'";
            return msg;
        }
        return paginateList(matches, offset, limit);
    }

    /**
     * Check whether a DataType matches the requested kind filter.
     */
    private boolean matchesKind(DataType dt, String kindLower) {
        switch (kindLower) {
            case "function_definition":
                return dt instanceof FunctionDefinition;
            case "struct":
            case "structure":
                return dt instanceof ghidra.program.model.data.Structure;
            case "enum":
                return dt instanceof ghidra.program.model.data.Enum;
            case "typedef":
                return dt instanceof ghidra.program.model.data.TypeDef;
            case "pointer":
                return dt instanceof ghidra.program.model.data.Pointer;
            case "union":
                return dt instanceof ghidra.program.model.data.Union;
            case "all":
                return true;
            default:
                return true;
        }
    }

    /**
     * Format a data type into a human-readable line for listing/search results.
     */
    private String formatDataTypeEntry(DataType dt) {
        String kind;
        if (dt instanceof FunctionDefinition) {
            kind = "FunctionDefinition";
        } else if (dt instanceof ghidra.program.model.data.Structure) {
            kind = "Structure";
        } else if (dt instanceof ghidra.program.model.data.Enum) {
            kind = "Enum";
        } else if (dt instanceof ghidra.program.model.data.Union) {
            kind = "Union";
        } else if (dt instanceof ghidra.program.model.data.TypeDef) {
            kind = "TypeDef";
        } else if (dt instanceof ghidra.program.model.data.Pointer) {
            kind = "Pointer";
        } else {
            kind = dt.getClass().getSimpleName();
        }

        return String.format("[%s] %s (%s, %d bytes)",
            kind,
            dt.getPathName(),
            dt.getName(),
            dt.getLength());
    }

    /**
     * Get detailed information about a data type by name, including its fields/members.
     */
    private String getDataTypeDetails(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Error: 'name' parameter is required";

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByNameInAllCategories(dtm, name);
        if (dt == null) return "Data type '" + name + "' not found";

        StringBuilder sb = new StringBuilder();
        sb.append("Name: ").append(dt.getName()).append("\n");
        sb.append("Path: ").append(dt.getPathName()).append("\n");
        sb.append("Size: ").append(dt.getLength()).append(" bytes\n");
        sb.append("Description: ").append(dt.getDescription() != null ? dt.getDescription() : "").append("\n");

        if (dt instanceof ghidra.program.model.data.Structure) {
            ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) dt;
            sb.append("Kind: Structure\n");
            sb.append("Alignment: ").append(struct.getAlignment()).append("\n");
            ghidra.program.model.data.DataTypeComponent[] comps = struct.getDefinedComponents();
            sb.append("Fields (").append(comps.length).append("):\n");
            for (ghidra.program.model.data.DataTypeComponent comp : comps) {
                String fieldName = comp.getFieldName();
                if (fieldName == null) {
                    fieldName = "field" + comp.getOrdinal() +
                                "_0x" + Integer.toHexString(comp.getOffset());
                }
                sb.append(String.format("  0x%x (%d bytes) %s %s",
                    comp.getOffset(),
                    comp.getLength(),
                    comp.getDataType().getName(),
                    fieldName));
                if (comp.getComment() != null && !comp.getComment().isEmpty()) {
                    sb.append("  // ").append(comp.getComment());
                }
                sb.append("\n");
            }
        } else if (dt instanceof ghidra.program.model.data.Enum) {
            ghidra.program.model.data.Enum enumDt = (ghidra.program.model.data.Enum) dt;
            sb.append("Kind: Enum\n");
            String[] names = enumDt.getNames();
            sb.append("Members (").append(names.length).append("):\n");
            for (String memberName : names) {
                sb.append(String.format("  %s = 0x%x (%d)\n",
                    memberName, enumDt.getValue(memberName), enumDt.getValue(memberName)));
            }
        } else if (dt instanceof ghidra.program.model.data.Union) {
            ghidra.program.model.data.Union union = (ghidra.program.model.data.Union) dt;
            sb.append("Kind: Union\n");
            ghidra.program.model.data.DataTypeComponent[] comps = union.getDefinedComponents();
            sb.append("Members (").append(comps.length).append("):\n");
            for (ghidra.program.model.data.DataTypeComponent comp : comps) {
                String fieldName = comp.getFieldName();
                if (fieldName == null) {
                    fieldName = "field" + comp.getOrdinal();
                }
                sb.append(String.format("  (%d bytes) %s %s",
                    comp.getLength(),
                    comp.getDataType().getName(),
                    fieldName));
                if (comp.getComment() != null && !comp.getComment().isEmpty()) {
                    sb.append("  // ").append(comp.getComment());
                }
                sb.append("\n");
            }
        } else if (dt instanceof FunctionDefinition) {
            FunctionDefinition funcDef = (FunctionDefinition) dt;
            sb.append("Kind: FunctionDefinition\n");
            sb.append("Return type: ").append(funcDef.getReturnType().getName()).append("\n");
            String cc = funcDef.getCallingConventionName();
            if (cc != null && !cc.isEmpty()) {
                sb.append("Calling convention: ").append(cc).append("\n");
            }
            ParameterDefinition[] params = funcDef.getArguments();
            sb.append("Parameters (").append(params.length).append("):\n");
            for (ParameterDefinition param : params) {
                sb.append(String.format("  %s %s",
                    param.getDataType().getName(),
                    param.getName()));
                if (param.getComment() != null && !param.getComment().isEmpty()) {
                    sb.append("  // ").append(param.getComment());
                }
                sb.append("\n");
            }
        } else if (dt instanceof ghidra.program.model.data.TypeDef) {
            ghidra.program.model.data.TypeDef typeDef = (ghidra.program.model.data.TypeDef) dt;
            sb.append("Kind: TypeDef\n");
            sb.append("Base type: ").append(typeDef.getBaseDataType().getName()).append("\n");
            sb.append("Base type path: ").append(typeDef.getBaseDataType().getPathName()).append("\n");
        } else {
            sb.append("Kind: ").append(dt.getClass().getSimpleName()).append("\n");
        }

        return sb.toString().trim();
    }

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return;

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    private String renameVariableByAddress(String functionAddressStr, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionAddressStr == null || functionAddressStr.isEmpty()) return "function_address is required";
        if (oldVarName == null || oldVarName.isEmpty()) return "old_name is required";
        if (newVarName == null || newVarName.isEmpty()) return "new_name is required";

        Address addr;
        try {
            addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(functionAddressStr);
        } catch (Exception e) {
            return "Invalid address: " + functionAddressStr;
        }

        Function func = program.getListing().getFunctionAt(addr);
        if (func == null) {
            return "No function at address: " + functionAddressStr;
        }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile");

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable named '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable '" + oldVarName + "' not found in function at " + functionAddressStr;
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename variable by address");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Failed to rename variable by address", e);
                } finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed successfully" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n", 
                func.getName(), 
                func.getEntryPoint()));
        }

        return result.toString();
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted()) 
                ? result.getDecompiledFunction().getC() 
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Resolve a comment type string to a CodeUnit comment type constant.
     * Supported values: "eol", "pre", "post", "plate", "repeatable".
     * For backwards compatibility, "decompiler" maps to PRE_COMMENT and
     * "disassembly" maps to EOL_COMMENT.
     * Returns -1 if the string is not recognized.
     */
    private int resolveCommentType(String commentTypeStr) {
        if (commentTypeStr == null) return -1;
        switch (commentTypeStr.toLowerCase()) {
            case "eol":
            case "disassembly":
                return CodeUnit.EOL_COMMENT;
            case "pre":
            case "decompiler":
                return CodeUnit.PRE_COMMENT;
            case "post":
                return CodeUnit.POST_COMMENT;
            case "plate":
                return CodeUnit.PLATE_COMMENT;
            case "repeatable":
                return CodeUnit.REPEATABLE_COMMENT;
            default:
                return -1;
        }
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                
                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }
                
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                
                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }
        
        return paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // Handle C-style pointer suffix(es): e.g. "SomeType *" or "SomeType **"
        // Strip trailing whitespace and count/remove trailing '*' characters
        String trimmed = typeName.trim();
        int pointerDepth = 0;
        while (trimmed.endsWith("*")) {
            pointerDepth++;
            trimmed = trimmed.substring(0, trimmed.length() - 1).trim();
        }
        if (pointerDepth > 0) {
            DataType baseType = resolveDataType(dtm, trimmed);
            for (int i = 0; i < pointerDepth; i++) {
                baseType = new PointerDataType(baseType, dtm);
            }
            return baseType;
        }

        // First try to find exact match by name in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Try as a path in the data type manager (with leading '/' if not already present)
        // This handles paths like "d3d9h/functions/IDirect3DDevice9/SomeType"
        String pathToTry = typeName.startsWith("/") ? typeName : "/" + typeName;
        DataType pathType = dtm.getDataType(pathToTry);
        if (pathType != null) {
            Msg.info(this, "Found data type by path: " + pathType.getPathName());
            return pathType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(new VoidDataType(dtm), dtm);
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType, dtm);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(new VoidDataType(dtm), dtm);
        }

        // Handle common built-in types using concrete classes (avoids dtm path lookup failures)
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return new IntegerDataType(dtm);
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return new UnsignedIntegerDataType(dtm);
            case "short":
                return new ShortDataType(dtm);
            case "ushort":
            case "unsigned short":
            case "word":
                return new UnsignedShortDataType(dtm);
            case "char":
            case "byte":
                return new CharDataType(dtm);
            case "uchar":
            case "unsigned char":
                return new UnsignedCharDataType(dtm);
            case "longlong":
            case "__int64":
                return new LongLongDataType(dtm);
            case "ulonglong":
            case "unsigned __int64":
                return new UnsignedLongLongDataType(dtm);
            case "float":
                return new FloatDataType(dtm);
            case "double":
                return new DoubleDataType(dtm);
            case "qword":
                return new LongLongDataType(dtm);
            case "pointer":
                return new PointerDataType(dtm);
            case "bool":
            case "boolean":
                return new BooleanDataType(dtm);
            case "void":
                return new VoidDataType(dtm);
            default:
                // Type not found anywhere — throw so callers get a clear error
                // instead of silently corrupting data with a wrong type
                throw new IllegalArgumentException("Cannot resolve data type: '" + typeName + "'");
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    private String clearData(String addressStr, String sizeStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to clear data");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Clear data");
                boolean success = false;
                try {
                    Address start = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();

                    Address end;
                    if (sizeStr != null && !sizeStr.isEmpty()) {
                        int size = Integer.parseInt(sizeStr);
                        end = start.add(size - 1);
                    } else {
                        Data data = listing.getDataAt(start);
                        if (data == null) {
                            data = listing.getDataContaining(start);
                        }
                        if (data != null) {
                            end = start.add(data.getLength() - 1);
                        } else {
                            end = start;
                        }
                    }

                    listing.clearCodeUnits(start, end, false);
                    success = true;
                    result.set("Cleared data from " + start + " to " + end);
                } catch (Exception e) {
                    Msg.error(this, "Error clearing data", e);
                    result.set("Error clearing data: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute clear data on Swing thread", e);
        }

        return result.get();
    }

    private String defineData(String addressStr, String dataTypeName, String label) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (dataTypeName == null || dataTypeName.isEmpty()) return "Data type is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to define data");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Define data");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = resolveDataType(dtm, dataTypeName);

                    program.getListing().createData(addr, dt);

                    if (label != null && !label.isEmpty()) {
                        program.getSymbolTable().createLabel(addr, label, SourceType.USER_DEFINED);
                    }

                    success = true;
                    result.set("Defined " + dataTypeName + " at " + addr +
                              (label != null && !label.isEmpty() ? " with label " + label : ""));
                } catch (Exception e) {
                    Msg.error(this, "Error defining data", e);
                    result.set("Error defining data: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute define data on Swing thread", e);
        }

        return result.get();
    }

    private String defineDataBatch(String jsonBody) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to define data batch");

        try {
            JsonArray items = JsonParser.parseString(jsonBody).getAsJsonArray();

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Define data batch");
                boolean success = false;
                int succeeded = 0;
                int failed = 0;
                StringBuilder errors = new StringBuilder();

                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    Listing listing = program.getListing();
                    SymbolTable symTable = program.getSymbolTable();

                    for (JsonElement el : items) {
                        JsonObject item = el.getAsJsonObject();
                        String addr = item.get("address").getAsString();
                        String typeName = item.get("data_type").getAsString();
                        String label = item.has("label") ? item.get("label").getAsString() : null;

                        try {
                            Address address = program.getAddressFactory().getAddress(addr);
                            DataType dt = resolveDataType(dtm, typeName);
                            listing.createData(address, dt);

                            if (label != null && !label.isEmpty()) {
                                symTable.createLabel(address, label, SourceType.USER_DEFINED);
                            }
                            succeeded++;
                        } catch (Exception e) {
                            failed++;
                            errors.append(addr).append(": ").append(e.getMessage()).append("\n");
                        }
                    }

                    success = succeeded > 0;
                    result.set("Total: " + items.size() + ", Succeeded: " + succeeded +
                              ", Failed: " + failed +
                              (errors.length() > 0 ? "\nErrors:\n" + errors : ""));
                } catch (Exception e) {
                    Msg.error(this, "Error in define data batch", e);
                    result.set("Error in batch: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    private String readBytes(String addressStr, String lengthStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (lengthStr == null || lengthStr.isEmpty()) return "Length is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            int length = Integer.parseInt(lengthStr);
            byte[] bytes = new byte[length];
            program.getMemory().getBytes(addr, bytes);

            StringBuilder hex = new StringBuilder();
            for (byte b : bytes) {
                hex.append(String.format("%02x", b & 0xFF));
            }
            return hex.toString();
        } catch (Exception e) {
            return "Error reading bytes: " + e.getMessage();
        }
    }

    private String getDataAt(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Listing listing = program.getListing();

            Data data = listing.getDataAt(addr);
            String matchType = "exact";
            if (data == null) {
                data = listing.getDataContaining(addr);
                matchType = "containing";
            }

            if (data == null) {
                return "No data defined at " + addressStr;
            }

            StringBuilder sb = new StringBuilder();
            sb.append("Address: ").append(data.getAddress()).append("\n");
            sb.append("Match: ").append(matchType).append("\n");
            sb.append("Type: ").append(data.getDataType().getName()).append("\n");
            sb.append("Size: ").append(data.getLength()).append(" bytes\n");
            sb.append("Value: ").append(data.getDefaultValueRepresentation()).append("\n");

            Symbol[] symbols = program.getSymbolTable().getSymbols(data.getAddress());
            if (symbols.length > 0) {
                sb.append("Label: ").append(symbols[0].getName()).append("\n");
            }

            if ("containing".equals(matchType)) {
                long offset = addr.subtract(data.getAddress());
                sb.append("Offset within item: ").append(offset).append("\n");
            }

            return sb.toString();
        } catch (Exception e) {
            return "Error getting data: " + e.getMessage();
        }
    }

    private String batchRenameFunctions(String jsonBody) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to batch rename");

        try {
            JsonArray items = JsonParser.parseString(jsonBody).getAsJsonArray();

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch rename functions");
                boolean success = false;
                int succeeded = 0;
                int failed = 0;
                StringBuilder errors = new StringBuilder();

                try {
                    for (JsonElement el : items) {
                        JsonObject item = el.getAsJsonObject();
                        String addr = item.get("address").getAsString();
                        String newName = item.get("new_name").getAsString();

                        try {
                            Address address = program.getAddressFactory().getAddress(addr);
                            Function func = getFunctionForAddress(program, address);
                            if (func == null) {
                                failed++;
                                errors.append(addr).append(": No function at address\n");
                                continue;
                            }
                            func.setName(newName, SourceType.USER_DEFINED);
                            succeeded++;
                        } catch (Exception e) {
                            failed++;
                            errors.append(addr).append(": ").append(e.getMessage()).append("\n");
                        }
                    }

                    success = succeeded > 0;
                    result.set("Total: " + items.size() + ", Succeeded: " + succeeded +
                              ", Failed: " + failed +
                              (errors.length() > 0 ? "\nErrors:\n" + errors : ""));
                } catch (Exception e) {
                    Msg.error(this, "Error in batch rename", e);
                    result.set("Error in batch: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    private String batchRenameData(String jsonBody) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to batch rename data");

        try {
            JsonArray items = JsonParser.parseString(jsonBody).getAsJsonArray();

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch rename data");
                boolean success = false;
                int succeeded = 0;
                int failed = 0;
                StringBuilder errors = new StringBuilder();

                try {
                    SymbolTable symTable = program.getSymbolTable();

                    for (JsonElement el : items) {
                        JsonObject item = el.getAsJsonObject();
                        String addrStr = item.get("address").getAsString();
                        String newName = item.get("new_name").getAsString();

                        try {
                            Address addr = program.getAddressFactory().getAddress(addrStr);
                            Symbol symbol = symTable.getPrimarySymbol(addr);
                            if (symbol != null) {
                                symbol.setName(newName, SourceType.USER_DEFINED);
                            } else {
                                symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                            }
                            succeeded++;
                        } catch (Exception e) {
                            failed++;
                            errors.append(addrStr).append(": ").append(e.getMessage()).append("\n");
                        }
                    }

                    success = succeeded > 0;
                    result.set("Total: " + items.size() + ", Succeeded: " + succeeded +
                              ", Failed: " + failed +
                              (errors.length() > 0 ? "\nErrors:\n" + errors : ""));
                } catch (Exception e) {
                    Msg.error(this, "Error in batch rename data", e);
                    result.set("Error in batch: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    private String batchCreateFunction(String jsonBody) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to batch create functions");

        try {
            JsonArray items = JsonParser.parseString(jsonBody).getAsJsonArray();

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch create functions");
                boolean success = false;
                int created = 0;
                int renamed = 0;
                int failed = 0;
                StringBuilder errors = new StringBuilder();

                try {
                    for (JsonElement el : items) {
                        JsonObject item = el.getAsJsonObject();
                        String addrStr = item.get("address").getAsString();
                        String name = item.has("name") && !item.get("name").isJsonNull()
                                ? item.get("name").getAsString() : null;

                        try {
                            Address addr = program.getAddressFactory().getAddress(addrStr);
                            if (addr == null) {
                                failed++;
                                errors.append(addrStr).append(": Invalid address\n");
                                continue;
                            }
                            Function existing = program.getFunctionManager().getFunctionAt(addr);
                            if (existing != null) {
                                if (name != null && !name.isEmpty()) {
                                    existing.setName(name, SourceType.USER_DEFINED);
                                    renamed++;
                                } else {
                                    // Treat "already exists, no rename requested" as success.
                                    renamed++;
                                }
                                continue;
                            }
                            AddressSet body = new AddressSet(addr, addr);
                            String funcName = (name != null && !name.isEmpty())
                                    ? name : ("FUN_" + addr.toString());
                            Function func = program.getFunctionManager().createFunction(
                                    funcName, addr, body, SourceType.USER_DEFINED);
                            if (func != null) {
                                created++;
                            } else {
                                failed++;
                                errors.append(addrStr).append(": createFunction returned null\n");
                            }
                        } catch (Exception e) {
                            failed++;
                            errors.append(addrStr).append(": ").append(e.getMessage()).append("\n");
                        }
                    }

                    success = (created + renamed) > 0;
                    result.set("Total: " + items.size() +
                              ", Created: " + created +
                              ", Already-existed: " + renamed +
                              ", Failed: " + failed +
                              (errors.length() > 0 ? "\nErrors:\n" + errors : ""));
                } catch (Exception e) {
                    Msg.error(this, "Error in batch create functions", e);
                    result.set("Error in batch: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    private String batchSetComments(String jsonBody) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to batch set comments");

        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            String commentTypeStr = body.has("comment_type") ? body.get("comment_type").getAsString() : "decompiler";
            int commentType = resolveCommentType(commentTypeStr);
            if (commentType < 0) {
                return "Invalid comment_type: " + commentTypeStr +
                    ". Supported: eol, pre, post, plate, repeatable, decompiler, disassembly";
            }
            JsonArray comments = body.getAsJsonArray("comments");

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch set comments");
                boolean success = false;
                int succeeded = 0;
                int failed = 0;
                StringBuilder errors = new StringBuilder();

                try {
                    Listing listing = program.getListing();

                    for (JsonElement el : comments) {
                        JsonObject item = el.getAsJsonObject();
                        String addr = item.get("address").getAsString();
                        String comment = item.get("comment").getAsString();

                        try {
                            Address address = program.getAddressFactory().getAddress(addr);
                            listing.setComment(address, commentType, comment);
                            succeeded++;
                        } catch (Exception e) {
                            failed++;
                            errors.append(addr).append(": ").append(e.getMessage()).append("\n");
                        }
                    }

                    success = succeeded > 0;
                    result.set("Total: " + comments.size() + ", Succeeded: " + succeeded +
                              ", Failed: " + failed +
                              (errors.length() > 0 ? "\nErrors:\n" + errors : ""));
                } catch (Exception e) {
                    Msg.error(this, "Error in batch set comments", e);
                    result.set("Error in batch: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    private String createLabel(String addressStr, String name, String namespace) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (name == null || name.isEmpty()) return "Name is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create label");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create label");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    SymbolTable symTable = program.getSymbolTable();

                    Namespace ns = null;
                    if (namespace != null && !namespace.isEmpty()) {
                        ns = symTable.getNamespace(namespace, null);
                        if (ns == null) {
                            ns = symTable.createNameSpace(null, namespace, SourceType.USER_DEFINED);
                        }
                    }

                    if (ns != null) {
                        symTable.createLabel(addr, name, ns, SourceType.USER_DEFINED);
                    } else {
                        symTable.createLabel(addr, name, SourceType.USER_DEFINED);
                    }

                    success = true;
                    result.set("Label '" + name + "' created at " + addr);
                } catch (Exception e) {
                    Msg.error(this, "Error creating label", e);
                    result.set("Error creating label: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute create label on Swing thread", e);
        }

        return result.get();
    }

    private String createEnum(String jsonBody) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create enum");

        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            String name = body.get("name").getAsString();
            int size = body.has("size") ? body.get("size").getAsInt() : 4;
            JsonArray values = body.getAsJsonArray("values");
            String categoryPathStr = body.has("category_path")
                    ? body.get("category_path").getAsString() : null;

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create enum");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    CategoryPath catPath = (categoryPathStr != null && !categoryPathStr.isEmpty())
                            ? new CategoryPath(categoryPathStr)
                            : CategoryPath.ROOT;
                    EnumDataType enumType = new EnumDataType(catPath, name, size, dtm);

                    for (JsonElement el : values) {
                        JsonObject entry = el.getAsJsonObject();
                        String entryName = entry.get("name").getAsString();
                        long entryValue = entry.get("value").getAsLong();
                        enumType.add(entryName, entryValue);
                    }

                    dtm.addDataType(enumType, DataTypeConflictHandler.REPLACE_HANDLER);
                    success = true;
                    result.set("Enum '" + name + "' created with " + values.size() + " values");
                } catch (Exception e) {
                    Msg.error(this, "Error creating enum", e);
                    result.set("Error creating enum: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    private String createStruct(String jsonBody) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create struct");

        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            String name = body.get("name").getAsString();
            JsonArray fields = body.getAsJsonArray("fields");
            String categoryPathStr = body.has("category_path")
                    ? body.get("category_path").getAsString() : null;

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create struct");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    CategoryPath catPath = (categoryPathStr != null && !categoryPathStr.isEmpty())
                            ? new CategoryPath(categoryPathStr)
                            : CategoryPath.ROOT;
                    StructureDataType struct = new StructureDataType(catPath, name, 0, dtm);

                    for (JsonElement el : fields) {
                        JsonObject field = el.getAsJsonObject();
                        String fieldName = field.get("name").getAsString();
                        String fieldType = field.get("type").getAsString();
                        int fieldSize = field.has("size") ? field.get("size").getAsInt() : 0;

                        DataType dt = resolveDataType(dtm, fieldType);
                        if (fieldSize > 0) {
                            struct.add(dt, fieldSize, fieldName, null);
                        } else {
                            struct.add(dt, dt.getLength(), fieldName, null);
                        }
                    }

                    dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
                    success = true;
                    result.set("Struct '" + name + "' created with " + fields.size() +
                              " fields, total size: " + struct.getLength() + " bytes");
                } catch (Exception e) {
                    Msg.error(this, "Error creating struct", e);
                    result.set("Error creating struct: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    /**
     * Create a function definition data type in the Data Type Manager.
     * This creates a reusable type (like a typedef for a function pointer)
     * that can be referenced by struct fields (e.g. VTable entries).
     *
     * JSON body:
     * {
     *   "name": "MyCallback",                          // required
     *   "return_type": "int",                           // optional, default "void"
     *   "parameters": [                                 // optional
     *     {"name": "param1", "type": "int"},
     *     {"name": "param2", "type": "char *"}
     *   ],
     *   "calling_convention": "default",                // optional
     *   "category_path": "/VTables"                     // optional, DTM category
     * }
     */
    private String createFunctionDefinition(String jsonBody) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create function definition");

        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            String name = body.get("name").getAsString();
            String returnTypeName = body.has("return_type") ? body.get("return_type").getAsString() : "void";
            JsonArray params = body.has("parameters") ? body.getAsJsonArray("parameters") : new JsonArray();
            String callingConvention = body.has("calling_convention")
                    ? body.get("calling_convention").getAsString() : null;
            String categoryPathStr = body.has("category_path")
                    ? body.get("category_path").getAsString() : null;

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create function definition");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Resolve the category path
                    CategoryPath catPath = (categoryPathStr != null && !categoryPathStr.isEmpty())
                            ? new CategoryPath(categoryPathStr)
                            : CategoryPath.ROOT;

                    // Check for an existing function definition to update in-place
                    // (preserves references from struct fields, etc.)
                    DataType existing = findDataTypeByNameInAllCategories(dtm, name);
                    boolean isUpdate = false;
                    FunctionDefinitionDataType funcDef;

                    if (existing instanceof FunctionDefinitionDataType
                            && existing.getCategoryPath().equals(catPath)) {
                        // Update existing definition in-place
                        funcDef = (FunctionDefinitionDataType) existing;
                        isUpdate = true;
                    } else {
                        // Create new function definition
                        funcDef = new FunctionDefinitionDataType(catPath, name, dtm);
                    }

                    // Set return type
                    DataType returnType = resolveDataType(dtm, returnTypeName);
                    funcDef.setReturnType(returnType);

                    // Set parameters
                    if (params.size() > 0) {
                        ParameterDefinition[] paramDefs = new ParameterDefinition[params.size()];
                        for (int i = 0; i < params.size(); i++) {
                            JsonObject param = params.get(i).getAsJsonObject();
                            String paramName = param.has("name") ? param.get("name").getAsString() : ("param_" + i);
                            String paramTypeName = param.get("type").getAsString();
                            DataType paramType = resolveDataType(dtm, paramTypeName);
                            paramDefs[i] = new ParameterDefinitionImpl(paramName, paramType, null);
                        }
                        funcDef.setArguments(paramDefs);
                    } else {
                        // Explicitly clear parameters when none are provided during an update
                        funcDef.setArguments(new ParameterDefinition[0]);
                    }

                    // Set calling convention if specified
                    if (callingConvention != null && !callingConvention.isEmpty()
                            && !callingConvention.equalsIgnoreCase("default")) {
                        try {
                            funcDef.setGenericCallingConvention(
                                GenericCallingConvention.getGenericCallingConvention(callingConvention));
                        } catch (Exception e) {
                            Msg.warn(this, "Unknown calling convention '" + callingConvention
                                    + "', using default. Error: " + e.getMessage());
                        }
                    }

                    // Add to the data type manager (only needed for new definitions)
                    DataType added;
                    if (isUpdate) {
                        added = funcDef;
                    } else {
                        added = dtm.addDataType(funcDef, DataTypeConflictHandler.REPLACE_HANDLER);
                    }

                    success = true;
                    String verb = isUpdate ? "updated" : "created";
                    result.set("Function definition '" + name + "' " + verb + " at " + added.getPathName()
                            + " — signature: " + added.toString());
                } catch (Exception e) {
                    Msg.error(this, "Error creating function definition", e);
                    result.set("Error creating function definition: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    /**
     * Look up a component of a structure by field name, by the auto-generated
     * name Ghidra shows for unnamed fields ("field&lt;ordinal&gt;_0x&lt;offset&gt;"),
     * or by a hex offset string such as "0x8".
     *
     * @return the matching component, or null if no field matches
     */
    private DataTypeComponent findStructComponent(ghidra.program.model.data.Structure struct,
                                                  String fieldName) {
        if (fieldName == null || fieldName.isEmpty()) return null;

        DataTypeComponent[] comps = struct.getDefinedComponents();
        for (DataTypeComponent comp : comps) {
            String compFieldName = comp.getFieldName();
            // Match explicit field names directly
            if (compFieldName != null) {
                if (fieldName.equals(compFieldName)) return comp;
                continue;
            }
            // For auto-generated names (getFieldName() returns null),
            // Ghidra displays them as "field<ordinal>_0x<offset>".
            String autoName = "field" + comp.getOrdinal() +
                              "_0x" + Integer.toHexString(comp.getOffset());
            if (fieldName.equals(autoName)) return comp;
        }

        // Fall back to matching by offset when the name looks like a hex offset
        // (e.g. "0x4"). Plain integers are not matched, to avoid ambiguity with
        // field names that happen to be numeric.
        int offsetVal = parseHexOffset(fieldName);
        if (offsetVal >= 0) {
            for (DataTypeComponent comp : comps) {
                if (comp.getOffset() == offsetVal) return comp;
            }
        }
        return null;
    }

    /**
     * Parse a hex offset string such as "0x18". Returns -1 when the value is not
     * a "0x"-prefixed non-negative hex number.
     */
    private int parseHexOffset(String value) {
        if (value == null) return -1;
        String trimmed = value.trim();
        if (!trimmed.startsWith("0x") && !trimmed.startsWith("0X")) return -1;
        try {
            int parsed = Integer.parseInt(trimmed.substring(2), 16);
            return parsed >= 0 ? parsed : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /**
     * Build a comma-separated list of the field names of a structure, using the
     * auto-generated "field&lt;ordinal&gt;_0x&lt;offset&gt;" name for unnamed fields.
     * Used to make "field not found" errors actionable.
     */
    private String listStructFieldNames(ghidra.program.model.data.Structure struct) {
        StringBuilder fieldList = new StringBuilder();
        for (DataTypeComponent comp : struct.getDefinedComponents()) {
            String name = comp.getFieldName();
            if (name == null) {
                name = "field" + comp.getOrdinal() +
                       "_0x" + Integer.toHexString(comp.getOffset());
            }
            if (fieldList.length() > 0) fieldList.append(", ");
            fieldList.append(name);
        }
        return fieldList.length() > 0 ? fieldList.toString() : "(none)";
    }

    /**
     * Add one or more fields to an existing structure, in place, so that all
     * existing references to the struct (variables, applied data, other structs)
     * are preserved. This is the counterpart to {@link #updateStructField}, which
     * can only modify fields that already exist.
     *
     * JSON body:
     * {
     *   "struct_name": "MyStruct",         // required
     *   "fields": [                        // required, non-empty
     *     {
     *       "name": "count",               // required
     *       "type": "int",                 // required
     *       "size": 4,                     // optional, defaults to the type's length
     *       "offset": "0x10",              // optional, hex or decimal; append if omitted
     *       "comment": "..."               // optional
     *     }
     *   ],
     *   "overwrite": false                 // optional, allow replacing defined fields
     * }
     *
     * Fields without an offset are appended to the end of the struct. Fields with
     * an offset are placed at that offset, consuming undefined padding bytes; the
     * struct's overall length is left unchanged. Placing a field over an existing
     * defined field requires "overwrite": true.
     *
     * All fields are added in a single transaction: if any field fails, the whole
     * transaction is rolled back so the struct is never left half-updated.
     */
    private String addStructFields(String jsonBody) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to add struct fields");

        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            if (!body.has("struct_name")) return "'struct_name' is required";
            if (!body.has("fields")) return "'fields' is required";
            String structName = body.get("struct_name").getAsString();
            JsonArray fields = body.getAsJsonArray("fields");
            boolean overwrite = body.has("overwrite") && body.get("overwrite").getAsBoolean();

            if (fields.size() == 0) return "'fields' must contain at least one field";

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Add struct fields");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType existing = findDataTypeByNameInAllCategories(dtm, structName);
                    if (!(existing instanceof ghidra.program.model.data.Structure)) {
                        result.set(existing == null
                                ? "Struct '" + structName + "' not found"
                                : "Data type '" + structName + "' is not a structure");
                        return;
                    }
                    ghidra.program.model.data.Structure struct =
                        (ghidra.program.model.data.Structure) existing;

                    StringBuilder added = new StringBuilder();
                    for (JsonElement el : fields) {
                        JsonObject field = el.getAsJsonObject();
                        if (!field.has("name") || !field.has("type")) {
                            result.set("Each field requires both 'name' and 'type'");
                            return;
                        }
                        String fieldName = field.get("name").getAsString();
                        String fieldType = field.get("type").getAsString();
                        String comment = field.has("comment") ? field.get("comment").getAsString() : null;

                        DataType dt = resolveDataType(dtm, fieldType);
                        int fieldSize = field.has("size") ? field.get("size").getAsInt() : dt.getLength();
                        if (fieldSize <= 0) {
                            result.set("Cannot determine a size for field '" + fieldName +
                                       "' of type '" + fieldType + "'; specify an explicit 'size'");
                            return;
                        }

                        // Reject duplicate field names up front so the struct keeps
                        // unique, addressable field names.
                        if (findStructComponent(struct, fieldName) != null) {
                            result.set("Struct '" + structName + "' already has a field named '" +
                                       fieldName + "'; use update_struct_field to change it");
                            return;
                        }

                        DataTypeComponent comp;
                        if (field.has("offset")) {
                            // In a packed struct Ghidra computes every offset itself and
                            // repacks after each edit, so an explicit offset cannot be honoured.
                            if (struct.isPackingEnabled()) {
                                result.set("Struct '" + structName + "' has packing enabled, so field " +
                                           "offsets are computed by Ghidra and cannot be set explicitly. " +
                                           "Add field '" + fieldName + "' without an offset to append it.");
                                return;
                            }
                            String offsetStr = field.get("offset").getAsString();
                            int offset = parseHexOffset(offsetStr);
                            if (offset < 0) {
                                try {
                                    offset = Integer.parseInt(offsetStr.trim());
                                } catch (NumberFormatException e) {
                                    offset = -1;
                                }
                            }
                            if (offset < 0) {
                                result.set("Invalid offset '" + offsetStr + "' for field '" + fieldName +
                                           "'; expected a hex value like \"0x10\" or a decimal value");
                                return;
                            }

                            // Refuse to silently clobber existing defined fields.
                            if (!overwrite) {
                                String clobbered = findDefinedFieldsInRange(struct, offset, fieldSize);
                                if (clobbered != null) {
                                    result.set("Field '" + fieldName + "' at offset 0x" +
                                               Integer.toHexString(offset) + " (" + fieldSize +
                                               " bytes) would overwrite existing field(s): " + clobbered +
                                               ". Pass overwrite=true to replace them.");
                                    return;
                                }
                            }

                            // Grow the struct if the new field extends past its end,
                            // otherwise replaceAtOffset would fail.
                            int required = offset + fieldSize;
                            if (required > struct.getLength()) {
                                struct.growStructure(required - struct.getLength());
                            }
                            comp = struct.replaceAtOffset(offset, dt, fieldSize, fieldName, comment);
                        } else {
                            comp = struct.add(dt, fieldSize, fieldName, comment);
                        }

                        if (added.length() > 0) added.append(", ");
                        added.append(fieldName)
                             .append(" @0x").append(Integer.toHexString(comp.getOffset()))
                             .append(" (").append(dt.getName())
                             .append(", ").append(comp.getLength()).append(" bytes)");
                    }

                    success = true;
                    result.set("Added " + fields.size() + " field(s) to '" + structName + "': " + added +
                               ". Struct size is now " + struct.getLength() + " bytes");
                } catch (Exception e) {
                    Msg.error(this, "Error adding struct fields", e);
                    result.set("Error adding struct fields: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    /**
     * List the defined (non-undefined) fields of a structure that overlap the
     * byte range [offset, offset + length).
     *
     * @return a comma-separated description of the overlapping fields, or null
     *         if the range only covers undefined/padding bytes
     */
    private String findDefinedFieldsInRange(ghidra.program.model.data.Structure struct,
                                            int offset, int length) {
        StringBuilder sb = new StringBuilder();
        for (DataTypeComponent comp : struct.getDefinedComponents()) {
            if (comp.isUndefined()) continue;
            // Overlap test between [offset, offset+length) and the component's extent
            if (comp.getOffset() < offset + length && offset <= comp.getEndOffset()) {
                String name = comp.getFieldName();
                if (name == null) {
                    name = "field" + comp.getOrdinal() +
                           "_0x" + Integer.toHexString(comp.getOffset());
                }
                if (sb.length() > 0) sb.append(", ");
                sb.append(name).append(" @0x").append(Integer.toHexString(comp.getOffset()));
            }
        }
        return sb.length() > 0 ? sb.toString() : null;
    }

    /**
     * Delete a field from an existing structure, in place.
     *
     * JSON body:
     * {
     *   "struct_name": "MyStruct",   // required
     *   "field_name": "count",       // required; name, auto-name, or hex offset
     *   "shrink": false              // optional; see below
     * }
     *
     * By default the field's bytes are cleared to undefined, which keeps every
     * later field at its current offset — the right behaviour when the struct
     * mirrors a real memory layout. With "shrink": true the component is removed
     * outright and all later fields shift up, shrinking the struct.
     */
    private String deleteStructField(String jsonBody) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to delete struct field");

        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            if (!body.has("struct_name")) return "'struct_name' is required";
            if (!body.has("field_name")) return "'field_name' is required";
            String structName = body.get("struct_name").getAsString();
            String fieldName = body.get("field_name").getAsString();
            boolean shrink = body.has("shrink") && body.get("shrink").getAsBoolean();

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Delete struct field");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType existing = findDataTypeByNameInAllCategories(dtm, structName);
                    if (!(existing instanceof ghidra.program.model.data.Structure)) {
                        result.set(existing == null
                                ? "Struct '" + structName + "' not found"
                                : "Data type '" + structName + "' is not a structure");
                        return;
                    }
                    ghidra.program.model.data.Structure struct =
                        (ghidra.program.model.data.Structure) existing;

                    DataTypeComponent target = findStructComponent(struct, fieldName);
                    if (target == null) {
                        result.set("Field '" + fieldName + "' not found in struct '" + structName +
                                   "'. Available fields: " + listStructFieldNames(struct));
                        return;
                    }

                    int ordinal = target.getOrdinal();
                    int offset = target.getOffset();
                    int length = target.getLength();

                    // A packed struct repacks after every edit, so its fields always shift
                    // up on removal; clearing to undefined padding is not possible there.
                    boolean packed = struct.isPackingEnabled();
                    if (shrink || packed) {
                        struct.delete(ordinal);
                    } else {
                        struct.clearComponent(ordinal);
                    }

                    success = true;
                    String effect;
                    if (packed) {
                        effect = "; struct is packed, so later fields shifted up";
                    } else if (shrink) {
                        effect = "; later fields shifted up";
                    } else {
                        effect = "; bytes left undefined";
                    }
                    result.set("Deleted field '" + fieldName + "' (offset 0x" +
                               Integer.toHexString(offset) + ", " + length + " bytes) from '" +
                               structName + "'" + effect +
                               ". Struct size is now " + struct.getLength() + " bytes");
                } catch (Exception e) {
                    Msg.error(this, "Error deleting struct field", e);
                    result.set("Error deleting struct field: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    private String updateStructField(String jsonBody) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to update struct field");

        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            String structName = body.get("struct_name").getAsString();
            String fieldName = body.get("field_name").getAsString();
            String newType = body.has("new_type") ? body.get("new_type").getAsString() : null;
            String newName = body.has("new_name") ? body.get("new_name").getAsString() : null;

            if (newType == null && newName == null) {
                return "At least one of 'new_type' or 'new_name' must be provided";
            }

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Update struct field");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType existing = findDataTypeByNameInAllCategories(dtm, structName);
                    if (existing == null || !(existing instanceof ghidra.program.model.data.Structure)) {
                        result.set("Struct '" + structName + "' not found");
                        return;
                    }
                    ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) existing;
                    DataTypeComponent target = findStructComponent(struct, fieldName);
                    if (target == null) {
                        result.set("Field '" + fieldName + "' not found in struct '" + structName +
                                   "'. Available fields: " + listStructFieldNames(struct));
                        return;
                    }
                    int targetIdx = target.getOrdinal();
                    int targetOffset = target.getOffset();
                    DataType oldDt = target.getDataType();
                    DataType effectiveDt = (newType != null) ? resolveDataType(dtm, newType) : oldDt;
                    String effectiveName = (newName != null) ? newName : fieldName;
                    struct.replace(targetIdx, effectiveDt, effectiveDt.getLength(), effectiveName, null);
                    success = true;
                    StringBuilder msg = new StringBuilder("Updated field '" + fieldName + "' in '" + structName + "'");
                    if (newType != null) {
                        msg.append(" type -> '" + effectiveDt.getName() + "'");
                    }
                    if (newName != null) {
                        msg.append(" name -> '" + newName + "'");
                    }
                    msg.append(" (offset 0x" + Integer.toHexString(targetOffset) +
                               ", size " + effectiveDt.getLength() + ")");
                    result.set(msg.toString());
                } catch (Exception e) {
                    Msg.error(this, "Error updating struct field", e);
                    result.set("Error: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    /**
     * Rename an existing data type (struct, enum, typedef, union, function definition, etc.)
     * found in the Data Type Manager. Looks the type up by its current name in all categories.
     */
    private String renameDataType(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (oldName == null || oldName.isEmpty()) return "old_name is required";
        if (newName == null || newName.isEmpty()) return "new_name is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to rename data type");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data type");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = findDataTypeByNameInAllCategories(dtm, oldName);
                    if (dt == null) {
                        result.set("Data type '" + oldName + "' not found");
                        return;
                    }
                    // Reject if a type with the new name already exists in the same category
                    DataType existing = dtm.getDataType(dt.getCategoryPath(), newName);
                    if (existing != null) {
                        result.set("A data type named '" + newName + "' already exists in category '" +
                                   dt.getCategoryPath().getPath() + "'");
                        return;
                    }
                    String oldPath = dt.getPathName();
                    dt.setName(newName);
                    success = true;
                    result.set("Renamed data type '" + oldPath + "' to '" + dt.getPathName() + "'");
                } catch (InvalidNameException e) {
                    result.set("Invalid name '" + newName + "': " + e.getMessage());
                } catch (DuplicateNameException e) {
                    result.set("A data type named '" + newName + "' already exists: " + e.getMessage());
                } catch (Exception e) {
                    Msg.error(this, "Error renaming data type", e);
                    result.set("Error: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error: " + e.getMessage());
        }

        return result.get();
    }

    /**
     * Move an existing data type (struct, enum, typedef, union, function definition, etc.)
     * to a different category in the Data Type Manager. The category is created if it
     * does not already exist.
     */
    private String moveDataType(String dataTypeName, String categoryPathStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (dataTypeName == null || dataTypeName.isEmpty()) return "data_type_name is required";
        if (categoryPathStr == null || categoryPathStr.isEmpty()) return "category_path is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to move data type");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Move data type");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = findDataTypeByNameInAllCategories(dtm, dataTypeName);
                    if (dt == null) {
                        result.set("Data type '" + dataTypeName + "' not found");
                        return;
                    }
                    CategoryPath newCatPath = new CategoryPath(categoryPathStr);
                    CategoryPath oldCatPath = dt.getCategoryPath();

                    if (oldCatPath.equals(newCatPath)) {
                        result.set("Data type '" + dataTypeName + "' is already in category '" +
                                   categoryPathStr + "'");
                        return;
                    }

                    // Create the target category if it does not exist, then move
                    ghidra.program.model.data.Category targetCategory =
                        dtm.createCategory(newCatPath);
                    targetCategory.moveDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);

                    success = true;
                    result.set("Moved data type '" + dataTypeName + "' from '" +
                               oldCatPath.getPath() + "' to '" + categoryPathStr + "'");
                } catch (Exception e) {
                    Msg.error(this, "Error moving data type", e);
                    result.set("Error: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error: " + e.getMessage());
        }

        return result.get();
    }

    /**
     * Rename a class/namespace symbol in the symbol table. Searches all symbols
     * for a namespace (class, namespace, etc.) whose name matches oldName and
     * renames its underlying symbol. This covers C++ classes and other namespaces
     * enumerated by list_classes / list_namespaces.
     */
    private String renameNamespace(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (oldName == null || oldName.isEmpty()) return "old_name is required";
        if (newName == null || newName.isEmpty()) return "new_name is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to rename namespace");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename namespace");
                boolean success = false;
                try {
                    SymbolTable symTable = program.getSymbolTable();

                    // Find the namespace by name. Try a direct lookup in the global
                    // namespace first, then fall back to scanning all symbols.
                    Namespace ns = symTable.getNamespace(oldName, null);
                    if (ns == null) {
                        for (Symbol symbol : symTable.getAllSymbols(true)) {
                            Namespace candidate = symbol.getParentNamespace();
                            if (candidate != null && !candidate.isGlobal()
                                    && candidate.getName().equals(oldName)) {
                                ns = candidate;
                                break;
                            }
                        }
                    }

                    if (ns == null || ns.isGlobal()) {
                        result.set("Namespace/class '" + oldName + "' not found");
                        return;
                    }

                    Symbol nsSymbol = ns.getSymbol();
                    if (nsSymbol == null) {
                        result.set("Namespace '" + oldName + "' has no renamable symbol");
                        return;
                    }

                    nsSymbol.setName(newName, SourceType.USER_DEFINED);
                    success = true;
                    result.set("Renamed namespace/class '" + oldName + "' to '" + newName + "'");
                } catch (InvalidInputException e) {
                    result.set("Invalid name '" + newName + "': " + e.getMessage());
                } catch (DuplicateNameException e) {
                    result.set("A namespace named '" + newName + "' already exists: " + e.getMessage());
                } catch (Exception e) {
                    Msg.error(this, "Error renaming namespace", e);
                    result.set("Error: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error: " + e.getMessage());
        }

        return result.get();
    }

    private String applyStruct(String addressStr, String structName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (structName == null || structName.isEmpty()) return "Struct name is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to apply struct");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Apply struct");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = findDataTypeByNameInAllCategories(dtm, structName);

                    if (dt == null) {
                        result.set("Struct '" + structName + "' not found");
                        return;
                    }

                    Listing listing = program.getListing();
                    // Clear existing data at the address range
                    listing.clearCodeUnits(addr, addr.add(dt.getLength() - 1), false);
                    listing.createData(addr, dt);

                    success = true;
                    result.set("Applied struct '" + structName + "' at " + addr +
                              " (" + dt.getLength() + " bytes)");
                } catch (Exception e) {
                    Msg.error(this, "Error applying struct", e);
                    result.set("Error applying struct: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute apply struct on Swing thread", e);
        }

        return result.get();
    }

    private String createFunctionAtAddress(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create function");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create function at address");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        result.set("Invalid address: " + addressStr);
                        return;
                    }
                    // Check if function already exists
                    Function existing = program.getFunctionManager().getFunctionAt(addr);
                    if (existing != null) {
                        // If a name is provided, rename it
                        if (name != null && !name.isEmpty()) {
                            existing.setName(name, SourceType.USER_DEFINED);
                            result.set("Function already existed at " + addressStr + ", renamed to " + name);
                        } else {
                            result.set("Function already exists at " + addressStr + ": " + existing.getName());
                        }
                        success = true;
                        return;
                    }
                    // Disassemble at the address first
                    ghidra.app.util.PseudoDisassembler pd = new ghidra.app.util.PseudoDisassembler(program);
                    // Create a minimal address set for the function
                    AddressSet body = new AddressSet(addr, addr);
                    String funcName = (name != null && !name.isEmpty()) ? name : ("FUN_" + addr.toString());
                    Function func = program.getFunctionManager().createFunction(
                        funcName, addr, body, SourceType.USER_DEFINED);
                    if (func != null) {
                        result.set("Function created at " + addressStr + " with name " + funcName);
                        success = true;
                    } else {
                        result.set("Failed to create function at " + addressStr);
                    }
                } catch (Exception e) {
                    result.set("Error creating function: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.set("Thread error: " + e.getMessage());
        }

        return result.get();
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Read raw request body as a string (for JSON endpoints).
     */
    private String readRequestBody(HttpExchange exchange) throws IOException {
        return new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm != null && pm.getCurrentProgram() != null) {
            return pm.getCurrentProgram();
        }
        // ProgramManager returns null when plugin is loaded via Code Browser
        // instead of a tool that directly provides ProgramManager. Fall back
        // to CodeViewerService which is always available in Code Browser.
        CodeViewerService cvs = tool.getService(CodeViewerService.class);
        if (cvs != null && cvs.getNavigatable() != null) {
            return cvs.getNavigatable().getProgram();
        }
        return null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    /**
     * Batch version of setPrimaryLabel. Accepts a JSON array of {address, name} objects.
     * All operations run in one Ghidra transaction.
     */
    private String batchSetPrimaryLabels(String jsonBody) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body required";

        AtomicReference<String> result = new AtomicReference<>("Failed");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch set primary labels");
                int succeeded = 0, failed = 0;
                StringBuilder errors = new StringBuilder();
                try {
                    com.google.gson.JsonArray arr =
                        com.google.gson.JsonParser.parseString(jsonBody).getAsJsonArray();
                    SymbolTable symTable = program.getSymbolTable();

                    for (com.google.gson.JsonElement el : arr) {
                        com.google.gson.JsonObject obj = el.getAsJsonObject();
                        String addrStr = obj.get("address").getAsString();
                        String name    = obj.get("name").getAsString();
                        try {
                            Address addr = program.getAddressFactory().getAddress(addrStr);
                            // Delete all existing user-defined labels at this address
                            for (Symbol sym : symTable.getSymbols(addr)) {
                                if (sym.getSource() == SourceType.USER_DEFINED) {
                                    sym.delete();
                                }
                            }
                            symTable.createLabel(addr, name, SourceType.USER_DEFINED);
                            succeeded++;
                        } catch (Exception e) {
                            failed++;
                            errors.append(addrStr).append(": ").append(e.getMessage()).append("\n");
                        }
                    }
                } catch (Exception e) {
                    Msg.error(this, "batchSetPrimaryLabels parse error", e);
                } finally {
                    program.endTransaction(tx, true);
                }
                result.set("Total: " + (succeeded + failed) + ", Succeeded: " + succeeded +
                    ", Failed: " + failed +
                    (errors.length() > 0 ? "\nErrors:\n" + errors : ""));
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute batch_set_primary_labels on Swing thread", e);
        }

        return result.get();
    }

    /**
     * Set the primary label at an address to the given name.
     * All existing labels at that address are deleted first, then the new name is created as primary.
     * POST params: address, name
     */
    private String setPrimaryLabel(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (name == null || name.isEmpty()) return "Name is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to set primary label");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set primary label");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    SymbolTable symTable = program.getSymbolTable();

                    // Delete all existing user-defined labels at this address
                    Symbol[] symbols = symTable.getSymbols(addr);
                    for (Symbol sym : symbols) {
                        if (sym.getSource() == SourceType.USER_DEFINED) {
                            sym.delete();
                        }
                    }

                    // Create the new primary label
                    symTable.createLabel(addr, name, SourceType.USER_DEFINED);
                    success = true;
                    result.set("Primary label '" + name + "' set at " + addr);
                } catch (Exception e) {
                    Msg.error(this, "Error setting primary label", e);
                    result.set("Error: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set_primary_label on Swing thread", e);
        }

        return result.get();
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
