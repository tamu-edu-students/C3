# This script analyzes obfuscated strings in binaries to detect transformations, 
# decode them, and predict possible outputs. It builds a call graph to track string 
# manipulations and generates reports for further analysis.
#@author 
#@category StringAnalysis
#@keybinding 
#@menupath Tools.String Analysis.String Obfuscation Resolver
#@toolbar string_analysis.png
#@runtime Jython


from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.data import DataUtilities
from ghidra.app.decompiler import DecompInterface
import base64
import math
import string

#String detection
def get_memory_data(address, size):
    """
    Reads raw data from memory starting at the specified address.
    :param address: The starting address (Address object) in memory.
    :param size: Number of bytes to read.
    :return: A list of byte values.
    """
    try:
        memory = currentProgram.getMemory()
        data = []
        for i in range(size):
            current_address = address.add(i)
            # Ensure the address is valid
            if not memory.contains(current_address):
                print("[DEBUG] Address {} is out of bounds.".format(current_address))
                break
            byte = memory.getByte(current_address)
            data.append(byte & 0xFF)  # Convert to unsigned byte
        return data
    except Exception as e:
        print("[ERROR] Error reading memory at {}: {}".format(address, e))
        return []

def autodetect_obfuscated_strings():
    """
    Attempts to autodetect potential obfuscated strings in the program's memory.
    :return: A list of potential addresses for obfuscated strings.
    """
    memory = currentProgram.getMemory()
    detected_strings = []
    print("[INFO] Autodetecting obfuscated strings in memory...")

    # Adjust the chunk size based on block size and typical string length
    DEFAULT_CHUNK_SIZE = 64  # Start with 64 bytes for better efficiency

    # Iterate over memory blocks
    for block in memory.getBlocks():
        if block.isInitialized():
            try:
                start = block.getStart()
                end = block.getEnd()
                address = start

                while address.compareTo(end) < 0:
                    # Adjust chunk size to stay within bounds
                    remaining_size = end.subtract(address) + 1
                    chunk_size = min(DEFAULT_CHUNK_SIZE, remaining_size)

                    # Read memory chunk
                    data = get_memory_data(address, chunk_size)
                    if not data:
                        address = address.add(chunk_size)  # Move to next chunk
                        continue

                    # Detect obfuscated string in the current chunk
                    if is_potentially_obfuscated(data):
                        detected_strings.append(address)
                        print("[INFO] Potential obfuscated string found at: {}".format(address))

                        # Expand detection to adjacent memory regions
                        address = expand_detected_region(address, block, chunk_size)
                    else:
                        address = address.add(chunk_size)  # Move to next chunk

            except Exception as e:
                print("[ERROR] Error scanning block {}: {}".format(block.getName(), e))

    # Combine overlapping or adjacent results
    detected_strings = merge_adjacent_addresses(detected_strings)
    print("[INFO] Detection complete. {} potential strings found.".format(len(detected_strings)))
    return detected_strings

def expand_detected_region(address, block, chunk_size):
    """
    Expands the detected region to include adjacent memory that may also be part of the string.
    :param address: Starting address of the detected string.
    :param block: Memory block being analyzed.
    :param chunk_size: Current chunk size.
    :return: New end address after expansion.
    """
    memory = currentProgram.getMemory()
    start = address
    end = address.add(chunk_size)

    # Expand forwards
    while end.compareTo(block.getEnd()) < 0:
        data = get_memory_data(end, chunk_size)
        if not data or not is_potentially_obfuscated(data):
            break
        end = end.add(chunk_size)

    # Expand backwards
    while start.compareTo(block.getStart()) > 0:
        data = get_memory_data(start.subtract(chunk_size), chunk_size)
        if not data or not is_potentially_obfuscated(data):
            break
        start = start.subtract(chunk_size)

    return start, end

def merge_adjacent_addresses(addresses, threshold=16):
    """
    Merges adjacent or overlapping addresses.
    :param addresses: List of addresses.
    :param threshold: Maximum distance between two addresses to consider them adjacent.
    :return: Merged list of addresses.
    """
    if not addresses:
        return []

    addresses = sorted(addresses)
    merged = [addresses[0]]

    for addr in addresses[1:]:
        last = merged[-1]
        if addr.subtract(last) <= threshold:  # Check proximity
            # Merge by extending the last address
            merged[-1] = max(last, addr)
        else:
            merged.append(addr)

    return merged

def is_potentially_obfuscated(data):
    """
    Heuristic to identify potentially obfuscated strings.
    :param data: A list of bytes.
    :return: True if the data matches obfuscation patterns, False otherwise.
    """
    try:
        # Convert data to string for easier analysis
        data_str = ''.join(chr(b) for b in data if b < 256)

        # 1. Check ratio of printable characters
        printable = sum(1 for b in data if chr(b) in string.printable)
        non_printable_ratio = (len(data) - printable) / len(data)
        if non_printable_ratio > 0.5:  # More than 50% non-printable
            return True

        # 2. Check for high entropy (randomness, often found in encryption/compression)
        entropy = calculate_entropy(data)
        if entropy > 4.0:  # Threshold for potential obfuscation
            return True

        # 3. Base64 detection
        try:
            decoded = base64.b64decode(bytes(data), validate=True)
            if decoded and all(chr(b) in string.printable for b in decoded):
                return True
        except (binascii.Error, ValueError):
            pass

        # 4. XOR-like patterns (check for repeating patterns after XOR)
        if detect_xor_pattern(data):
            return True

        # 5. Shift patterns (detect if bytes are consistently shifted)
        if detect_shift_pattern(data):
            return True

        # 6. Hexadecimal-encoded strings
        try:
            decoded = bytes.fromhex(data_str)
            if all(chr(b) in string.printable for b in decoded):
                return True
        except ValueError:
            pass

        return False
    except Exception as e:
        print("[ERROR] Error in obfuscation detection: {}".format(e))
        return False

#Helper Functions
def calculate_entropy(data):
    """
    Calculate the Shannon entropy of the given byte data.
    :param data: A list of byte values.
    :return: Entropy value (float).
    """
    if not data:
        return 0.0

    # Count frequency of each byte
    frequency = [data.count(b) / len(data) for b in set(data)]

    # Shannon entropy formula
    return -sum(p * math.log2(p) for p in frequency if p > 0)

def detect_xor_pattern(data):
    """
    Detect XOR-like patterns in data by checking repeating transformations.
    :param data: A list of bytes.
    :return: True if a pattern suggests XOR obfuscation, False otherwise.
    """
    for key in range(1, 256):  # Try all possible 1-byte XOR keys
        decoded = [b ^ key for b in data]
        if all(32 <= char <= 126 for char in decoded):  # Printable ASCII
            return True
    return False

def detect_shift_pattern(data):
    """
    Detect if data appears to be shifted by a fixed value.
    :param data: A list of bytes.
    :return: True if a consistent shift pattern is detected, False otherwise.
    """
    for shift in range(-32, 32):  # Test small shifts
        shifted = [(b + shift) & 0xFF for b in data]
        if all(32 <= char <= 126 for char in shifted):  # Printable ASCII
            return True
    return False

#Encoding and Pathing
# Helper: Track string usage in the program
def track_string_pipeline(string_address):
    """
    Tracks the pipeline of a string in the program by identifying functions and references.
    :param string_address: The memory address of the string.
    :return: A call graph as a dictionary {function_name: [list_of_references]}.
    """
    print("Tracking pipeline for string at {}...".format(string_address))
    references = getReferencesTo(string_address)
    call_graph = {}

    for ref in references:
        ref_func = getFunctionContaining(ref.getFromAddress())
        if ref_func:
            func_name = ref_func.getName()
            if func_name not in call_graph:
                call_graph[func_name] = []
            call_graph[func_name].append(ref.getFromAddress())

    return call_graph

# Helper: Detect and annotate transformations
def detect_transformations(call_graph):
    """
    Detects and annotates transformations applied to the string, including bitwise, mathematical,
    and string manipulation operations.
    :param call_graph: The call graph of functions and references.
    :return: A list of transformations [(function_name, transformation_description)].
    """
    print("[INFO] Analyzing transformations in the pipeline...")
    transformations = []

    for func_name, refs in call_graph.items():
        func = getFunction(func_name)
        if not func:
            print("[WARNING] Function {} not found.".format(func_name))
            continue

        decompiled_code = decompile_function(func)
        if not decompiled_code:
            print("[WARNING] Could not decompile function: {}".format(func_name))
            continue

        # Analyze decompiled code for transformation patterns
        if "<<" in decompiled_code or ">>" in decompiled_code:
            transformations.append((func_name, "Transformation detected: Bitwise Shift"))
        if "&" in decompiled_code:
            transformations.append((func_name, "Transformation detected: Bitwise AND"))
        if "|" in decompiled_code:
            transformations.append((func_name, "Transformation detected: Bitwise OR"))
        if "^" in decompiled_code:
            transformations.append((func_name, "Transformation detected: XOR"))
        if "+" in decompiled_code or "-" in decompiled_code:
            transformations.append((func_name, "Transformation detected: Addition/Subtraction"))
        if "*" in decompiled_code or "/" in decompiled_code:
            transformations.append((func_name, "Transformation detected: Multiplication/Division"))

    return transformations

#Prediction and Reporting
# Helper: Predict possible outputs
def predict_outputs(transformations, string_data):
    """
    Predicts possible outputs of the obfuscated string based on transformations.
    :param transformations: List of transformations [(function_name, transformation_description)].
    :param string_data: The raw bytes of the string.
    :return: A list of possible outputs [(function_name, output_string)].
    """
    print("Predicting possible outputs...")
    possible_outputs = []

    def detect_common_xor_key(data):
        """
        Detects a common XOR key by checking repeating patterns in data.
        """
        for key in range(1, 256):
            decoded = [b ^ key for b in data]
            if all(32 <= char <= 126 for char in decoded):  # Printable ASCII
                return key
        return None

    def detect_common_shift(data):
        """
        Detects a common shift (addition or subtraction) value.
        """
        for shift in range(-32, 32):  # Small shifts
            shifted = [b + shift for b in data]
            if all(32 <= char <= 126 for char in shifted):  # Printable ASCII
                return shift
        return None

    for transform in transformations:
        func_name, description = transform

        # XOR Transformation
        if "XOR" in description:
            xor_key = detect_common_xor_key(string_data)
            if xor_key is not None:
                try:
                    decoded = ''.join(chr(b ^ xor_key) for b in string_data)
                    possible_outputs.append((func_name, "XOR with detected key {}: {}".format(xor_key, decoded)))
                except Exception as e:
                    print("[ERROR] XOR decoding failed with detected key {}: {}".format(xor_key, e))
            else:
                for key in range(1, 256):  # Brute force XOR keys
                    try:
                        decoded = ''.join(chr(b ^ key) for b in string_data if 32 <= (b ^ key) <= 126)
                        if decoded:
                            possible_outputs.append((func_name, "XOR with key {}: {}".format(key, decoded)))
                    except Exception as e:
                        print("[ERROR] XOR decoding failed with key {}: {}".format(key, e))

        # Addition/Subtraction
        elif "Addition/Subtraction" in description:
            shift = detect_common_shift(string_data)
            if shift is not None:
                try:
                    adjusted = ''.join(chr((b + shift) & 0xFF) for b in string_data if 32 <= (b + shift) <= 126)
                    possible_outputs.append((func_name, "Addition/Subtraction with detected shift {}: {}".format(shift, adjusted)))
                except Exception as e:
                    print("[ERROR] Addition/Subtraction decoding failed with detected shift {}: {}".format(shift, e))
            else:
                for shift in range(-32, 32):  # Small shifts
                    try:
                        adjusted = ''.join(chr((b + shift) & 0xFF) for b in string_data if 32 <= (b + shift) <= 126)
                        if adjusted:
                            possible_outputs.append((func_name, "Addition with shift {}: {}".format(shift, adjusted)))
                    except Exception as e:
                        print("[ERROR] Addition/Subtraction decoding failed with shift {}: {}".format(shift, e))

        # Base64 Transformation
        elif "Base64" in description:
            try:
                decoded = base64.b64decode(string_data).decode('utf-8')
                possible_outputs.append((func_name, "Base64 decoded: {}".format(decoded)))
            except Exception as e:
                print("[ERROR] Base64 decoding failed: {}".format(e))

        # Bitwise Shifts
        elif "Bitwise Shift" in description:
            try:
                shifted_left = ''.join(chr((b << 1) & 0xFF) for b in string_data if 32 <= (b << 1) & 0xFF <= 126)
                possible_outputs.append((func_name, "Bitwise Shift Left: {}".format(shifted_left)))
            except Exception as e:
                print("[ERROR] Bitwise shift decoding failed: {}".format(e))

        # String Reversal
        elif "String Reversal" in description:
            try:
                reversed_string = ''.join(reversed(string_data.decode('utf-8')))
                possible_outputs.append((func_name, "Reversed string: {}".format(reversed_string)))
            except Exception as e:
                print("[ERROR] String reversal decoding failed: {}".format(e))

        # Concatenation or Substring
        elif "Concatenation" in description or "Substring" in description:
            try:
                substring = string_data.decode('utf-8')[:10]  # Example: Take the first 10 characters
                possible_outputs.append((func_name, "Substring (first 10 chars): {}".format(substring)))
            except Exception as e:
                print("[ERROR] Substring decoding failed: {}".format(e))

        # Fallback for Unknown Transformations
        else:
            possible_outputs.append((func_name, "Unknown transformation - no output prediction available"))

    # Filter plausible outputs (e.g., only ASCII strings)
    plausible_outputs = filter_plausible_outputs(possible_outputs)

    return plausible_outputs

def filter_plausible_outputs(outputs):
    """
    Filters predicted outputs to remove implausible results (e.g., non-ASCII).
    :param outputs: List of possible outputs [(function_name, output_string)].
    :return: Filtered list of plausible outputs.
    """
    plausible = []
    for func_name, output in outputs:
        # Check for printable ASCII characters or match against expected patterns
        if all(32 <= ord(c) < 127 for c in output):
            plausible.append((func_name, output))
    return plausible

# Utility: Decompile a function
def decompile_function(func):
    """
    Decompiles a function using Ghidra's decompiler.
    :param func: The function to decompile.
    :return: Decompiled code as a string, or None if decompilation fails.
    """
    if not func:
        print("[ERROR] Invalid function passed to decompiler.")
        return None

    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    try:
        decompilation = decompiler.decompileFunction(func, 60, None)
        if decompilation.decompileCompleted():
            return decompilation.getDecompiledFunction().getC()
        else:
            print("[WARNING] Decompilation failed for function: {}".format(func.getName()))
    except Exception as e:
        print("[ERROR] Exception during decompilation of function {}: {}".format(func.getName(), e))
    return None

# Helper: Visualize the call graph
def visualize_call_graph(call_graph, output_file="call_graph.dot"):
    """
    Outputs a DOT file for Graphviz.
    :param call_graph: Dictionary {function_name: [list_of_references]}.
    :param output_file: Name of the DOT file.
    """
    print("Generating DOT file for call graph...")
    with open(output_file, "w") as f:
        f.write("digraph CallGraph {\n")
        for func, refs in call_graph.items():
            for ref in refs:
                f.write('  "{}" -> "{}";\n'.format(ref, func))
        f.write("}\n")

def analyze_string(string_address):
    """
    Analyzes a single string address by:
    1. Tracking the pipeline.
    2. Detecting transformations.
    3. Predicting possible outputs.
    """
    print("[INFO] Using string address: {}".format(string_address))

    # Step 2: Track the pipeline
    print("[INFO] Tracking string pipeline...")
    call_graph = track_string_pipeline(string_address)
    if not call_graph:
        print("[WARNING] No call graph found for the specified string address.")
    else:
        print("[INFO] Call Graph:")
        for func, refs in call_graph.items():
            print("  Function: {}, References: {}".format(func, refs))

        # Visualize the call graph
        visualize_call_graph(call_graph, output_file="call_graph_{}.dot".format(string_address))
        print("[INFO] Call graph saved to call_graph_{}.dot".format(string_address))

    # Step 3: Detect transformations
    print("[INFO] Detecting transformations...")
    transformations = detect_transformations(call_graph)
    if not transformations:
        print("[WARNING] No transformations detected.")
    else:
        print("[INFO] Transformations Detected:")
        for transform in transformations:
            print("  {}: {}".format(transform[0], transform[1]))

    # Step 4: Predict outputs
    print("[INFO] Predicting possible outputs...")
    string_data = get_memory_data(string_address, 100)  # Adjust size as needed
    if not string_data:
        print("[WARNING] No data found at the specified address.")
    else:
        possible_outputs = predict_outputs(transformations, string_data)
        if not possible_outputs:
            print("[WARNING] No plausible outputs predicted.")
        else:
            print("[INFO] Possible Outputs:")
            for output in possible_outputs:
                print("  Function: {}, Output: {}".format(output[0], output[1]))

def main():
    print("[INFO] Starting String Obfuscation Resolver...")

    # Step 1: Autodetect potential obfuscated strings
    print("[INFO] Attempting to autodetect obfuscated strings in memory...")
    detected_strings = autodetect_obfuscated_strings()

    if detected_strings:
        print("[INFO] Detected potential obfuscated strings:")
        for i, addr in enumerate(detected_strings):
            print("  [{}] Address: {}".format(i, addr))

        # Let the user choose to process one or all detected strings
        choice = askChoice(
            "Select Option",
            "Choose to analyze one address, all addresses, or specify manually:",
            ["Manual Input", "Analyze All"] + [str(addr) for addr in detected_strings],
            "Analyze All"
        )

        if choice == "Manual Input":
            string_address = askAddress("String Address", "Enter the address of the suspected obfuscated string:")
            analyze_string(string_address)
        elif choice == "Analyze All":
            print("[INFO] Analyzing all detected strings...")
            for addr in detected_strings:
                print("\n[INFO] Processing address: {}".format(addr))
                analyze_string(addr)
        else:
            string_address = detected_strings[int(choice.split(" ")[0])]
            analyze_string(string_address)
    else:
        print("[WARNING] No obfuscated strings detected. Please specify an address manually.")
        string_address = askAddress("String Address", "Enter the address of the suspected obfuscated string:")
        analyze_string(string_address)

    print("[INFO] String Obfuscation Resolver completed.")

# Run the script
main()
