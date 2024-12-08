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
import urllib  # For URL decoding
import base64
import math
import string
import threading
import binascii
import re


#0. String detection
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
            data.append(byte & 0xFF)
        return data
    except Exception as e:
        print("[ERROR] Error reading memory at {}: {}".format(address, e))
        return []

def process_block_thread(block, chunk_size, detected_strings_lock, detected_strings):
    """
    Processes a block in a thread-safe manner and appends detected strings.
    """
    if block.isInitialized():
        try:
            entropies, avg_entropy, std_dev = calculate_block_entropy(block, chunk_size)
            start = block.getStart()
            end = block.getEnd()
            address = start

            while address.compareTo(end) < 0:
                remaining_size = end.subtract(address) + 1
                effective_chunk_size = min(chunk_size, remaining_size)
                data = get_memory_data(address, effective_chunk_size)
                if data and is_potentially_obfuscated(data, avg_entropy, std_dev):
                    with detected_strings_lock:
                        detected_strings.append(address)
                address = address.add(effective_chunk_size)
        except Exception as e:
            print("[ERROR] Error scanning block {}: {}".format(block.getName(), e))

def autodetect_obfuscated_strings_parallel():
    """
    Multi-threaded version using the threading module for Jython compatibility.
    """
    memory = currentProgram.getMemory()
    detected_strings = []
    detected_strings_lock = threading.Lock()
    threads = []

    print("[INFO] Autodetecting obfuscated strings in memory...")

    # Prompt user to select the chunk size
    chunk_size = select_chunk_size()
    print("[INFO] Using chunk size: {} bytes.".format(chunk_size))

    for block in memory.getBlocks():
        thread = threading.Thread(target=process_block_thread, args=(block, chunk_size, detected_strings_lock, detected_strings))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    detected_strings = merge_adjacent_addresses(detected_strings)
    print("[INFO] Detection complete. {} potential strings found.".format(len(detected_strings)))
    return detected_strings

def expand_detected_region(address, block, chunk_size):
    """
    Expands the detected region to include adjacent memory that may also be part of the string.
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
    """
    if not addresses:
        return []

    addresses = sorted(addresses)
    merged = [addresses[0]]

    for addr in addresses[1:]:
        last = merged[-1]
        # Check if the addresses are in the same memory space
        if last.getAddressSpace() == addr.getAddressSpace():
            if addr.subtract(last) <= threshold:  # Check proximity
                # Merge by extending the last address
                merged[-1] = max(last, addr)
            else:
                merged.append(addr)
        else:
            print("[WARNING] Addresses {} and {} are in different spaces.".format(last, addr))
            merged.append(addr)  # Keep both addresses separate

    return merged

def is_potentially_obfuscated(data, avg_entropy, std_dev):
    """
    Heuristic to identify potentially obfuscated strings with dynamic entropy thresholds.
    """
    try:
        # Ensure all values in data are valid bytes
        if not all(isinstance(b, int) and 0 <= b <= 255 for b in data):
            raise ValueError("Data contains invalid byte values.")

        # Convert data to string for easier analysis
        data_str = ''.join(chr(b) for b in data if b < 256)

        # 1. Check ratio of printable characters
        printable = sum(1 for b in data if chr(b) in string.printable)
        non_printable_ratio = (len(data) - printable) / len(data)
        if non_printable_ratio > 0.5:  # More than 50% non-printable
            return True

        # 2. Check for high entropy relative to block statistics
        entropy = calculate_entropy(data)
        if entropy > avg_entropy + std_dev:  # Dynamic threshold
            return True

        # 3. Base64 detection
        try:
            if re.match(r'^[A-Za-z0-9+/]*={0,2}$', data_str):  # Regex for Base64 strings
                decoded = base64.b64decode(data_str + "=" * ((4 - len(data_str) % 4) % 4))
                if decoded and all(32 <= c <= 126 for c in decoded):
                    return True
        except (binascii.Error, ValueError):
            pass

        # 4. Base32 detection
        if detect_base32(data):
            return True

        # 5. URL-encoding detection
        if detect_url_encoding(data):
            return True

        # 6. XOR-like patterns (check for repeating patterns after XOR)
        if detect_xor_pattern(data):
            return True

        # 7. Shift patterns (detect if bytes are consistently shifted)
        if detect_shift_pattern(data):
            return True

        # 8. Hexadecimal-encoded strings
        try:
            decoded = binascii.unhexlify(data_str)  # Use binascii.unhexlify for decoding hex
            if all(chr(b) in string.printable for b in decoded):  # Check if all characters are printable
                return True
        except (binascii.Error, TypeError):  # Catch appropriate exceptions for invalid input
            pass

        return False
    except Exception as e:
        print("[ERROR] Error in obfuscation detection: {}".format(e))
        return False

def select_chunk_size():
    """
    Prompt the user to select a chunk size from a predefined list.
    """
    chunk_sizes = [16, 32, 64, 128, 256]
    default_size = 64
    choice = askChoice(
        "Select Chunk Size",
        "Choose a chunk size for memory scanning:",
        [str(size) for size in chunk_sizes],
        str(default_size)
    )
    return int(choice)

#Detection Helper Functions
def calculate_block_entropy(block, chunk_size):
    """
    Calculates the entropy for each byte in a memory block with a user-defined chunk size.
    """
    try:
        start = block.getStart()
        end = block.getEnd()
        entropies = []
        address = start

        while address.compareTo(end) < 0:
            effective_chunk_size = min(chunk_size, end.subtract(address) + 1)
            data = get_memory_data(address, effective_chunk_size)
            if data:
                entropy = calculate_entropy(data)
                entropies.append(entropy)
            address = address.add(effective_chunk_size)

        # Calculate average entropy and standard deviation
        if entropies:
            avg_entropy = sum(entropies) / len(entropies)
            std_dev = math.sqrt(sum((e - avg_entropy) ** 2 for e in entropies) / len(entropies))
        else:
            avg_entropy, std_dev = 0, 0

        return entropies, avg_entropy, std_dev

    except Exception as e:
        print("[ERROR] Error calculating block entropy: {}".format(e))
        return [], 0, 0

def calculate_entropy(data):
    """
    Calculate the Shannon entropy of the given byte data.
    """
    if not data:
        return 0.0

    # Count frequency of each byte
    frequency = [data.count(b) / len(data) for b in set(data)]

    # Shannon entropy formula
    return -sum(p * math.log(p, 2) for p in frequency if p > 0)

def detect_xor_pattern(data):
    """
    Detect XOR-like patterns in data by checking repeating transformations.
    """
    for key in range(1, 256):  # Try all possible 1-byte XOR keys
        decoded = [b ^ key for b in data]
        if all(32 <= char <= 126 for char in decoded):  # Printable ASCII
            return True
    return False

def detect_shift_pattern(data):
    """
    Detect if data appears to be shifted by a fixed value.
    """
    for shift in range(-32, 32):  # Test small shifts
        shifted = [(b + shift) & 0xFF for b in data]
        if all(32 <= char <= 126 for char in shifted):  # Printable ASCII
            return True
    return False

def detect_url_encoding(data):
    """
    Detect URL-encoded strings.
    """
    try:
        decoded = urllib.unquote(''.join(chr(b) for b in data))
        if all(c in string.printable for c in decoded):
            return True
    except Exception:
        pass
    return False

def detect_base32(data):
    """
    Detect Base32-encoded strings.
    """
    try:
        decoded = base64.b32decode(''.join(chr(b) for b in data), casefold=True)
        if all(chr(c) in string.printable for c in decoded):  # Check if decoded content is printable
            return True
    except Exception:
        pass
    return False

#Visualization
def visualize_detected_strings(detected_strings, output_file="detected_strings.png"):
    """
    Visualizes the distribution of detected obfuscated strings within memory.
    """
    if not detected_strings:
        print("[INFO] No strings to visualize.")
        return

    try:
        addresses = [addr.getOffset() for addr in detected_strings]

        # Generate histogram
        plt.figure(figsize=(10, 6))
        plt.hist(addresses, bins=50, color="blue", alpha=0.7, edgecolor="black")
        plt.title("Distribution of Detected Strings in Memory")
        plt.xlabel("Memory Address (Offset)")
        plt.ylabel("Frequency")
        plt.grid(axis="y", alpha=0.75)

        # Save as image file
        plt.savefig(output_file)
        print("[INFO] Visualization saved to {}".format(output_file))
        plt.close()
    except Exception as e:
        print("[ERROR] Failed to visualize detected strings: {}".format(e))


#1. Encoding and Pathing
# Helper: Track string usage in the program
def track_string_pipeline(string_address):
    """
    Tracks the pipeline of a string in the program by identifying functions and references.
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

#E&P Helpers
# Helper: Detect and annotate transformations
def detect_transformations(call_graph):
    """
    Detects and annotates transformations applied to the string, including bitwise, mathematical,
    and string manipulation operations.
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

# Helper: Visualize the call graph
def visualize_call_graph(call_graph, output_file="call_graph.dot"):
    """
    Outputs a DOT file for Graphviz.
    """
    print("[INFO] Generating DOT file for call graph...")
    try:
        with open(output_file, "w") as f:
            f.write("digraph CallGraph {\n")
            for func, refs in call_graph.items():
                for ref in refs:
                    f.write('  "{}" -> "{}";\n'.format(ref, func))
            f.write("}\n")
        print("[INFO] DOT file generated successfully at: {}".format(output_file))
    except Exception as e:
        print("[ERROR] Failed to generate DOT file: {}".format(e))


#2. Prediction and Reporting
# Helper: Predict possible outputs
def predict_outputs(transformations, string_data):
    """
    Predicts possible outputs of the obfuscated string based on transformations.
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

#P&R Helpers
def filter_plausible_outputs(outputs):
    """
    Filters predicted outputs to remove implausible results (e.g., non-ASCII).
    """
    plausible = []
    for func_name, output in outputs:
        # Check for printable ASCII characters or match against expected patterns
        if all(32 <= ord(c) < 127 for c in output):
            plausible.append((func_name, output))
    return plausible

def validate_addresses(addresses):
    """
    Validate that all addresses in the list are properly formatted and accessible.
    """
    memory = currentProgram.getMemory()
    valid_addresses = []

    for addr in addresses:
        try:
            if memory.contains(addr):
                valid_addresses.append(addr)
            else:
                print("[WARNING] Address {} is out of bounds.".format(addr))
        except Exception as e:
            print("[ERROR] Failed to validate address {}: {}".format(addr, e))

    return valid_addresses

def process_detected_strings(detected_strings):
    """
    Process each detected string by tracking its pipeline and analyzing transformations.
    Allows the user to manually input an address if needed.
    """
    valid_addresses = validate_addresses(detected_strings)

    if not valid_addresses:
        print("[WARNING] No valid detected strings. Please provide an address manually.")
        manual_address = askAddress(
            "Manual Address Entry",
            "Enter the address of the string you want to analyze:"
        )
        if manual_address:
            valid_addresses = [manual_address]
        else:
            print("[INFO] No addresses to process. Exiting.")
            return

    for addr in valid_addresses:
        print("[INFO] Processing address: {}".format(addr))
        try:
            # Step 1: Track the pipeline
            call_graph = track_string_pipeline(addr)

            if not call_graph:
                print("[WARNING] No call graph generated for address {}. Logging for manual review.".format(addr))
                with open("failed_addresses.log", "a") as log_file:
                    log_file.write("Failed to process call graph for address: {}\n".format(addr))
                continue

            # Visualize the call graph
            visualize_call_graph(call_graph, output_file="call_graph_{}.dot".format(addr))

            # Step 2: Detect transformations
            transformations = detect_transformations(call_graph)

            if not transformations:
                print("[WARNING] No transformations detected for address {}. Logging for manual review.".format(addr))
                with open("failed_addresses.log", "a") as log_file:
                    log_file.write("Failed to detect transformations for address: {}\n".format(addr))
                continue

            print("[INFO] Transformations for address {}:".format(addr))
            for func, transformation in transformations:
                print("  Function: {}, Transformation: {}".format(func, transformation))

        except Exception as e:
            print("[ERROR] Failed to process address {}: {}".format(addr, e))
            with open("failed_addresses.log", "a") as log_file:
                log_file.write("Exception for address {}: {}\n".format(addr, e))

# Utility: Decompile a function
def decompile_function(func):
    """
    Decompiles a function using Ghidra's decompiler.
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

#Analysis of single string
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

    # Step 0: Autodetect potential obfuscated strings
    print("[INFO] Attempting to autodetect obfuscated strings in memory...")
    detected_strings = autodetect_obfuscated_strings_parallel()

    # Validate the detected addresses
    valid_addresses = validate_addresses(detected_strings)

    if valid_addresses:
        print("[INFO] Valid detected obfuscated strings:")
        for i, addr in enumerate(valid_addresses):
            print("  [{}] Address: {}".format(i, addr))

        # Visualize the results
        visualize_detected_strings(valid_addresses)

        # Let the user choose to process one or all detected strings
        choice = askChoice(
            "Select Option",
            "Choose to analyze one address, all addresses, or specify manually:",
            ["Manual Input", "Analyze All"] + ["[{}] {}".format(i, addr) for i, addr in enumerate(valid_addresses)],
            "Analyze All"
        )

        if choice == "Manual Input":
            # Allow user to manually input an address
            manual_address = askAddress("String Address", "Enter the address of the suspected obfuscated string:")
            if manual_address:
                process_detected_strings([manual_address])
            else:
                print("[WARNING] No manual address provided. Exiting.")
        elif choice == "Analyze All":
            print("[INFO] Analyzing all detected strings...")
            process_detected_strings(valid_addresses)
        else:
            # Process a single selected address
            selected_index = int(choice.split(" ")[0].strip("[]"))
            process_detected_strings([valid_addresses[selected_index]])
    else:
        print("[WARNING] No valid obfuscated strings detected.")
        manual_address = askAddress("Manual Address Entry", "Enter the address of the string you want to analyze:")
        if manual_address:
            process_detected_strings([manual_address])
        else:
            print("[INFO] No addresses to process. Exiting.")

    print("[INFO] String Obfuscation Resolver completed.")

# Run the script
main()
