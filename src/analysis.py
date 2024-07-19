import re
import random
from typing import List
import logging

from code import Code
from utils import OBFUSCATED_VARIABLE_PATTERN
from config import Config

CONFIG = Config()
LOGGER = logging.getLogger(__name__)

# Java object types
COMPLEX_TYPES = {
    "STRING": "java.lang.String",
    "INTEGER": "java.lang.Integer",
    "DOUBLE": "java.lang.Double",
    "FLOAT": "java.lang.Float",
    "BYTE": "java.lang.Byte",
    "BOOLEAN": "java.lang.Boolean",
    "SHORT": "java.lang.Short",
    "CHAR": "java.lang.Char",
    "LONG": "java.lang.Long",
    "LIST": "java.util.List",
    "ARRAY": "java.util.ArrayList"
}

SIMPLE_TYPES = {
    "I": f"{COMPLEX_TYPES['INTEGER']}",
    "D": f"{COMPLEX_TYPES['DOUBLE']}",
    "F": f"{COMPLEX_TYPES['FLOAT']}",
    "B": f"{COMPLEX_TYPES['BYTE']}",
    "Z": f"{COMPLEX_TYPES['BOOLEAN']}",
    "S": f"{COMPLEX_TYPES['SHORT']}",
    "C": f"{COMPLEX_TYPES['CHAR']}",
    "J": f"{COMPLEX_TYPES['LONG']}"
}

LIST_OBJECT_PATTERN = re.compile(
    r"(java\.util\.(?:[A-Za-z]+)?List(?:[0-9/]+)?)<([a-zA-Z0-9./]+)[<>]?(?:(.*[^>]))?>"
)


def is_number(value):
    return bool(re.match(r'^-?\.?\d+(\.\d*)?$', value))


def get_offset(code, line, key):
    """ REFACTORED """
    if line < 0 or line >= len(code):
        raise ValueError("Invalid line number")

    for offset, content in enumerate(code[line:], start=0):
        if key in content.strip():
            return offset

    # If the key is not found, raise an exception or return a default value
    raise ValueError(f"Key '{key}' not found after line {line}")


def sort_by(dict_list, key):
    """ Returns a List of dictionaries, sorted by a specific key """
    return sorted(dict_list, key=lambda k: k[key])


def find_value(code, value):
    """ Returns the value of a given variable name within the code """
    value_pattern = re.compile(rf"{re.escape(value)} ?= ?([^=][a-zA-Z0-9\.'/_)(]*)")

    target = None
    for line in code:
        if value_pattern.search(line):
            target = re.findall(value_pattern, line)
            break

    return target[0] if target is not None else value


def parse_parameter(code, param):
    """ REFACTORED """
    if param != "null" and not param.lstrip().startswith("'") and not is_number(param):
        param = find_value(code, param)

    return param.replace("'", "")


def get_method_parameter_values(code: List[str], line: int, full_sig: str) -> List[str]:
    """ REFACTORED """
    param_list = []
    offset = (get_offset(code, line, "catch(") - 3) // 2
    line += offset + 1

    param_pattern = re.compile(rf", ?(?:'' ?\+ ?)?(?:{OBFUSCATED_VARIABLE_PATTERN}\(?.*, ?)?(.*[^\)])\)\)?;")
    nested_boolean_pattern = re.compile(rf".*\?(('?{OBFUSCATED_VARIABLE_PATTERN}'?):('?{OBFUSCATED_VARIABLE_PATTERN}'?))")

    for i in range(offset):
        # param = re.findall(param_pattern, code[line])[0].replace("'", "")
        param_matches = param_pattern.findall(code[line])

        if not param_matches:
            line += 1
            continue

        param = param_matches[0].replace("'", "")
        param_type = full_sig[i]

        # If the parameter is a boolean, append a 0
        if nested_boolean_pattern.search(code[line]) or param_type.startswith(COMPLEX_TYPES["BOOLEAN"]):
            param_list.append("§0§")
        # If the parameter is a number, append it directly
        elif is_number(param) or param_type.startswith("I"):
            param_list.append(f"§{param if is_number(param) else random.randint(0, 99)}§")
        # Else, treat it as string and append with a prefix
        else:
            param = param.replace(" ", "_").replace("|", "\\!").replace("\\", "\\\\")
            param_list.append(f"§param_{param}§")

        line += 1

    return param_list


def normalise_signature(method_signature):
    """ REFACTORED """
    unique_signatures = list(set(method_signature))
    normalized = []

    # Specific logic for normalizing the script's custom java.util.List type format
    list_object_pattern = re.compile(
        r"(java\.util\.(?:[A-Za-z]+)?List(?:[0-9\/]+)?)<([a-zA-Z0-9\.\/]+)[<>]?(?:(.*[^>]))?>"
    )

    for sig in unique_signatures:
        matches = list_object_pattern.match(sig)

        # If list object found, fragment and append each part to the signature List
        if matches:
            parts = matches.groups()
            normalized.extend(filter(None, parts))
        else:
            normalized.append(sig)

    # Remove duplicates and filter out any empty elements
    return list(set(normalized))


def get_list_type(param_type: str) -> List[str]:
    return list(filter(None, re.findall(LIST_OBJECT_PATTERN, param_type)[0]))


def append_list_elements(parameter_map: List[str], rpc_blocks, list_type: List[str], param: str, list_length=1):
    for _ in range(list_length):
        parameter_map.append(str(rpc_blocks.index(list_type[1] if len(list_type) < 3 else list_type[2]) - 2))
        parameter_map.append(str(rpc_blocks.index(param) - 2))


def generate_parameter_map(rpc_blocks, full_signature, param_values):
    """ REFACTORED """
    parameter_map = []

    # Append type index for each parameter value
    for i, param in enumerate(param_values):
        param_type = full_signature[i]

        # If parameter is of type list, append index of list type
        if re.match(LIST_OBJECT_PATTERN, param_type):
            list_type = get_list_type(param_type)[0]
            parameter_map.append(str(rpc_blocks.index(list_type) - 2))
        # If not of type list, append the index of the simple type
        else:
            parameter_map.append(str(rpc_blocks.index(param_type) - 2))

    # For each indexed parameter append type and value indices
    for i, param in enumerate(param_values):
        param_type = full_signature[i]

        # If parameter is a string object, append value index
        if param_type.startswith(COMPLEX_TYPES["STRING"]):
            parameter_map.append(str(rpc_blocks.index(param) - 2))

        # Else if the parameter is simple type, append value
        elif param_type in SIMPLE_TYPES:
            parameter_map.append(str(param))

        # Else if the parameter is a java list object, append type index and length
        elif re.match(LIST_OBJECT_PATTERN, param_type):
            list_length = 1
            list_type = get_list_type(param_type)

            parameter_map.append(str(rpc_blocks.index(list_type[0] if len(list_type) < 3 else list_type[1]) - 2))
            parameter_map.append(str(list_length))
            append_list_elements(parameter_map, rpc_blocks, list_type, param, list_length)

        # If parameter is a so far unhandled complex type, append runtime index and value
        elif any(param_type.startswith(val) for val in COMPLEX_TYPES.values()):
            parameter_map.append(str(rpc_blocks.index(param_type) - 2))
            parameter_map.append(str(param))

        # If parameter is unknown, append runtime index and value index
        else:
            parameter_map.append(str(rpc_blocks.index(param_type) - 2))
            parameter_map.append(str(rpc_blocks.index(param) - 2))

    return parameter_map


def get_string_values(param_values, full_signature):
    """ REFACTORED """
    strings, complex_types = [], set()
    complex_type_values = set(COMPLEX_TYPES.values())
    simple_type_keys = set(SIMPLE_TYPES.keys())

    for i, value in enumerate(param_values):
        signature = full_signature[i]

        # If value is string, append value to strings List
        if COMPLEX_TYPES["STRING"] in signature:
            strings.append(value)
        elif not any(signature.startswith(val) for val in complex_type_values) and signature not in simple_type_keys:
            complex_types.add(signature)
            strings.append(value)

    return strings, list(complex_types)


def build_method_call(code, line, method_object):
    """
    REFACTORED

    Note: This is unfortunately not 100% reliable, and can only
    process and serialize a small number of known Java types
    """

    def get_rpc_payload_length(signature, values):
        return str(4 + len(signature) + len(values))

    def get_strong_name(service):
        # Default to stub value if method-to-service correlation failed
        return service["strongName"] if service is not None else "X" * 32

    full_signature = method_object["methodSignature"]
    normalized_signature = normalise_signature(full_signature)
    param_values = get_method_parameter_values(code, line, full_signature)
    string_values, complex_types = get_string_values(param_values, full_signature)

    rpc_payload_length = get_rpc_payload_length(normalized_signature, string_values)
    strong_name = get_strong_name(method_object["service"])

    rpc_blocks = [
        CONFIG.rpc_version,
        CONFIG.rpc_flags,
        rpc_payload_length,
        CONFIG.base_url,
        strong_name,
        method_object["rmtSvcIntName"],
        method_object["methodName"],
        *normalized_signature,
        *string_values,
        "1", "2", "3", "4",
        method_object["paramCount"]
    ]

    rpc_blocks.extend(
        generate_parameter_map(
            rpc_blocks,
            full_signature,
            param_values
        )
    )

    return rpc_blocks, complex_types


##################################################
# Enumerate methods within the static code
##################################################
def extract_method_signature(code, line):
    """ Returns a List of parameters for a given method """
    line += 5
    method_signature = []
    offset = get_offset(code, line, "catch(")
    param_pattern = re.compile(rf"{OBFUSCATED_VARIABLE_PATTERN}\(.*, ?.*, ?(.*)\)\);")

    for _ in range(int((offset - 2) / 2)):
        parameter = parse_parameter(code, re.findall(param_pattern, code[line])[0])

        # If List type found, assume ArrayList implementation of Strings
        if parameter.startswith(COMPLEX_TYPES["LIST"]):
            parameter += f"<{COMPLEX_TYPES['ARRAY']}/4159755760"
            parameter += f"<{COMPLEX_TYPES['STRING']}/2004016611>>"

        # If specific List implementation found, assume it is of Strings
        elif re.match(r"java\.util\.[A-Za-z]+List/.*", parameter):
            parameter += f"<{COMPLEX_TYPES['STRING']}/2004016611>"

        method_signature.append(parameter)

        line += 1

    return method_signature


def correlate_service(method, service_objects):
    """ Returns the service containing the appropriate service path
        for the provided method, if a match is found """
    service_segment = method["rmtSvcIntName"].lower().split(".")[-1]
    for service in service_objects:
        service_path = service["servicePath"].lower().replace("/", "")
        if (
                service_segment in service_path
                or service_path in service_segment
        ):
            return service

    return None


def extract_method_info(code: Code, service_objects):
    """ BUGGY """
    def get_method_object(method, rmt_svc_int_name_value, code, loc):
        """Creates a method object from the extracted method and service interface values"""
        method_object = {
            "methodName": parse_parameter(code, method[0][2]),
            "methodSignature": extract_method_signature(code, loc - 2),
            "serviceProxy": parse_parameter(code, method[0][1]),
            "rmtSvcIntName": parse_parameter(code, rmt_svc_int_name_value[0][0]),
            "paramCount": parse_parameter(code, rmt_svc_int_name_value[0][1]),
        }

        if CONFIG.rpc_mode:
            service = correlate_service(method_object, service_objects)
            method_object["service"] = service

            rpc_call, ctypes = build_method_call(code, loc + 2, method_object)
            method_object["methodRpcCall"] = rpc_call
            method_object["complexTypes"] = ctypes

        return method_object

    def get_rmt_svc_int_name_value(line: str):
        """Extracts the remote service interface value for the identified method"""
        rmt_svc_pattern_1 = re.compile(
            rf"^[ \t]*(?:{OBFUSCATED_VARIABLE_PATTERN} ?= ?)?{OBFUSCATED_VARIABLE_PATTERN}\({OBFUSCATED_VARIABLE_PATTERN}, ?(.*), ?(.*)\);"
        )
        rmt_svc_pattern_2 = re.compile(
            rf"{OBFUSCATED_VARIABLE_PATTERN} ?= ?\(.*\({OBFUSCATED_VARIABLE_PATTERN}, ?(.*)\).*, ?.*\(.*\).*, ?(.*)\), ?.*\);"
        )

        rmt_svc_int_name_value = re.findall(rmt_svc_pattern_1, line)
        if not rmt_svc_int_name_value:
            rmt_svc_int_name_value = re.findall(rmt_svc_pattern_2, line)

        return rmt_svc_int_name_value

    method_pattern = re.compile(
        rf"({OBFUSCATED_VARIABLE_PATTERN} ?= ?new\ ?{OBFUSCATED_VARIABLE_PATTERN}\({OBFUSCATED_VARIABLE_PATTERN}, ?)('?{OBFUSCATED_VARIABLE_PATTERN}'?), ?('?.*'?)\)\;"
    )
    method_objects = []

    code_array = code.get_content_array()
    for loc, line in enumerate(code_array):
        if method_pattern.search(line) and "try" in code_array[loc + 1]:
            # If a method definition is found, break it into its values
            method = re.findall(method_pattern, line)
            rmt_svc_int_name_value = get_rmt_svc_int_name_value(code_array[loc + 2])

            # Extract the remote service interface value for the identified method
            if rmt_svc_int_name_value:
                method_object = get_method_object(method, rmt_svc_int_name_value, code_array, loc)
                method_objects.append(method_object)

    return sort_by(method_objects, "serviceProxy")


##################################################
# Enumerate services within the static code
##################################################
def extract_service_info(code: Code):
    """ REFACTORED """
    service_pattern = re.compile(
        rf"{OBFUSCATED_VARIABLE_PATTERN}\.call\(this, ?{OBFUSCATED_VARIABLE_PATTERN}\(\), ?(?:(.*), ?)?(.*), ?{OBFUSCATED_VARIABLE_PATTERN}\)"
    )

    service_objects = []
    code_array = code.get_content_array()
    for line in code_array:
        matches = service_pattern.search(line)
        if matches:
            service_path = matches.group(1).strip() if matches.group(1) else "Unknown"
            strong_name = matches.group(2).strip()

            service_object = {
                "servicePath": parse_parameter(code_array, service_path),
                "strongName": parse_parameter(code_array, strong_name),
            }
            service_objects.append(service_object)

    return sort_by(service_objects, "servicePath")
