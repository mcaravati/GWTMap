#!/usr/bin/python3

"""
GWTMap v0.1 BETA
Author: Oliver Simonnet @FSecureLabs

Released as open source by F-Secure Labs (c) 2020
under BSD 3-Clause License. See LICENSE for more.
"""

import argparse
import logging
import os
import re
import sys
from typing import List

from code import classify_code, Code, CodeType, is_fragmented
from analysis import extract_method_info, extract_service_info
from http_client import HttpClient
from utils import GWT_VERSION_PATTERN, STRONGNAME_PATTERN, RPC_VERSION_PATTERN, RPC_FLAGS_PATTERN
from config import Config


CONFIG = Config()
logging.basicConfig(level=logging.INFO)  # or logging.INFO
logger = logging.getLogger(__name__)
http_client = None

VERSION = "0.1"

DESCRIPTON = "Enumerates GWT-RPC methods from {hex}.cache.js permutation files"

EXAMPLE = (
    f"Example: {sys.argv[0]} "
    '-u "http://127.0.0.1/example/example.nocache.js" '
    '-p "http://127.0.0.1:8080" --rpc'
)

BANNER = f"""
   ___|  \\        / __ __|   \\  |     \\      _ \\
  |       \\  \\   /     |    |\\/ |    _ \\    |   |
  |   |    \\  \\ /      |    |   |   ___ \\   ___/
 \\____|    _/\\_/      _|   _|  _| _/    _\\ _|"""

# Immutable global variables
DEFERRED = "deferredjs/"
UNKNOWN = "Unknown"
BOOTSTRAP = "bootstrap"
PERMUTATION = "permutation"
FRAGMENT = "fragment"
CLEAN = "clean"
OBFCTD = "obfuscated"


def print_heading(text):
    print(f"\n[+] {text}\n{'=' * 20}")


def present_services(services):
    """ Prints the enumerated GWT services """
    logging.info("Services Found")

    if len(services) < 1:
        logging.warning("No services were identified!")
    else:
        for service in services:
            logging.info(f"Policy Strong Name: {service['strongName']} - Path: {service['servicePath']}")


def present_rpc_method(method, send_probe):
    """ Prints the method's RPC request structure """
    svc_path_bk = method["rmtSvcIntName"].split(".")[-1]
    if method["service"] is None:
        svc_path_bk = svc_path_bk[0].lower() + svc_path_bk[1:]
        logging.warning(
            f"Unable to correlate method to a service path. Guessed /{svc_path_bk}\n"
            + " - Strong name unknown - Use --svc to see options"
        )
    if CONFIG.rpc_version != "7":
        logging.warning(
            "RPC body generation may be invalid - version 7 expected"
            + f", version {CONFIG.rpc_version} found",
        )
    if len(method["complexTypes"]) != 0:
        logging.warning(
            "Unhandled complex type found - RPC likely invalid:\n - {}"
            .format('\n - '.join(method['complexTypes']))
        )

    service_path = (
        method["service"]["servicePath"]
        if method["service"] is not None
        else svc_path_bk
    )
    rpc_call = '|'.join(method["methodRpcCall"]) + "|"

    base_url = CONFIG.base_url()

    print(
        "POST /{}{} HTTP/1.1\r".format(
            '/'.join(base_url.split("/")[3:]), service_path
        ).replace("//", "/")
    )
    print(f"Host: {base_url.split('/')[2]}\r")
    print(str(CONFIG))
    print(f"Content-Length: {len(rpc_call.encode('utf-8'))}\r\n\r")
    print(f"{rpc_call}\n")

    if send_probe:
        url = (base_url + service_path)
        http_client.send_rpc_probe(url, rpc_call)


def present_methods(methods, quiet, send_probe):
    """ Prints the enumerated GWT methods """
    ret_service_count, ret_method_count = 0, 0
    if not quiet:
        print_heading("Methods Found")

    if len(methods) < 1:
        logging.warning("No methods were identified!")
        return 0, 0

    service_category = ""
    for _, method in enumerate(methods):

        method_string = "{}.{}( {} )".format(
            method["serviceProxy"][:-6],
            method["methodName"], ', '.join(method["methodSignature"])
        ).replace("(  )", "()")

        if CONFIG.filter in method_string:
            if method["serviceProxy"] != service_category:
                print(f"\n----- {method['serviceProxy'][:-6]} -----\n")
                ret_service_count += 1

            service_category = method["serviceProxy"]

            print(method_string)
            ret_method_count += 1

            if CONFIG.rpc_mode:
                present_rpc_method(method, send_probe)

    if not CONFIG.rpc_mode:
        print()

    return ret_service_count, ret_method_count


def present_summary(services, methods, count, backup):
    """ Prints the target resource being analysed """
    print_heading("Summary")
    if backup is not None:
        print(f"Backup: {backup}")
    print(f"Showing {count[0]}/{len(services)} Services")
    print(f"Showing {count[1]}/{len(methods)} Methods\n")


##################################################
# Methods for extracting values from static code
##################################################
def extract_permutations(code) -> List[str]:
    """ Returns a List of code permutation values """
    return [match for line in code.get_content_array() for match in re.findall(r"([A-Z0-9]{32})", line)]


##################################################
# Code for building a method's RPC body structure
##################################################


def set_globals(code, args):
    """ Initialises the module's global variables """
    CONFIG.filter = args.filter
    CONFIG.rpc_mode = args.rpc

    # Search static code for the appropriate module values
    for i, line in enumerate(code):
        if re.search(GWT_VERSION_PATTERN, line):
            CONFIG.gwt_version = re.findall(GWT_VERSION_PATTERN, line)[0]

        if re.search(STRONGNAME_PATTERN, line):
            CONFIG.gwt_permutation = re.findall(STRONGNAME_PATTERN, line)[0]

        if re.search(RPC_VERSION_PATTERN, line):
            CONFIG.rpc_version = re.findall(RPC_VERSION_PATTERN, line)[0]
            CONFIG.rpc_flags = re.findall(RPC_FLAGS_PATTERN, code[i - 1])[0]

        # If all values found, break out of the code review
        if all(x != UNKNOWN for x in [CONFIG.gwt_permutation, CONFIG.gwt_version, CONFIG.rpc_version, CONFIG.rpc_flags]):
            break


def has_cache_extension(filename):
    pattern = r'\.(?:no?)cache(?:\.html|\.js)$'
    return bool(re.search(pattern, filename))


def url_mode_checks(file_name: str) -> str:
    """ Throws an error if an invalid resource is provided --url mode """
    if not has_cache_extension(file_name):
        raise argparse.ArgumentTypeError(
            "\nURL resource must be:\n"
            + " 1) Obfuscated {name}.nocache.js GWT bootstrap file\n"
            + " 2) Obfuscated {name}.nocache.html GWT bootstrap file\n"
            + " 3) Obfuscated {hex}.cache.js GWT permutation file\n"
            + " 4) Obfuscated {int}.cache.js GWT deferred fragment file"
        )
    return file_name


def file_mode_checks(file_name: str) -> str:
    """ Throws an error if an invalid file is provided --file mode """
    if not has_cache_extension(file_name):
        raise argparse.ArgumentTypeError(
            "\nFile resource must be:\n"
            + " 1) Obfuscated {hex}.cache.js GWT permutation file"
            + " 2) Obfuscated {hex}.cache.html GWT permutation file"
        )
    return file_name


##################################################
# Retrieve target resource data
##################################################


def read_file(file_path, encoding="utf-8") -> Code:
    with open(file_path, "r", encoding=encoding) as file_obj:
        file_name = os.path.basename(file_path)
        file_content = file_obj.read()

        return classify_code(file_name, file_content)


def append_fragments(code: Code, max_misses=2) -> Code:
    """ Returns a new code List with any enumerated deferred JS fragments appended """
    miss, frag = 0, 0

    while miss < max_misses:
        frag_name = f"{frag}{code.get_suffix()}"
        frag_url = f"{CONFIG.base_url}{DEFERRED}{CONFIG.gwt_permutation}/{frag_name}"

        try:
            fragment_code = http_client.get(frag_url)
            logging.info(f"+ Fragment : {frag_url}")
            code.add_line(fragment_code.get_content_array())
        except:
            miss += 1

        frag += 1

    return code


def get_permutation(code: Code):
    permutations = extract_permutations(code)
    logging.info(f"Found {len(permutations)} permutations")

    for permutation in permutations:
        CONFIG.gwt_permutation = permutation

        suffix = code.get_name().split(".")[-1]
        if code.get_type() == CodeType.BOOTSTRAP:
            suffix = code.get_permutation_suffix()

        target = f"{CONFIG.base_url}{permutation}.cache.{suffix}"

        try:
            code = http_client.get(target)
        except:
            logging.error(f"Error getting permutation {target}")
            continue

        return code

    return None


##################################################
# Main
##################################################
def main():
    global http_client

    """ Main function to orchestrates the script """
    parser = argparse.ArgumentParser(description=DESCRIPTON, epilog=EXAMPLE)
    parser.add_argument(
        "--version", action="version", version="%(prog)s {}".format(VERSION)
    )
    parser.add_argument(
        "-u", "--url", metavar="<TARGET_URL>",
        required="-F" not in sys.argv and "--file" not in sys.argv,
        help="URL of the target GWT {name}.nocache.js bootstrap or {hex}.cache.js file",
        type=url_mode_checks
    )
    parser.add_argument(
        "-F", "--file", metavar="<FILE>", default=None,
        required="-u" not in sys.argv and "--url" not in sys.argv,
        help="path to the local copy of a {hex}.cache.js GWT permutation file",
        type=file_mode_checks
    )
    parser.add_argument(
        "-b", "--base", metavar="<BASE_URL>", default=None,
        help="specifies the base URL for a given permutation file in -F/--file mode"
    )
    parser.add_argument(
        "-p", "--proxy", metavar="<PROXY>", default=None,
        help="URL for an optional HTTP proxy (e.g. -p http://127.0.0.1:8080)"
    )
    parser.add_argument(
        "-c", "--cookies", metavar="<COOKIES>", default=None,
        help="any cookies required to access the remote resource in -u/--url mode "
             + "(e.g. 'JSESSIONID=ABCDEF; OTHER=XYZABC')"
    )
    parser.add_argument(
        "-f", "--filter", metavar="<FILTER>", default="",
        help="case-sensitive method filter for output (e.g. -f AuthSvc.checkSession)"
    )
    parser.add_argument(
        "--basic", action="store_true", default=False,
        help="enables HTTP Basic authentication if require. Prompts for credentials"
    )
    parser.add_argument(
        "--rpc", action="store_true", default=False,
        required="--probe" in sys.argv,
        help="attempts to generate a serialized RPC request for each method"
    )
    parser.add_argument(
        "--probe", action="store_true", default=False,
        help="sends an HTTP probe request to test each method returned in --rpc mode"
    )
    parser.add_argument(
        "--svc", action="store_true", default=False,
        help="displays enumerated service information, in addition to methods"
    )
    parser.add_argument(
        "--code", action="store_true", default=False,
        help="skips all and dumps the 're-formatted' state of the provided resource"
    )
    parser.add_argument(
        "--color", action="store_true", default=False,
        help="enables coloured console output"
    )
    parser.add_argument(
        "--backup", metavar="DIR", nargs='?', default=False,
        help="creates a local backup of retrieved code in -u/--url mode"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", default=False,
        help="enables quiet mode (minimal output)"
    )

    args = parser.parse_args()

    if args.base is None:
        base_url = '/'.join((args.url.split('/')[:-1])) + '/'
    else:
        base_url = args.base

    CONFIG.base_url = base_url
    http_client = HttpClient(args, base_url)

    # Print target infos banner
    if not args.code and not args.quiet:
        if args.file is None:
            target = args.url
        else:
            target = args.file

        logging.info(f"Analysing {target}")

    # Get and classify file
    if args.file is not None:
        code = read_file(args.file)
    else:

        code = http_client.get(args.url)

    # Prints a warning if unreliable / unexpected use identified
    if args.file is not None and args.code is False:
        if code.get_type() == CodeType.FRAGMENT:
            logging.warning("Analysing a deferred fragment in -F/--file mode will most likely cause errors")
        elif code.get_type() == CodeType.PERMUTATION:
            logging.warning("Individual permutation files in -F/--file mode do not include deferred fragments")

    if code.get_type() == CodeType.BOOTSTRAP and args.file is None:
        code = get_permutation(code)

    set_globals(code.get_content_array(), args)

    if is_fragmented(code) and args.file is None:
        logging.info("Code seems to be fragmented")
        code = append_fragments(code)

    backup_file = None
    if args.backup is not False and args.file is None:
        backup_file = code.save(CONFIG.gwt_permutation, args.backup)

    if args.code:
        logging.info(str(code))

    if not args.quiet:
        logging.info(str(CONFIG))

    service_objects = extract_service_info(code)
    if args.svc:
        present_services(service_objects)

    method_objects = extract_method_info(code, service_objects)
    count = present_methods(method_objects, args.quiet, args.probe)

    if not args.quiet:
        present_summary(service_objects, method_objects, count, backup_file)


if __name__ == "__main__":
    main()
