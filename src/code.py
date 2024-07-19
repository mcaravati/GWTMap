import re
from abc import ABC, abstractmethod
from enum import Enum
from typing import List
import time

from utils import PERMUTATION_PATTERN, FRAGMENT_CALL_PATTERN

OBFUSCATED = "obfuscated"
CLEAR = "clear"


class CodeType(Enum):
    BOOTSTRAP = 0,
    PERMUTATION = 1,
    FRAGMENT = 2


def retab(code):
    tabs, tabbed_code = 0, ""
    for line in code.split("\n"):
        if line.strip() == "}":
            tabs -= 1

        tabbed_code += tabs * "\t" + line + "\n"
        if line.strip().endswith("{"):
            tabs += 1

    return tabbed_code


class Code(ABC):
    def __init__(self, file_name: str, file_content: str):
        self._name = file_name
        self._content = file_content
        self._content_array = self.clean()
        self._obfuscated = self.is_obfuscated()

    @abstractmethod
    def is_obfuscated(self) -> bool:
        pass

    @abstractmethod
    def get_type(self) -> CodeType:
        pass

    @abstractmethod
    def clean(self) -> List[str]:
        pass

    def get_content(self) -> str:
        return self._content

    def get_name(self) -> str:
        return self._name

    def add_line(self, line: str) -> None:
        self._content_array.extend(line)

    def get_content_array(self) -> List[str]:
        return self._content_array

    def get_suffix(self) -> str:
        return '.' + '.'.join(self._name.split('.')[-2:])

    def __str__(self):
        return '\n'.join(self.get_content_array())

    def save(self, permutation, directory="./", encoding="utf-8") -> str:
        output_code = ''.join(self.get_content_array())

        suffix = self.get_suffix()
        out_name = f"{directory}/{str(int(time.time()))}_{permutation}{suffix}"
        out_name = out_name.replace("//", "/")

        if not self.is_obfuscated():
            output_code = output_code.replace("\\", "\\\\").replace("\t", "")

        with open(out_name, "w", encoding=encoding) as file_obj:
            file_obj.write(output_code)

        return out_name


class FragmentCode(Code):
    def is_obfuscated(self) -> bool:
        obfuscated_pattern = re.compile(r"^function [a-zA-Z0-9_\.\$]+\(\)\{")

        return bool(obfuscated_pattern.search(self._content))

    def get_type(self) -> CodeType:
        return CodeType.FRAGMENT

    def clean(self) -> List[str]:
        content = self.get_content()

        if self.is_obfuscated():
            content = content.replace("{", "{\\n").replace("}", "\\n}\\n").replace(";", ";\\n")

        content = retab(bytes(content, encoding="ascii").decode('unicode_escape'))
        return content.split("\n")


class PermutationCode(Code):
    def is_obfuscated(self) -> bool:
        obfuscated_pattern = re.compile(r"[a-zA-Z0-9_\.\$]+\.onScriptLoad\(")

        return bool(obfuscated_pattern.search(self._content))

    def get_type(self) -> CodeType:
        return CodeType.PERMUTATION

    def clean(self) -> List[str]:
        if self.is_obfuscated():
            content = self._content.replace("{", "{\\n").replace("}", "\\n}\\n").replace(";", ";\\n")
            content = retab(bytes(content, encoding="ascii").decode('unicode_escape'))
            return content.split("\n")

        return self._content.split("\n")


class BootstrapCode(Code):
    def is_obfuscated(self) -> bool:
        obfuscated_pattern = re.compile(
            r"^function .*\(\) ?\{.*= ?[\"']begin.*?= ?[\"']bootstrap", flags=re.DOTALL
        )
        obfuscated_pattern_alt = re.compile(
            r"^function .*\(\) ?\{.*= ?[\"']bootstrap.*?= ?[\"']begin", flags=re.DOTALL
        )

        for pattern in [obfuscated_pattern, obfuscated_pattern_alt]:
            if bool(pattern.search(self._content)):
                return True

        return False

    def get_type(self) -> CodeType:
        return CodeType.BOOTSTRAP

    def clean(self) -> List[str]:
        if self.is_obfuscated():
            content = self._content.replace("\\", "\\\\")
            content = content.replace("{", "{\\n").replace("}", "\\n}\\n").replace(";", ";\\n")
            content = retab(bytes(content, encoding="ascii").decode('unicode_escape'))
            return content.split("\n")

        return self._content.split("\n")

    def get_permutation_suffix(self):
        suffix_pattern = r".cache.(html|js)"

        for line in self.get_content_array():
            for match in re.findall(suffix_pattern, line):
                return match

        return self.get_name().split(".")[-1]


def classify_code(file_name: str, file_content: str) -> Code:
    if ".nocache." in file_name:
        return BootstrapCode(file_name, file_content)
    elif re.search(rf"{PERMUTATION_PATTERN}\.cache\.", file_name):
        return PermutationCode(file_name, file_content)
    elif re.search(r'\d+\.cache\.', file_name):
        return FragmentCode(file_name, file_content)

    raise Exception(f"Could not classify code of given file: {file_name}")


def is_fragmented(code: Code) -> bool:
    if code.get_type() != CodeType.PERMUTATION:
        raise TypeError("Expected code type PERMUTATION, got {}".format(code.get_type()))

    content = ''.join(code.get_content())

    if not code.is_obfuscated():
        content = content.replace("\n", "")

    frag_calls = re.findall(FRAGMENT_CALL_PATTERN, content)
    return len(frag_calls) > 1
