# SPDX-License-Identifier: MIT

import abc
import re
import os
from typing import cast, Collection, Dict, List, Optional


class GrokPatternLoader:
    """Loads and expands grok patterns from a grok patterns file."""
    
    _patterns_cache: Optional[Dict[str, str]] = None
    
    @classmethod
    def load_patterns(cls, patterns_file: Optional[str] = None) -> Dict[str, str]:
        """
        Load grok patterns from file or use default location.
        
        :param patterns_file: path to grok patterns file
        :return: dictionary of pattern_name -> regex_pattern
        """
        if cls._patterns_cache is not None:
            return cls._patterns_cache
        
        if patterns_file is None:
            # Try to find grok patterns file relative to this module
            module_dir = os.path.dirname(os.path.abspath(__file__))
            possible_paths = [
                os.path.join(module_dir, '../../../grok_patterns_dump/grok-patterns'),
                os.path.join(module_dir, '../../../../grok_patterns_dump/grok-patterns'),
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    patterns_file = path
                    break
        
        patterns = {}
        if patterns_file and os.path.exists(patterns_file):
            with open(patterns_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if ' ' in line:
                        name, pattern = line.split(' ', 1)
                        patterns[name] = pattern
        
        cls._patterns_cache = patterns
        return patterns
    
    @classmethod
    def expand_pattern(cls, pattern: str, patterns_file: Optional[str] = None) -> str:
        """
        Expand grok patterns in a string (e.g., %{POSINT} -> \d+).
        
        :param pattern: pattern string with grok references
        :param patterns_file: optional path to grok patterns file
        :return: expanded regex pattern
        """
        patterns = cls.load_patterns(patterns_file)
        
        # Iteratively expand patterns until no more %{...} references exist
        max_iterations = 100
        iteration = 0
        while '%{' in pattern and iteration < max_iterations:
            iteration += 1
            # Find all %{PATTERN_NAME} references
            grok_refs = re.findall(r'%\{([A-Z0-9_]+)(?::[^}]*)?\}', pattern)
            if not grok_refs:
                break
            
            for ref in grok_refs:
                if ref in patterns:
                    # Replace %{NAME} and %{NAME:capture_name} with the pattern
                    # Use a function to avoid backslash interpretation in replacement
                    replacement = '(' + patterns[ref] + ')'
                    pattern = re.sub(
                        r'%\{' + ref + r'(?::[^}]*)?\}',
                        lambda m: replacement,
                        pattern
                    )
                else:
                    # Pattern not found, remove the reference to avoid infinite loop
                    pattern = re.sub(
                        r'%\{' + ref + r'(?::[^}]*)?\}',
                        '',
                        pattern
                    )
        
        return pattern


class AbstractMaskingInstruction(abc.ABC):

    def __init__(self, mask_with: str):
        self.mask_with = mask_with

    @abc.abstractmethod
    def mask(self, content: str, mask_prefix: str, mask_suffix: str) -> str:
        """
        Mask content according to this instruction and return the result.

        :param content: text to apply masking to
        :param mask_prefix: the prefix of any masks inserted
        :param mask_suffix: the suffix of any masks inserted
        """
        pass


class MaskingInstruction(AbstractMaskingInstruction):

    def __init__(self, pattern: str, mask_with: str, grok_patterns_file: Optional[str] = None):
        super().__init__(mask_with)
        # Expand grok patterns if present
        if '%{' in pattern:
            pattern = GrokPatternLoader.expand_pattern(pattern, grok_patterns_file)
        self.regex = re.compile(pattern)

    @property
    def pattern(self) -> str:
        return self.regex.pattern

    def mask(self, content: str, mask_prefix: str, mask_suffix: str) -> str:
        mask = mask_prefix + self.mask_with + mask_suffix
        return self.regex.sub(mask, content)


# Alias for `MaskingInstruction`.
RegexMaskingInstruction = MaskingInstruction


class LogMasker:

    def __init__(self, masking_instructions: Collection[AbstractMaskingInstruction],
                 mask_prefix: str, mask_suffix: str):
        self.mask_prefix = mask_prefix
        self.mask_suffix = mask_suffix
        self.masking_instructions = masking_instructions
        mask_name_to_instructions: Dict[str, List[AbstractMaskingInstruction]] = {}
        for mi in self.masking_instructions:
            mask_name_to_instructions.setdefault(mi.mask_with, [])
            mask_name_to_instructions[mi.mask_with].append(mi)
        self.mask_name_to_instructions = mask_name_to_instructions

    def mask(self, content: str) -> str:
        for mi in self.masking_instructions:
            # print(f"Applying mask '{mi.mask_with}' with pattern: {getattr(mi, 'pattern', 'N/A')} for content: {content}")
            content = mi.mask(content, self.mask_prefix, self.mask_suffix)
        return content

    @property
    def mask_names(self) -> Collection[str]:
        return self.mask_name_to_instructions.keys()

    def instructions_by_mask_name(self, mask_name: str) -> Collection[AbstractMaskingInstruction]:
        return cast(Collection[AbstractMaskingInstruction], self.mask_name_to_instructions.get(mask_name, []))

# Some masking examples
# ---------------------
#
# masking_instances = [
#    MaskingInstruction(r'((?<=[^A-Za-z0-9])|^)(([0-9a-f]{2,}:){3,}([0-9a-f]{2,}))((?=[^A-Za-z0-9])|$)', "ID"),
#    MaskingInstruction(r'((?<=[^A-Za-z0-9])|^)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})((?=[^A-Za-z0-9])|$)', "IP"),
#    MaskingInstruction(r'((?<=[^A-Za-z0-9])|^)([0-9a-f]{6,} ?){3,}((?=[^A-Za-z0-9])|$)', "SEQ"),
#    MaskingInstruction(r'((?<=[^A-Za-z0-9])|^)([0-9A-F]{4} ?){4,}((?=[^A-Za-z0-9])|$)', "SEQ"),
#
#    MaskingInstruction(r'((?<=[^A-Za-z0-9])|^)(0x[a-f0-9A-F]+)((?=[^A-Za-z0-9])|$)', "HEX"),
#    MaskingInstruction(r'((?<=[^A-Za-z0-9])|^)([\-\+]?\d+)((?=[^A-Za-z0-9])|$)', "NUM"),
#    MaskingInstruction(r'(?<=executed cmd )(".+?")', "CMD"),
# ]
