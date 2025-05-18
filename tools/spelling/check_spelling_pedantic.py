#! /usr/bin/env python3

from __future__ import print_function

import argparse
import locale
import math
import os
import re
import subprocess
import sys
import json
import requests
from collections import defaultdict

from functools import partial
from itertools import chain

# Handle function rename between python 2/3.
try:
    input = raw_input
except NameError:
    pass

try:
    cmp
except NameError:

    def cmp(x, y):
        return (x > y) - (x < y)


CURR_DIR = os.path.dirname(os.path.realpath(__file__))

# Special comment commands control behavior.
SPELLCHECK_OFF = "SPELLCHECKER(off)"
SPELLCHECK_ON = "SPELLCHECKER(on)"
SPELLCHECK_SKIP_FILE = "SPELLCHECKER(skip-file)"
SPELLCHECK_SKIP_BLOCK = "SPELLCHECKER(skip-block)"

# Comment extraction patterns
INLINE_COMMENT = re.compile(r'(?:^|[^:"])//( .*?$|$)|/\*+(.*?)\*+/')
MULTI_COMMENT_START = re.compile(r'/\*(.*?)$')
MULTI_COMMENT_END = re.compile(r'^(.*?)\*/')

# Proto-specific patterns
PROTO_SERVICE = re.compile(r'service\s+\w+')
PROTO_MESSAGE = re.compile(r'message\s+\w+')
PROTO_ENUM = re.compile(r'enum\s+\w+')
PROTO_FIELD_TYPE = re.compile(r'\b(string|int32|int64|uint32|uint64|bool|double|float|bytes|repeated|optional|required|oneof|map|google\.protobuf\.\w+)\b')

# TODO and doc patterns
TODO = re.compile(r'(TODO|NOTE|FIXME|HACK|XXX)\s*\(@?[A-Za-z0-9-]+\):?')
METHOD_DOC = re.compile(r'@(param\s+\w+|return(\s+const)?\s+\w+|brief|details|note|warning)')

# Text patterns to mask
CAMEL_CASE = re.compile(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)')
BASE64 = re.compile(r'^[\s*]+([A-Za-z0-9/+=]{16,})\s*$')
NUMBER = re.compile(r'\d')
HEX = re.compile(r'(?:^|\s|[(])([A-Fa-f0-9]{8,})(?:$|\s|[.,)])')
HEX_SIG = re.compile(r'(?:\W|^)([A-Fa-f0-9]{2}(:[A-Fa-f0-9]{2})+)(?:\W|$)')
PREFIXED_HEX = re.compile(r'0x[A-Fa-f0-9]+')
UUID = re.compile(r'[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}')
IPV6_ADDR = re.compile(r'(?:\W|^)([A-Fa-f0-9]+:[A-Fa-f0-9:]+/[0-9]{1,3})(?:\W|$)')
QUOTED_WORD = re.compile(r'((["\'])[A-Za-z0-9.:-]+(\2))|(\*[A-Za-z0-9.:-]+\*)')
QUOTED_EXPR = re.compile(r'`[A-Za-z0-9:()<>_.,/{}\[\]&*-]+`')
FLAG = re.compile(r'\W([-%][A-Za-z]+)')
USER = re.compile(r'\W(@[A-Za-z0-9-]+)')
ABSPATH = re.compile(r'(?:\s|^)((/[A-Za-z0-9_.*-]+)+)(?:\s|$)')
FILEREF = re.compile(r'(?:\s|^)([A-Za-z0-9_./-]+\.(cc|js|h|py|sh|proto|yaml|json))(?:\s|$)')
ORDINALS = re.compile(r'([0-9]*1st|[0-9]*2nd|[0-9]*3rd|[0-9]+th)')

# Grammar and style patterns
PASSIVE_VOICE = re.compile(r'\b(is|are|was|were|be|been|being)\s+\w+ed\b', re.IGNORECASE)
REDUNDANT_WORDS = re.compile(r'\b(very\s+unique|more\s+perfect|most\s+unique|completely\s+finished|totally\s+destroyed|absolutely\s+essential)\b', re.IGNORECASE)
SENTENCE_STARTERS = re.compile(r'^\s*(This|That|These|Those|There|Here)\s+', re.IGNORECASE)
WEAK_WORDS = re.compile(r'\b(very|really|quite|rather|somewhat|just|actually|basically|literally)\b', re.IGNORECASE)

# Common word confusions
WORD_CONFUSIONS = {
    'there': ['their', 'they\'re'],
    'their': ['there', 'they\'re'],
    'they\'re': ['there', 'their'],
    'its': ['it\'s'],
    'it\'s': ['its'],
    'your': ['you\'re'],
    'you\'re': ['your'],
    'then': ['than'],
    'than': ['then'],
    'affect': ['effect'],
    'effect': ['affect'],
    'accept': ['except'],
    'except': ['accept'],
    'loose': ['lose'],
    'lose': ['loose']
}

# Valid dictionary words
DICTIONARY_WORD = re.compile(r"^[A-Za-z']+$")

DEBUG = 0
COLOR = True
MARK = False

# Error severity levels
SEVERITY_SPELLING = "spelling"
SEVERITY_GRAMMAR = "grammar"
SEVERITY_STYLE = "style"
SEVERITY_CLARITY = "clarity"

def red(s):
    if COLOR:
        return "\33[1;31m" + s + "\033[0m"
    return s

def green(s):
    if COLOR:
        return "\33[1;32m" + s + "\033[0m"
    return s

def blue(s):
    if COLOR:
        return "\33[1;34m" + s + "\033[0m"
    return s

def yellow(s):
    if COLOR:
        return "\33[1;33m" + s + "\033[0m"
    return s

def magenta(s):
    if COLOR:
        return "\33[1;35m" + s + "\033[0m"
    return s

def debug(s):
    if DEBUG > 0:
        print(s)

def debug1(s):
    if DEBUG > 1:
        print(s)

class Error:
    """Represents an error with type, position, and suggestions."""

    def __init__(self, word, offset, suggestions, severity, rule_id=None, message=None):
        self.word = word
        self.offset = offset
        self.suggestions = suggestions
        self.severity = severity
        self.rule_id = rule_id
        self.message = message or f"Misspelled word: {word}"

    def get_color(self):
        color_map = {
            SEVERITY_SPELLING: red,
            SEVERITY_GRAMMAR: magenta,
            SEVERITY_STYLE: yellow,
            SEVERITY_CLARITY: blue
        }
        return color_map.get(self.severity, red)

class SpellChecker:
    """Aspell-based spell checker."""

    def __init__(self, dictionary_file):
        self.dictionary_file = dictionary_file
        self.aspell = None
        self.prefixes = []
        self.suffixes = []
        self.prefix_re = None
        self.suffix_re = None

    def start(self):
        words, prefixes, suffixes = self.load_dictionary()

        self.prefixes = prefixes
        self.suffixes = suffixes

        self.prefix_re = re.compile(r"(?:\s|^)((%s)-)" % ("|".join(prefixes)), re.IGNORECASE)
        self.suffix_re = re.compile(r"(-(%s))(?:\s|$)" % ("|".join(suffixes)), re.IGNORECASE)

        # Generate aspell personal dictionary.
        pws = os.path.join(CURR_DIR, '.aspell.en.pws')
        with open(pws, 'w') as f:
            f.write("personal_ws-1.1 en %d\n" % (len(words)))
            f.writelines(words)

        # Start an aspell process.
        aspell_args = ["aspell", "pipe", "--lang=en_US", "--encoding=utf-8", "--personal=" + pws]
        self.aspell = subprocess.Popen(
            aspell_args,
            bufsize=4096,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True)

        # Read the version line that aspell emits on startup.
        self.aspell.stdout.readline()

    def stop(self):
        if not self.aspell:
            return

        self.aspell.stdin.close()
        self.aspell.wait()
        self.aspell = None

    def check(self, line):
        if line.strip() == '':
            return []

        self.aspell.poll()
        if self.aspell.returncode is not None:
            print("aspell quit unexpectedly: return code %d" % (self.aspell.returncode))
            sys.exit(2)

        debug1("ASPELL< %s" % (line))

        self.aspell.stdin.write(line + os.linesep)
        self.aspell.stdin.flush()

        errors = []
        while True:
            result = self.aspell.stdout.readline().strip()
            debug1("ASPELL> %s" % (result))

            # Check for end of results.
            if result == "":
                break

            t = result[0]
            if t == "*" or t == "-" or t == "+":
                continue

            original, rem = result[2:].split(" ", 1)

            if t == "#":
                errors.append(Error(original, int(rem), [], SEVERITY_SPELLING))
            elif t == '&' or t == '?':
                _, rem = rem.split(" ", 1)
                o, rem = rem.split(": ", 1)
                suggestions = rem.split(", ")
                errors.append(Error(original, int(o), suggestions, SEVERITY_SPELLING))
            else:
                print("aspell produced unexpected output: %s" % (result))
                sys.exit(2)

        return errors

    def load_dictionary(self):
        all_words = []
        with open(self.dictionary_file, 'r') as f:
            all_words = f.readlines()

        words = [w for w in all_words if len(w.strip()) > 0 and re.match(DICTIONARY_WORD, w)]
        suffixes = [w.strip()[1:] for w in all_words if w.startswith('-')]
        prefixes = [w.strip()[:-1] for w in all_words if w.strip().endswith('-')]

        for word in words:
            if word.isupper():
                words += word.lower()

        return (words, prefixes, suffixes)

    def add_words(self, additions):
        lines = []
        with open(self.dictionary_file, 'r') as f:
            lines = f.readlines()

        additions = [w + os.linesep for w in additions]
        additions.sort()

        idx = 0
        add_idx = 0
        while idx < len(lines) and add_idx < len(additions):
            line = lines[idx]
            if len(line.strip()) != 0 and line[0] != "#" and line[0] != '-':
                c = cmp(additions[add_idx], line)
                if c < 0:
                    lines.insert(idx, additions[add_idx])
                    add_idx += 1
                elif c == 0:
                    add_idx += 1
            idx += 1

        lines += additions[add_idx:]

        with open(self.dictionary_file, 'w') as f:
            f.writelines(lines)

        self.stop()
        self.start()

class GrammarChecker:
    """LanguageTool-based grammar checker."""

    def __init__(self, server_url="http://localhost:8081", use_online=False):
        self.server_url = server_url
        self.use_online = use_online
        self.online_url = "https://api.languagetool.org/v2/check"
        self.available = self._check_availability()

    def _check_availability(self):
        """Check if LanguageTool server is available."""
        try:
            if self.use_online:
                response = requests.get(f"{self.online_url.replace('/check', '')}/languages", timeout=5)
                return response.status_code == 200
            else:
                response = requests.get(f"{self.server_url}/v2/languages", timeout=5)
                return response.status_code == 200
        except:
            return False

    def check(self, text):
        """Check text for grammar errors."""
        if not self.available:
            return []

        try:
            url = self.online_url if self.use_online else f"{self.server_url}/v2/check"
            data = {
                'text': text,
                'language': 'en-US',
                'enabledRules': 'PASSIVE_VOICE,REDUNDANT_WORDS,SENTENCE_WHITESPACE,DOUBLE_PUNCTUATION'
            }

            response = requests.post(url, data=data, timeout=10)
            result = response.json()

            errors = []
            for match in result.get('matches', []):
                offset = match['offset']
                length = match['length']
                word = text[offset:offset+length]

                suggestions = [r['value'] for r in match.get('replacements', [])]
                rule_id = match.get('rule', {}).get('id', '')
                message = match.get('message', '')

                # Determine severity based on rule category
                category = match.get('rule', {}).get('category', {}).get('id', '')
                if 'GRAMMAR' in rule_id or 'VERB' in rule_id:
                    severity = SEVERITY_GRAMMAR
                elif 'STYLE' in rule_id or 'PASSIVE' in rule_id:
                    severity = SEVERITY_STYLE
                else:
                    severity = SEVERITY_CLARITY

                errors.append(Error(word, offset, suggestions, severity, rule_id, message))

            return errors
        except Exception as e:
            debug(f"Grammar check failed: {e}")
            return []

class StyleChecker:
    """Checks for style and clarity issues."""

    def check(self, text):
        """Check text for style issues."""
        errors = []

        # Check for passive voice
        for match in PASSIVE_VOICE.finditer(text):
            errors.append(Error(
                match.group(),
                match.start(),
                ["Consider using active voice"],
                SEVERITY_STYLE,
                "PASSIVE_VOICE",
                "Passive voice can make text less engaging"
            ))

        # Check for redundant words
        for match in REDUNDANT_WORDS.finditer(text):
            errors.append(Error(
                match.group(),
                match.start(),
                [match.group().split()[1]],  # Suggest removing redundant word
                SEVERITY_STYLE,
                "REDUNDANT_WORDS",
                "Remove redundant words for clearer writing"
            ))

        # Check for weak words
        for match in WEAK_WORDS.finditer(text):
            errors.append(Error(
                match.group(),
                match.start(),
                ["Consider a stronger word"],
                SEVERITY_STYLE,
                "WEAK_WORDS",
                "Weak words can dilute your message"
            ))

        # Check for word confusions
        words = re.findall(r'\b\w+\'?\w*\b', text.lower())
        for i, word in enumerate(words):
            if word in WORD_CONFUSIONS:
                start_pos = text.lower().find(word)
                if start_pos != -1:
                    errors.append(Error(
                        word,
                        start_pos,
                        WORD_CONFUSIONS[word],
                        SEVERITY_SPELLING,
                        "WORD_CONFUSION",
                        f"Commonly confused with: {', '.join(WORD_CONFUSIONS[word])}"
                    ))

        return errors

def check_camel_case(checker, err):
    """Split camel case words and check them."""
    parts = re.findall(CAMEL_CASE, err.word)

    if len(parts) <= 1:
        return [err]

    split_errs = []
    part_offset = 0
    for part in parts:
        split_err = checker.check(part)
        if split_err:
            split_errs += [Error(part, err.offset + part_offset, split_err[0].suggestions, SEVERITY_SPELLING)]
        part_offset += len(part)

    return split_errs

def check_affix(checker, err):
    """Check for valid affixes."""
    for prefix in checker.prefixes:
        if err.word.lower().startswith(prefix.lower()):
            root = err.word[len(prefix):]
            if root != '':
                root_err = checker.check(root)
                if not root_err:
                    return []

    for suffix in checker.suffixes:
        if err.word.lower().endswith(suffix.lower()):
            root = err.word[:-len(suffix)]
            if root != '':
                root_err = checker.check(root)
                if not root_err:
                    return []

    return [err]

def mask_with_regex(comment, regex, group, secondary=None):
    """Mask patterns in comment to avoid false positives."""
    found = False
    for m in regex.finditer(comment):
        if secondary and secondary.search(m.group(group)) is None:
            continue

        start = m.start(group)
        end = m.end(group)
        comment = comment[:start] + (' ' * (end - start)) + comment[end:]
        found = True

    return (comment, found)

def check_comment(spell_checker, grammar_checker, style_checker, offset, comment, check_grammar=True, check_style=True):
    """Check comment for spelling, grammar, and style issues."""
    original_comment = comment

    # Strip smart quotes
    smart_quotes = {"\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"'}
    for sq, q in smart_quotes.items():
        comment = comment.replace(sq, q)

    # Mask various patterns to avoid false positives
    comment, _ = mask_with_regex(comment, TODO, 0)
    comment, _ = mask_with_regex(comment, METHOD_DOC, 0)
    comment, _ = mask_with_regex(comment, BASE64, 1, NUMBER)
    comment, _ = mask_with_regex(comment, HEX, 1)
    comment, _ = mask_with_regex(comment, PREFIXED_HEX, 0)
    comment, _ = mask_with_regex(comment, UUID, 0)
    comment, _ = mask_with_regex(comment, IPV6_ADDR, 1)
    comment, _ = mask_with_regex(comment, PROTO_FIELD_TYPE, 0)
    comment, _ = mask_with_regex(comment, QUOTED_WORD, 0)
    comment, _ = mask_with_regex(comment, QUOTED_EXPR, 0)
    comment, _ = mask_with_regex(comment, FLAG, 1)
    comment, _ = mask_with_regex(comment, USER, 1)
    comment, _ = mask_with_regex(comment, ABSPATH, 1)
    comment, _ = mask_with_regex(comment, FILEREF, 1)
    comment, _ = mask_with_regex(comment, ORDINALS, 0)

    if spell_checker.prefix_re:
        comment, _ = mask_with_regex(comment, spell_checker.prefix_re, 1)
    if spell_checker.suffix_re:
        comment, _ = mask_with_regex(comment, spell_checker.suffix_re, 1)

    if comment.strip() == "":
        return []

    if not comment[0].isalnum():
        comment = ' ' + comment[1:]

    all_errors = []

    # Spell checking
    spelling_errors = spell_checker.check(comment)
    for err in spelling_errors:
        err.offset += offset

    # Process camel case and affixes
    spelling_errors = [*chain.from_iterable(map(lambda err: check_camel_case(spell_checker, err), spelling_errors))]
    spelling_errors = [*chain.from_iterable(map(lambda err: check_affix(spell_checker, err), spelling_errors))]

    all_errors.extend(spelling_errors)

    # Grammar checking
    if check_grammar and grammar_checker and grammar_checker.available:
        grammar_errors = grammar_checker.check(original_comment)
        for err in grammar_errors:
            err.offset += offset
        all_errors.extend(grammar_errors)

    # Style checking
    if check_style and style_checker:
        style_errors = style_checker.check(original_comment)
        for err in style_errors:
            err.offset += offset
        all_errors.extend(style_errors)

    return all_errors

def print_error_detailed(file, line_offset, lines, errors):
    """Print detailed error information with context."""
    line = lines[line_offset]
    prefix = f"{file}:{line_offset + 1}:"

    # Group errors by type
    errors_by_type = defaultdict(list)
    for error in errors:
        errors_by_type[error.severity].append(error)

    # Create highlighted line
    highlighted_line = line
    for error in reversed(sorted(errors, key=lambda e: e.offset)):
        color_func = error.get_color()
        highlighted_line = (highlighted_line[:error.offset] +
                          color_func(error.word) +
                          highlighted_line[error.offset + len(error.word):])

    print(f"{prefix}{highlighted_line.rstrip()}")

    if MARK:
        # Print carets
        marks = ' ' * len(prefix)
        last = 0
        for error in errors:
            marks += (' ' * (error.offset - last)) + '^'
            last = error.offset + 1
        print(marks)

    # Print detailed error information
    for severity, severity_errors in errors_by_type.items():
        severity_name = severity.upper()
        color_func = severity_errors[0].get_color()
        print(f"  {color_func(f'{severity_name} ISSUES:')}")

        for error in severity_errors:
            print(f"    • {error.word}: {error.message}")
            if error.suggestions:
                suggestions_str = ', '.join(error.suggestions[:5])
                print(f"      Suggestions: {suggestions_str}")
            if error.rule_id:
                print(f"      Rule: {error.rule_id}")
            print()

def print_error_summary(file, line_offset, lines, errors):
    """Print summary of errors."""
    line = lines[line_offset]
    prefix = f"{file}:{line_offset + 1}:"

    # Highlight all errors
    highlighted_line = line
    for error in reversed(sorted(errors, key=lambda e: e.offset)):
        color_func = error.get_color()
        highlighted_line = (highlighted_line[:error.offset] +
                          color_func(error.word) +
                          highlighted_line[error.offset + len(error.word):])

    print(f"{prefix}{highlighted_line.rstrip()}")

    # Count errors by type
    error_counts = defaultdict(int)
    for error in errors:
        error_counts[error.severity] += 1

    # Print summary
    summary_parts = []
    for severity, count in error_counts.items():
        color_func = Error("", 0, [], severity).get_color()
        summary_parts.append(f"{color_func(severity)}: {count}")

    print(f"  Errors: {', '.join(summary_parts)}")
    print()

def fix_error(spell_checker, file, line_offset, lines, errors):
    """Interactive error fixing."""
    print_error_detailed(file, line_offset, lines, errors)

    fixed = {}
    replacements = []
    additions = []

    for error in errors:
        if error.word in fixed:
            replacements.append(fixed[error.word])
            continue

        print(f"\n{error.get_color()(error.word)} ({error.severity}): {error.message}")

        if error.suggestions:
            print("Suggestions:")
            for i, suggestion in enumerate(error.suggestions):
                print(f"  {i}: {suggestion}")

        print("Options:")
        print("  a: accept and add to dictionary (spelling errors only)")
        print("  f <word>: replace with given word")
        print("  i: ignore this error")
        print("  r <word>: replace and add to dictionary (spelling errors only)")
        print("  x: abort")

        replacement = ""
        while replacement == "":
            try:
                choice = input("> ")
            except EOFError:
                choice = "x"

            if choice == "x":
                print("Checking aborted.")
                sys.exit(2)
            elif choice == "a" and error.severity == SEVERITY_SPELLING:
                replacement = error.word
                additions.append(error.word)
            elif choice.startswith("f "):
                replacement = choice[2:].strip()
            elif choice == "i":
                replacement = error.word
            elif choice.startswith("r ") and error.severity == SEVERITY_SPELLING:
                replacement = choice[2:].strip()
                if re.match(DICTIONARY_WORD, replacement):
                    additions.append(replacement)
            else:
                try:
                    idx = int(choice)
                    if 0 <= idx < len(error.suggestions):
                        replacement = error.suggestions[idx]
                    else:
                        print("Invalid choice")
                except ValueError:
                    print("Invalid choice")

        fixed[error.word] = replacement
        replacements.append(replacement)

    # Apply replacements
    line = lines[line_offset]
    for error, replacement in zip(reversed(sorted(errors, key=lambda e: e.offset)), reversed(replacements)):
        if error.word != replacement:
            line = line[:error.offset] + replacement + line[error.offset + len(error.word):]
    lines[line_offset] = line

    # Update dictionary
    if additions:
        spell_checker.add_words(additions)

class Comment:
    """Comment with location information."""

    def __init__(self, line, col, text, last_on_line):
        self.line = line
        self.col = col
        self.text = text
        self.last_on_line = last_on_line

def extract_comments(lines):
    """Extract comments from source lines."""
    in_comment = False
    comments = []

    for line_idx, line in enumerate(lines):
        line_comments = []
        last = 0

        if in_comment:
            mc_end = MULTI_COMMENT_END.search(line)
            if mc_end is None:
                line_comments.append((0, line))
            else:
                line_comments.append((0, mc_end.group(1)))
                last = mc_end.end()
                in_comment = False

        if not in_comment:
            for inline in INLINE_COMMENT.finditer(line, last):
                m = inline.lastindex
                line_comments.append((inline.start(m), inline.group(m)))
                last = inline.end(m)

            if last < len(line):
                mc_start = MULTI_COMMENT_START.search(line, last)
                if mc_start is not None:
                    line_comments.append((mc_start.start(1), mc_start.group(1)))
                    in_comment = True

        for idx, line_comment in enumerate(line_comments):
            col, text = line_comment
            last_on_line = idx + 1 >= len(line_comments)
            comments.append(Comment(line=line_idx, col=col, text=text, last_on_line=last_on_line))

    # Handle control statements
    result = []
    n = 0

    while n < len(comments):
        text = comments[n].text

        if SPELLCHECK_SKIP_FILE in text:
            return []

        if SPELLCHECK_ON in text:
            pos = text.find(SPELLCHECK_ON)
            comments[n].text = text[:pos] + ' ' * len(SPELLCHECK_ON) + text[pos + len(SPELLCHECK_ON):]
            result.append(comments[n])
            n += 1
        elif SPELLCHECK_OFF in text or SPELLCHECK_SKIP_BLOCK in text:
            n += 1
            while n < len(comments) and SPELLCHECK_ON not in comments[n].text:
                n += 1
            if n < len(comments):
                n += 1
        else:
            result.append(comments[n])
            n += 1

    return result

def check_file(spell_checker, grammar_checker, style_checker, file, lines, error_handler, check_grammar=True, check_style=True):
    """Check a file for all types of errors."""
    comments = extract_comments(lines)
    total_errors = 0

    for comment in comments:
        errors = check_comment(spell_checker, grammar_checker, style_checker,
                             comment.col, comment.text, check_grammar, check_style)

        if comment.last_on_line and errors:
            total_errors += len(errors)
            error_handler(file, comment.line, lines, errors)

    return (len(comments), total_errors)

def execute(files, dictionary_file, fix, detailed_output=False, check_grammar=True, check_style=True, use_online_grammar=False):
    """Execute the checking process."""
    # Initialize checkers
    spell_checker = SpellChecker(dictionary_file)
    spell_checker.start()

    grammar_checker = None
    if check_grammar:
        grammar_checker = GrammarChecker(use_online=use_online_grammar)
        if not grammar_checker.available:
            print(f"{yellow('Warning: Grammar checker not available. Install LanguageTool server or use --online-grammar')}")

    style_checker = StyleChecker() if check_style else None

    # Determine error handler
    if fix:
        handler = partial(fix_error, spell_checker)
    elif detailed_output:
        handler = print_error_detailed
    else:
        handler = print_error_summary

    # Process files
    total_files = 0
    total_comments = 0
    total_errors = 0
    files_with_errors = []
    error_summary = defaultdict(int)

    print(f"\n{blue('='*70)}")
    print(f"{blue('INTELLIGENT SPELL & GRAMMAR CHECKER')}")
    print(f"{blue('='*70)}")

    checkers_enabled = []
    if spell_checker: checkers_enabled.append("Spelling")
    if grammar_checker and grammar_checker.available: checkers_enabled.append("Grammar")
    if style_checker: checkers_enabled.append("Style")

    print(f"Enabled checkers: {green(', '.join(checkers_enabled))}")
    print(f"Processing {len(files)} files...")
    print()

    for path in files:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                total_files += 1

                (num_comments, num_errors) = check_file(
                    spell_checker, grammar_checker, style_checker,
                    path, lines, handler, check_grammar, check_style
                )

                total_comments += num_comments
                total_errors += num_errors

                if num_errors > 0:
                    files_with_errors.append((path, num_errors))

            if fix and num_errors > 0:
                with open(path, 'w', encoding='utf-8') as f:
                    f.writelines(lines)

        except Exception as e:
            print(f"{red(f'Error processing {path}: {e}')}")

    spell_checker.stop()

    # Print summary
    print(f"{blue('='*70)}")
    print(f"{blue('SUMMARY')}")
    print(f"{blue('='*70)}")
    print(f"Files processed: {green(str(total_files))}")
    print(f"Comments checked: {green(str(total_comments))}")
    print(f"Total errors: {red(str(total_errors)) if total_errors > 0 else green(str(total_errors))}")

    if files_with_errors:
        print(f"\n{red('Files with errors:')}")
        for file_path, error_count in files_with_errors:
            print(f"  • {file_path}: {error_count} error(s)")
    else:
        print(f"\n{green('✓ No errors found!')}")

    print(f"{blue('='*70)}\n")

    return total_errors == 0

if __name__ == "__main__":
    # Set locale
    try:
        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
    except:
        locale.setlocale(locale.LC_ALL, 'C.UTF-8')

    default_dictionary = os.path.join(CURR_DIR, 'spelling_dictionary.txt')

    parser = argparse.ArgumentParser(description="Intelligent spell, grammar, and style checker for code comments.")
    parser.add_argument('operation_type', choices=['check', 'fix'], help="Check or fix errors")
    parser.add_argument('target_paths', nargs="*", help="Files or directories to process")
    parser.add_argument('-d', '--debug', action='count', default=0, help="Debug mode")
    parser.add_argument('--mark', action='store_true', help="Mark errors with carets")
    parser.add_argument('--dictionary', default=default_dictionary, help="Dictionary file")
    parser.add_argument('--color', choices=['on', 'off', 'auto'], default="auto", help="Colorized output")
    parser.add_argument('--proto-only', action='store_true', help="Check only .proto files")
    parser.add_argument('--detailed', action='store_true', help="Detailed error output")
    parser.add_argument('--no-grammar', action='store_true', help="Disable grammar checking")
    parser.add_argument('--no-style', action='store_true', help="Disable style checking")
    parser.add_argument('--online-grammar', action='store_true', help="Use online LanguageTool API")
    parser.add_argument('--test-ignore-exts', action='store_true', help="Ignore file extensions (for testing)")

    args = parser.parse_args()

    # Configure output
    COLOR = args.color == "on" or (args.color == "auto" and sys.stdout.isatty())
    DEBUG = args.debug
    MARK = args.mark

    # Determine file paths
    if not args.target_paths:
        args.target_paths = ['./api'] if args.proto_only else ['./api', './include', './source', './test', './tools']

    # Filter out third_party
    paths = [p for p in args.target_paths if not p.startswith('./third_party/')]

    # Determine file extensions
    if args.proto_only:
        exts = ['.proto']
    elif args.test_ignore_exts:
        exts = None
    else:
        exts = ['.cc', '.js', '.h', '.proto']

    # Collect target files
    target_paths = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                target_paths.extend([
                    os.path.join(root, f) for f in files
                    if exts is None or os.path.splitext(f)[1] in exts
                ])
        elif os.path.isfile(p) and (exts is None or os.path.splitext(p)[1] in exts):
            target_paths.append(p)

    if args.proto_only:
        target_paths = [p for p in target_paths if p.endswith('.proto')]

    # Execute checking
    success = execute(
        target_paths,
        args.dictionary,
        args.operation_type == 'fix',
        args.detailed,
        not args.no_grammar,
        not args.no_style,
        args.online_grammar
    )

    if args.operation_type == 'check' and not success:
        print(f"{red('FAILED: Errors found. Run with fix to correct them.')}")
        sys.exit(1)
    elif args.operation_type == 'check':
        print(f"{green('SUCCESS: All checks passed!')}")
