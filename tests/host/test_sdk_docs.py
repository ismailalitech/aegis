# SPDX-License-Identifier: Apache-2.0
"""The SDK's documents against the code, and the release hygiene of the repository:

  - docs/sdk-api-reference.md is what tools/gen_sdk_api_ref.py makes from sdk/include/aegis_sdk.h, and names every
    function, macro, structure and result of the header (so the generator cannot silently skip a declaration);
  - the numbers the porting guide and the versioning statement quote are the header's;
  - every document in docs/ is in the index, docs/README.md, and the relative links of the release documents resolve;
  - tools/check_release.py: every source file has an SPDX line, no secret is tracked.
"""
import os
import re
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import gen_sdk_api_ref  # noqa: E402

HEADER = os.path.join(ROOT, "sdk", "include", "aegis_sdk.h")


def read(*p):
    with open(os.path.join(ROOT, *p)) as f:
        return f.read()


class ApiReference(unittest.TestCase):
    def test_up_to_date(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "gen_sdk_api_ref.py"), "--check"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_every_declaration_of_the_header_is_in_it(self):
        src = read("sdk", "include", "aegis_sdk.h")
        ref = read("docs", "sdk-api-reference.md")
        names = set(re.findall(r"#define\s+(AEGIS_\w+)", src)) - {"AEGIS_SDK_H"}
        names |= set(re.findall(r"^\s*(AEGIS_(?:OK|ERR_\w+))", src, re.M))
        names |= set(re.findall(r"\b(aegis_\w+)\s*\(", src))
        names |= {"struct " + n for n in re.findall(r"struct\s+(\w+)\s*\{", src)}
        names |= {"enum " + n for n in re.findall(r"enum\s+(\w+)\s*\{", src)}
        self.assertGreater(len(names), 60)
        missing = sorted(n for n in names if n not in ref)
        self.assertEqual(missing, [], "declared in aegis_sdk.h but not in docs/sdk-api-reference.md")
        # each structure member, too
        for kind, d in gen_sdk_api_ref.parse(HEADER):
            if kind == "struct":
                for m in d["members"]:
                    self.assertIn(m["code"], ref)

    def test_results_numbered_as_the_compiler_numbers_them(self):
        items = gen_sdk_api_ref.parse(HEADER)
        enum = next(d for k, d in items if k == "enum")
        self.assertEqual([m["value"] for m in enum["members"]], list(range(len(enum["members"]))))
        self.assertEqual(enum["members"][0]["name"], "AEGIS_OK")
        self.assertEqual(enum["members"][-1]["name"], "AEGIS_ERR_BUFFER")


class GuideNumbers(unittest.TestCase):
    """The numbers the guide quotes, recomputed from the header's macros."""

    def macros(self):
        src = read("sdk", "include", "aegis_sdk.h")
        return {n: v for n, v in re.findall(r"#define\s+(AEGIS_\w+)\s+(\d+)u", src)}

    def test_sizes(self):
        m = {k: int(v) for k, v in self.macros().items()}
        guide = read("docs", "sdk-porting-guide.md")
        work_min = 18 + m["AEGIS_CHALLENGE_LEN"] + m["AEGIS_KEM_EK_LEN"]
        work_cred = 20 + m["AEGIS_CRED_MAX"] - 1 - m["AEGIS_SIG_LEN"]
        self.assertIn("`AEGIS_WORK_MIN` (%d bytes)" % work_min, guide)
        self.assertIn("(%d with small evidence)" % work_cred, guide)
        self.assertIn("`AEGIS_EAT_WORK_MIN` (%d)" % (10 + m["AEGIS_PK_LEN"]), guide)
        self.assertIn("`AEGIS_LINE_MAX` (%d bytes)" % m["AEGIS_LINE_MAX"], guide)
        self.assertIn("`AEGIS_REPLY_MAX` (%d)" % m["AEGIS_REPLY_MAX"], guide)
        # the context size is the one sdk/README.md gives
        self.assertIn("13232 bytes", read("sdk", "README.md"))
        self.assertIn("13232 bytes", guide)

    def test_versions_agree(self):
        api = self.macros()["AEGIS_SDK_API_VERSION"]
        cmake = read("sdk", "CMakeLists.txt")
        release = re.search(r"project\(aegis_sdk VERSION (\d+\.\d+\.\d+)", cmake).group(1)
        self.assertEqual(re.search(r"set\(AEGIS_SDK_API_VERSION (\d+)\)", cmake).group(1), api)
        self.assertEqual(release.split(".")[0], api, "the major release is the API version")
        for doc in (("docs", "sdk-versioning.md"), ("docs", "sdk-porting-guide.md")):
            text = read(*doc)
            self.assertIn(release, text, doc)
            self.assertIn("API version %s" % api, text.replace("**", ""), doc)


class DocsIndex(unittest.TestCase):
    RELEASE_DOCS = [("docs", "README.md"), ("docs", "sdk-porting-guide.md"), ("docs", "sdk-versioning.md"),
                    ("docs", "sdk-api-reference.md"), ("sdk", "README.md"),
                    ("sdk", "examples", "simulated-device", "README.md"), ("container", "README.md"), ("README.md",)]

    def test_every_document_is_indexed(self):
        index = read("docs", "README.md")
        for name in sorted(os.listdir(os.path.join(ROOT, "docs"))):
            if name.endswith(".md") and name != "README.md":
                self.assertIn("(%s)" % name, index, name)

    def test_relative_links_resolve(self):
        for doc in self.RELEASE_DOCS:
            path = os.path.join(ROOT, *doc)
            for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", read(*doc)):
                if re.match(r"[a-z]+:", target):
                    continue
                full = os.path.normpath(os.path.join(os.path.dirname(path), target))
                self.assertTrue(os.path.exists(full), "%s links to %s, which does not exist" % ("/".join(doc), target))


class ReleaseHygiene(unittest.TestCase):
    def test_spdx_and_no_secrets(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "check_release.py")], capture_output=True,
                           text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertRegex(r.stdout, r"0 without an SPDX line, .* 0 secrets")

    def test_the_checker_finds_what_it_looks_for(self):
        import check_release
        self.assertTrue(any(p.search("-----BEGIN " + "PRIVATE KEY-----") for p, _ in check_release.SECRET_CONTENT))
        self.assertTrue(any(p.search('{"sk": "%s"}' % ("ab" * 32)) for p, _ in check_release.SECRET_CONTENT))
        self.assertTrue(check_release.match("gateway/state/identity.json", [n for n, _ in check_release.SECRET_NAMES]))
        self.assertTrue(check_release.match("bench.env", [n for n, _ in check_release.SECRET_NAMES]))
        self.assertFalse(check_release.match("bench.env.example", [n for n, _ in check_release.SECRET_NAMES]))


if __name__ == "__main__":
    unittest.main()
