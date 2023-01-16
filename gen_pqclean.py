#!/usr/bin/env python3

import fileinput
import logging
import tempfile
import re
import subprocess
import functools
import io
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterator, List, Literal, Set, Tuple, cast

# types
SizeT = Literal[128, 192, 256]
VariantT = Literal["fast", "small"]
HashT = Literal["sha2", "shake", "haraka"]
ThashT = Literal["simple", "robust"]

ImplementationLiteralT = (
    Literal["ref"] | Literal["avx2"] | Literal["aesni"] | Literal["a64"]
)

BUILD_ENABLED = True



def exclude_file(file: Path) -> bool:
    filename: str = str(file.name)
    if "PQCgenKAT" in filename:
        return True
    if file.is_dir():
        return True
    if filename == "params.h":
        return True
    if filename.startswith("rng") or filename.startswith("randombytes"):
        return True
    if filename.startswith(".git"):
        return True
    if filename.startswith("fips202.") or filename.startswith("sha2."):
        return True
    if filename == "Makefile":
        return True
    if filename == "api.h":
        return True

    return False


def get_pqclean_impl_name(
    impl: ImplementationLiteralT,
) -> Literal["clean"] | Literal["aarch64"] | Literal["aesni"] | Literal["avx2"]:
    match impl:
        case "ref":
            return "clean"
        case "a64":
            return "aarch64"
        case _:
            return impl


def replace_in_file(path: Path, text_to_search: str, replacement_text: str) -> None:
    with fileinput.FileInput(path, inplace=True) as file:
        for line in file:
            print(re.sub(text_to_search, replacement_text, line), end="")


def remove_stupid_ifdef(path: Path, ifdef: str):
    if not path.exists():
        return
    suppress = False
    with fileinput.FileInput(path, inplace=True) as file:
        for line in file:
            if line.strip() == ifdef:
                suppress = True
            if not suppress:
                print(line, end="")
            else:
                print(f"//{line}", end="")
            if line.strip() == "#endif":
                suppress = False


@dataclass
class Sphincs:
    """A SPHINCS+ instantiation"""

    size: SizeT
    variant: VariantT
    hash: HashT
    thash: ThashT

    def __post_init__(self):
        self.log = logging.getLogger(__class__.__name__)

    def __hash__(self):
        return hash((self.size, self.variant, self.hash, self.thash))

    def __eq__(self, other) -> bool:
        return (self.size == other.size
                and self.variant == other.variant
                and self.hash == other.hash
                and self.thash == other.thash)

    @property
    def nist_level(self) -> Literal[1, 2, 3, 5]:
        match self.size:
            case 128:
                level = 1
            case 192:
                level = 3
            case 256:
                level = 5
        if self.hash == "haraka":
            if level > 2:
                level = 2

        return level

    @property
    def n(self) -> int:
        return self.size // 8

    @property
    def h(self) -> int:
        if self.size in (128, 192):
            if self.variant == "small":
                return 63
            else:
                return 66
        else:
            if self.variant == "small":
                return 64
            else:
                return 68

    @property
    def log_t(self) -> int:
        match self.size:
            case 128:
                match self.variant:
                    case "small":
                        return 12
                    case "fast":
                        return 6
            case 192:
                match self.variant:
                    case "small":
                        return 14
                    case "fast":
                        return 8
            case 256:
                match self.variant:
                    case "small":
                        return 14
                    case "fast":
                        return 9

    @property
    def k(self) -> int:
        if self.size in (128, 192) and self.variant == "fast":
            return 33
        elif self.size == 128 and self.variant == "small":
            return 14
        elif self.size == 192 and self.variant == "small":
            return 17
        elif self.size == 256 and self.variant == "small":
            return 22
        elif self.variant == 256 and self.variant == "fast":
            return 35

        raise ValueError(
            f"Unexpected combination of size {self.size} and variant {self.variant}"
        )

    @property
    def w(self) -> int:
        return 16

    @property
    def bits_security(self) -> int:
        if self.size == 128 and self.variant == "small":
            return 133
        elif self.size == 128 and self.variant == "fast":
            return 128
        elif self.size == 192 and self.variant == "small":
            return 193
        elif self.size == 192 and self.variant == "fast":
            return 194
        elif self.size == 256:
            return 255

        assert False, "Unexpected size/variant for bits_security"

    @property
    def pk_bytes(self) -> int:
        match self.size:
            case 128:
                return 32
            case 192:
                return 48
            case 256:
                return 64

    @property
    def sk_bytes(self) -> int:
        return self.pk_bytes * 2

    @property
    def sig_bytes(self) -> int:
        ident = str(self.size) + self.variant[0]
        match ident:
            case "128s":
                return 7856
            case "128f":
                return 17088
            case "192s":
                return 16224
            case "192f":
                return 35664
            case "256s":
                return 29792
            case "256f":
                return 49856
        raise ValueError(f"Unexpected identity {ident}")

    @functools.lru_cache
    def get_nistkat(self) -> str:
        katfiles = list((Path("KAT") /self.basefile).glob("PQCsignKAT_*.rsp"))
        if len(katfiles) == 0:
            raise ValueError(f"No KAT file found for {self}. Did you run ./vectors.py?")
        katfile = katfiles[0]
        with katfile.open("rb") as katfh:
            kat = katfh.readlines()
            buf = io.BytesIO()
            buf.writelines(kat[2:10])
            sha = hashlib.sha256()
            sha.update(buf.getvalue())
            return sha.hexdigest()

    @property
    def name(self) -> str:
        return f"SPHINCS+-{self.hash}-{self.size}{self.variant[0]}-{self.thash}"

    def ns_name(self, impl) -> str:
        nsname = self.basefile.replace("-", "").replace("_", "").upper()
        return f"PQCLEAN_{nsname}_{get_pqclean_impl_name(impl).upper()}"

    @property
    def basefile(self) -> str:
        return f"sphincs-{self.hash}-{self.size}{self.variant[0]}-{self.thash}"

    @property
    def implementations(self) -> List[ImplementationLiteralT]:
        match self.hash:
            case "sha2":
                return ["ref", "avx2"]
            case "shake":
                return ["ref", "avx2", "a64"]
            case "haraka":
                return ["ref", "aesni"]

    def get_source_files(
        self, impl: ImplementationLiteralT
    ) -> Iterator[Tuple[Path, str]]:
        self.log.info("Generating filenames for %s impl %s", self.name, impl)
        match impl:
            case "ref":
                implpath = Path("ref")
            case "avx2":
                assert self.hash != "haraka"
                implpath = Path(f"{self.hash}-avx2")
            case "a64":
                assert self.hash == "shake"
                implpath = Path("shake-a64")
            case "aesni":
                assert self.hash == "haraka"
                implpath = Path("haraka-aesni")

        # We definitely need api.h and the LICENSE
        yield (implpath / "api.h", "nistapi.h")
        yield (Path("LICENSE"), "LICENSE")

        # resolve params.h
        yield (
            implpath
            / "params"
            / f"params-sphincs-{self.hash}-{self.size}{self.variant[0]}.h",
            "params.h",
        )

        other_hashes = {"haraka", "shake", "sha2"}
        other_hashes.remove(self.hash)

        for file in implpath.glob("*"):
            if exclude_file(file):
                self.log.debug("Excluding %s", file.name)
                continue
            if impl == "ref":
                found_hash = False
                for hash in other_hashes:
                    if hash in file.name:
                        self.log.debug(
                            "Excluding %s based on hash %s", file.name, file.name
                        )
                        found_hash = True
                        break
                if found_hash:
                    continue
            if self.hash == "sha2" and self.size == 128:
                if "sha512" in file.name:
                    self.log.debug("Omitting %s", file.name)
                    continue
            if file.name.startswith("thash_"):
                if not self.thash in file.name:
                    self.log.debug("Skipping thash file %s", file.name)
                    continue
            yield (file, file.name)



def gen_api_h(params: Sphincs, impl: ImplementationLiteralT) -> str:
    ns = params.ns_name(impl)
    return f"""\
#ifndef {ns}_API_H
#define {ns}_API_H

#include <stddef.h>
#include <stdint.h>

#define {ns}_CRYPTO_ALGNAME "{params.name}"

#define {ns}_CRYPTO_SECRETKEYBYTES {params.sk_bytes}
#define {ns}_CRYPTO_PUBLICKEYBYTES {params.pk_bytes}
#define {ns}_CRYPTO_BYTES          {params.sig_bytes}

#define {ns}_CRYPTO_SEEDBYTES      {3*params.n}

/*
 * Returns the length of a secret key, in bytes
 */
size_t {ns}_crypto_sign_secretkeybytes(void);

/*
 * Returns the length of a public key, in bytes
 */
size_t {ns}_crypto_sign_publickeybytes(void);

/*
 * Returns the length of a signature, in bytes
 */
size_t {ns}_crypto_sign_bytes(void);

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
size_t {ns}_crypto_sign_seedbytes(void);

/*
 * Generates a SPHINCS+ key pair given a seed.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int {ns}_crypto_sign_seed_keypair(uint8_t *pk, uint8_t *sk,
                                  const uint8_t *seed);

/*
 * Generates a SPHINCS+ key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int {ns}_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

/**
 * Returns an array containing a detached signature.
 */
int {ns}_crypto_sign_signature(uint8_t *sig, size_t *siglen,
                               const uint8_t *m, size_t mlen,
                               const uint8_t *sk);

/**
 * Verifies a detached signature and message under a given public key.
 */
int {ns}_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                            const uint8_t *m, size_t mlen,
                            const uint8_t *pk);

/**
 * Returns an array containing the signature followed by the message.
 */
int {ns}_crypto_sign(uint8_t *sm, size_t *smlen,
                     const uint8_t *m, size_t mlen,
                     const uint8_t *sk);

/**
 * Verifies a given signature-message pair under a given public key.
 */
int {ns}_crypto_sign_open(uint8_t *m, size_t *mlen,
                          const uint8_t *sm, size_t smlen,
                          const uint8_t *pk);
#endif
"""


def pqclean_metadata(params: Sphincs) -> str:
    output = f"""\
name: {params.name}
type: signature
claimed-nist-level: {params.nist_level}
length-public-key: {params.pk_bytes}
length-secret-key: {params.sk_bytes}
length-signature: {params.sig_bytes}
testvectors-sha256: testvectorvalue
nistkat-sha256: {params.get_nistkat()}
principal-submitters:
  - Andreas Hülsing
auxiliary-submitters:
  - Jean-Philippe Aumasson
  - Daniel J. Bernstein,
  - Ward Beullens
  - Christoph Dobraunig
  - Maria Eichlseder
  - Scott Fluhrer
  - Stefan-Lukas Gazdag
  - Panos Kampanakis
  - Stefan Kölbl
  - Tanja Lange
  - Martin M. Lauridsen
  - Florian Mendel
  - Ruben Niederhagen
  - Christian Rechberger
  - Joost Rijneveld
  - Peter Schwabe
  - Bas Westerbaan
implementations:
"""
    for impl in params.implementations:
        output += implementation_metadata(impl)

    return output


def implementation_metadata(impl: Literal['avx2', 'aesni', 'a64']):
    gitout = subprocess.run(
        ["git", "rev-parse", "master"], capture_output=True, text=True
    )
    commit = gitout.stdout.strip()
    if impl == "ref":
        return f"""\
  - name: clean
    version: https://github.com/sphincs/sphincsplus/commit/{commit}
"""
    print_impl = impl
    if impl == "avx2":
        arch = "x86_64"
        flags = ["avx2"]
    elif impl == "aesni":
        arch = "x86_64"
        flags = ["aes"]
    elif impl == "a64":
        print_impl = "aarch64"
        arch = "arm_8"
        flags = ["sha3"]
    else:
        assert False

    data = f"""\
  - name: {print_impl}
    version: https://github.com/sphincs/sphincsplus/commit/{commit}
    supported_platforms:
      - architecture: {print_impl}
        required_flags: {flags!r}
"""
    if impl == "a64":
        data += """\
        operating_systems:
          - Linux
          - Darwin
"""
    return data


def test_api_h(params: Sphincs):
    subprocess.run(
        [
            "make",
            "-B",
            "-C",
            "metadata",
            "test_api_h",
            f"NS={params.ns_name('ref')}",
            f"THASH={params.thash}",
            f"PARAMS=sphincs-{params.hash}-{params.size}{params.variant[0]}",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(["./metadata/test_api_h"], check=True)


def test_build(implpath) -> None:
    if not BUILD_ENABLED:
        return
    if implpath.name == "aarch64":
        return
    subprocess.run(["make", "-j4", "-C", implpath], check=True, capture_output=False)
    subprocess.run(["make", "-C", implpath, "clean"], check=True, capture_output=False)


def gen_makefile(params: Sphincs, export_path: Path) -> None:
    c_files = list(export_path.glob("*.[cs]"))
    h_files = [fn.name for fn in export_path.glob("*.h")]
    o_files = [fn.with_suffix(".o").name for fn in c_files]
    obj_files = [fn.with_suffix(".obj").name for fn in c_files]

    cflags: Set[str] = {
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Wconversion",
        "-Werror",
        "-Wmissing-prototypes",
        "-Wredundant-decls",
    }

    if export_path.name == "aesni":
        cflags.add("-maes")
    if export_path.name == "avx2":
        cflags.add("-mavx2")

    makefile = f"""\
# This Makefile can be used with GNU Make or BSD Make

LIB = lib{params.basefile}_{export_path.name}.a

HEADERS = {' '.join(sorted(h_files))}
OBJECTS = {' '.join(sorted(o_files))}

CFLAGS  = -std=c99 -O3 {' '.join(sorted(cflags))} -I../../../common $(EXTRAFLAGS)

all: $(LIB)

%.o: %.c $(HEADERS)
\t$(CC) $(CFLAGS) -c -o $@ $<

"""
    if any(map(lambda x: x.suffix == ".s", c_files)):
        makefile += """\

%.o: %.s
\t$(AS) -o $@ $<

"""
    keccaklib = ""
    keccakclean = ""
    if export_path.name == "avx2" and params.hash == "shake":
        makefile += f"""
KECCAK4XDIR=../../../common/keccak4x
KECCAK4XOBJ=KeccakP-1600-times4-SIMD256.o
KECCAK4X=$(KECCAK4XDIR)/$(KECCAK4XOBJ)

$(KECCAK4X):
	$(MAKE) -C $(KECCAK4XDIR) $(KECCAK4XOBJ)

"""
        keccaklib = "$(KECCAK4X)"
        keccakclean = "\t$(MAKE) -C $(KECCAK4XDIR) clean\n"

    makefile += f"""\
$(LIB): $(OBJECTS) {keccaklib}
\t$(AR) -r $@ $(OBJECTS) {keccaklib}

clean:
\t$(RM) $(OBJECTS)
\t$(RM) $(LIB)
{keccakclean}
"""

    with (export_path / "Makefile").open("w") as fh:
        fh.write(makefile)

    if export_path.name == "aarch64":
        return

    # Generate Microsoft file
    archflag = ""
    keccak = ""
    keccakdel = ""
    if export_path.name in ("avx2", "aesni"):
        archflag = "/arch:AVX "
        keccak = (
            rf"""\

KECCAK4XDIR=..\..\..\common\keccak4x
KECCAK4XOBJ=KeccakP-1600-times4-SIMD256.obj
KECCAK4X=$(KECCAK4XDIR)\$(KECCAK4XOBJ)"""
            """

$(KECCAK4X):
\tcd $(KECCAK4XDIR) && $(MAKE) /f Makefile.Microsoft_nmake $(KECCAK4XOBJ)

"""
        )
        keccakdel = "\t-DEL $(KECCAK4X)\n"

    makefile = f"""\
# This Makefile can be used with Microsoft Visual Studio's nmake using the command:
#    nmake /f Makefile.Microsoft_nmake

LIBRARY = lib{params.basefile}_{export_path.name}.lib
OBJECTS = {' '.join(sorted(obj_files))}

CFLAGS = /nologo /O2 {archflag}/I ..\\..\\..\\common /W4 /WX

all: $(LIBRARY)

$(OBJECTS): *.h

$(LIBRARY): $(OBJECTS) {keccaklib}
\tLIB.EXE /NOLOGO /WX /OUT:$@ $**

clean:
\t-DEL $(OBJECTS)
\t-DEL $(LIBRARY)
{keccakdel}
"""
    makefile = makefile.replace("\n", "\r\n")
    with (export_path / "Makefile.Microsoft_nmake").open("w") as fh:
        fh.write(makefile)


def unifdef(params: Sphincs, implpath: Path):
    paramfile = (
        Path("ref")
        / "params"
        / f"params-sphincs-{params.hash}-{params.size}{params.variant[0]}.h"
    )
    hash_offsets = (
        Path("ref") / f"{params.hash}_offsets.h"
    )
    with tempfile.TemporaryDirectory() as tempdir:
        temppar = Path(tempdir) / "tempparams.h"
        editpar = Path(tempdir) / "editparams.h"
        with paramfile.open("r") as rh:
            lines = rh.readlines()
        with temppar.open("w") as wh:
            wh.writelines(lines[2:23])
        with editpar.open("w") as wh:
            wh.writelines(lines[2:-1])

        subprocess.run(["unifdef", f"-f{temppar}", "-k", "-m", editpar])
        replace_in_file(editpar, "#if.*$", "")
        replace_in_file(editpar, "#error.*$", "")
        replace_in_file(editpar, "#endif.*$", "")
        replace_in_file(editpar, "#include.*$", "")
        replace_in_file(editpar, "\\\\\n", "")

        undef_hashes = ["sha2", "haraka", "shake"]
        undef_hashes.remove(params.hash)

        subprocess.run(
            [
                "unifdef",
                "-m",
                "-k",
                "-x2",
                "-U_MSC_VER",
                f"-DSPX_SHA512={'0' if params.size == 128 else '1'}",
                f"-DSPX_{params.hash.upper()}",
                *[f"-USPX_{hsh.upper()}" for hsh in undef_hashes],
                f"-f{editpar}",
                *list(implpath.glob("*.[ch]")),
            ],
            check=True,
        )
        output = subprocess.run(["coan", "defs", editpar], capture_output=True, text=True)
        output2 = subprocess.run(["coan", "defs", hash_offsets], capture_output=True, text=True)
        defsfile = Path(tempdir) / "defs.h"

        defines = {}
        for line in (output.stdout + output2.stdout).split('\n'):
            if "SPX_NAMESPACE" in line or '#define' not in line:
                continue
            line = line.replace("#define ", "")
            if ' ' not in line:
                continue
            print(f"Splitting {line}")
            (name, value) = line.split(" ", 1)
            defines[name] = value

        for _ in range(10):
            for name, value in defines.copy().items():
                if "SPX_" not in value:
                    continue
                for name2, value2 in defines.copy().items():
                    print(f"Trying to replace {name2} in {defines[name]}")
                    defines[name] = defines[name].replace(name2, value2)

        for name in defines.keys():
            print(f"Evaluating '{name}={defines[name]}'")
            defines[name] = eval(defines[name].replace("/", "//"))

        with defsfile.open("w") as fh:
            for name, value in defines.items():
                fh.write(f"-D{name}={value} ")
        sourcefiles = [file for file in implpath.glob("*.[ch]") if file.name != "params.h" and "_offsets.h" not in file.name]

        subprocess.run(
            [
                "coan",
                "source",
                "-f", defsfile,
                "-E",
                "-r",
                "-kd",
                *sourcefiles
            ],
            check=False,
        )


def astyle(implpath: Path):
    subprocess.run(
        ["astyle", "--options=pqclean-export/.astylerc", *list(implpath.glob("*.[ch]"))]
    )

def set_testvectors(destpath: Path, params: Sphincs):
    impl = get_pqclean_impl_name(
        cast(
            Literal["aesni", "avx2"],
            [impl for impl in params.implementations
             if impl not in ("ref", "a64")][0]
        )
    )
    sourcepath = destpath / params.basefile / impl

    subprocess.run(["make", "-C", sourcepath], check=True)
    with tempfile.TemporaryDirectory() as tmpdir:
        subprocess.run(
            [
                "make",
                "-C",
                "pqclean-export/test",
                "testvectors",
                "TYPE=sign",
                f"SCHEME={params.basefile}",
                f"SCHEME_DIR={sourcepath.resolve()}",
                f"IMPLEMENTATION={impl}",
                f"DEST_DIR={tmpdir}",
            ],
            check=True,
        )
        testvector_out = subprocess.run(
            [f"{tmpdir}/testvectors_{params.basefile}_{impl}"],
            capture_output=True,
            check=True,
        )

    output = testvector_out.stdout.replace(b"\r", b"")
    vector = hashlib.sha256(output).hexdigest().lower()
    replace_in_file(
        destpath / params.basefile / "META.yml", "testvectorvalue", vector
    )


def clang_tidy(implpath: Path, check=False):
    subprocess.run(
        [
            "clang-tidy",  #'-quiet',
            "--config-file=pqclean-export/.clang-tidy",
            "-header-filter=.*",
            "--fix",
            "--fix-errors",
            "--fix-notes",
            *list(implpath.glob("*.c")),
            *list(Path("pqclean-export/common").glob("*.c")),
            "--",
            "-iquote",
            "pqclean-export/test/common",
            "-iquote",
            "pqclean-export/common",
            "-iquote",
            implpath,
        ],
        check=check,
    )



def generate_impl(destpath: Path, params: Sphincs):
    sphincspath = destpath / params.basefile
    sphincspath.mkdir()

    logging.info("Generating metadata")
    with (sphincspath / "META.yml").open("w") as fh:
        fh.write(pqclean_metadata(params))

    logging.info("Copying files")
    for impl in params.implementations:
        implpath = sphincspath / get_pqclean_impl_name(impl)
        implpath.mkdir()

        with (implpath / "api.h").open("w") as fh:
            fh.write(gen_api_h(params, impl))

        for (srcfile, destfn) in params.get_source_files(impl):
            logging.debug("Copying %s to %s", srcfile, destfn)
            shutil.copyfile(srcfile, implpath / destfn, follow_symlinks=True)
            replace_in_file(implpath / destfn, "SPX_VLA", "PQCLEAN_VLA")

        replace_in_file(implpath / "params.h", r"^#include \"\.\./", '#include "')
        replace_in_file(
            implpath / "params.h", "SPX_##s", f"{params.ns_name(impl)}_##s"
        )
        replace_in_file(
            implpath / "sign.c", r"#include \"api\.h\"", '#include "nistapi.h"'
        )

        gen_makefile(params, implpath)
        test_build(implpath)
        unifdef(params, implpath)
        replace_in_file(implpath / "utils.h", "# define SPX_VLA.*", "")
        replace_in_file(
            implpath / "utils.h",
            '#include "context.h"',
            '#include "compat.h"\n#include "context.h"',
        )
        remove_stupid_ifdef(implpath / "params.h", "#if SPX_TREE_HEIGHT * SPX_D != SPX_FULL_HEIGHT")
        clang_tidy(implpath)
        clang_tidy(implpath, check=True)
        astyle(implpath)

    set_testvectors(destpath, params)


def get_sphincses() -> list[Sphincs]:
    SPHINCSES: List[Sphincs] = [
        Sphincs(size, variant, hash_, thash)
        for size in (128, 192, 256)
        for variant in ("small", "fast")
        for hash_ in ("sha2", "shake", "haraka")
        for thash in ("simple", "robust")
    ]

    def filterspx() -> Iterator[Sphincs]:
        for sphincs in SPHINCSES:
            #if sphincs.hash != "sha2":
            #    continue
            #if sphincs.thash != "simple":
            #    continue
            #if sphincs.size != 128:
            #    continue
            yield sphincs

    return list(filterspx())


if __name__ == "__main__":
    import hashlib
    import shutil
    import multiprocessing
    import functools
    import sys

    logging.basicConfig(level=logging.DEBUG)

    sphincses = get_sphincses()

    for params in sphincses:
        apipath = Path("metadata/api") / (params.basefile + ".h")
        metapath = Path("metadata/meta") / (params.basefile + ".yml")
        with open(apipath, "w") as fh:
            fh.write(gen_api_h(params, "ref"))
        with open(metapath, "w") as fh:
            fh.write(pqclean_metadata(params))
        test_api_h(params)

    destpath = Path("pqclean-export/crypto_sign")
    if destpath.exists():
        logging.warning("Removing existing destination path")
        shutil.rmtree(destpath)
    destpath.mkdir(parents=True, exist_ok=False)

    with multiprocessing.Pool() as pool:
        pool.map(functools.partial(generate_impl, destpath), sphincses)
