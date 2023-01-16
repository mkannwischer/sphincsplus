#!/usr/bin/env python3
from pprint import pprint
from pathlib import Path
import itertools

import yaml

from gen_pqclean import (
    Sphincs,
    ImplementationLiteralT,
    get_pqclean_impl_name,
    get_sphincses,
)


def get_duplicates_basic(scheme: Sphincs, impl: ImplementationLiteralT):
    parent_hash = "sha2"
    if scheme.hash == "sha2":
        parent_hash = "shake"
    parent_spx = Sphincs(scheme.size, "small", parent_hash, "robust")

    duplicates = [
        {
            "source": {
                "scheme": parent_spx.basefile,
                "implementation": "clean",
            },
            "files": [
                "address.h",
                "fors.h",
                "sign.c",
                "merkle.h",
                "utils.c",
                "utils.h",
                "wots.h",
            ],
        },
    ]
    duplicates.append({
        "source": {
            "scheme": scheme.basefile,
            "implementation": "clean",
        },
        "files": [
            "address.c",
            "api.h",
            "fors.h",
            "hash.h",
            f"hash_{scheme.hash}.c",
            "merkle.h",
            "params.h",
            "sign.c",
            "thash.h",
            "utils.c",
            "utils.h",
            *[f"thash_{scheme.hash}_{scheme.thash}.{ext}" for ext in "c" if scheme.hash != "shake" or impl != "a64"],
            *[f"context_{scheme.hash}.c" for ext in "c" if scheme.hash != "sha2"],
        ]
    })
    for (size, variant) in itertools.product((128, 192, 256), ("small", "fast")):
        if size == scheme.size and variant == scheme.variant:
            continue
        if scheme.hash == "sha2":
            if scheme.size == 128 and size > 128:
                continue
            elif scheme.size > 128 and size == 128:
                continue
        parent_spx = Sphincs(size, variant, scheme.hash, scheme.thash)
        dup_files = [
            f"context_{scheme.hash}.c",
            f"hash_{scheme.hash}.c",
            f"{scheme.hash}_offsets.h",
        ]
        if scheme.size == size:
            dup_files += [
            ]
        if impl != "a64":
            dup_files += [
                f"thash_{scheme.hash}_{scheme.thash}.c",
            ]
        if scheme.hash == "sha2" and impl == "avx2":
            dup_files += [
                "hashx8.h",
                "thashx8.h",
                f"thash_sha2_{scheme.thash}.c",
                "hash_sha2x8.c",
                "sha256avx.c",
                "sha256avx.h",
                "sha256x8.h",
                "utilsx8.c",
                "utilsx8.h",
                "wots.c",
                "wotsx8.h",
            ]
            if scheme.size > 128:
                dup_files += [
                    "sha512x4.c",
                    "sha512x4.h",
                ]
        elif scheme.hash == "shake" and impl != "ref":
            mult = "x4" if impl == "avx2" else "x2"
            dup_files += [
                f"hash{mult}.h",
                f"hash_shake{mult}.c",
                f"wots{mult}.h",
                f"utils{mult}.c",
                f"utils{mult}.h",
                f"thash_shake_{scheme.thash}{mult}.c",
                f"hash_shake{mult}.c",
                f"fips202{mult}.c",
                f"fips202{mult}.h",
            ]
            if impl == "a64":
                dup_files += [
                    f"f1600x2.h",
                    f"f1600x2.c",
                    f"f1600x2.s",
                ]

        elif scheme.hash == "haraka" and impl != "ref":
            dup_files += [
                "harakax4.h",
                "hash_harakax4.c",
                f"thash_haraka_{scheme.thash}x4.c",
                f"thashx4.h",
                "utilsx4.h",
                "utilsx4.c",
                "wotsx4.h",
            ]

        duplicates.append(
            {
                "source": {
                    "scheme": parent_spx.basefile,
                    "implementation": get_pqclean_impl_name(impl),
                },
                "files": list(sorted(dup_files)),
            }
        )

        if (scheme.hash == "shake" or scheme.hash == "haraka") and impl in ("avx2", "aesni"):
            other_hash = "haraka" if scheme.hash == "shake" else "shake"
            other_impl = "avx2" if scheme.hash == "haraka" else "aesni"
            duplicates.append(
                {
                    "source": {
                        "scheme": Sphincs(scheme.size, scheme.variant, other_hash, scheme.thash).basefile,
                        "implementation": other_impl,
                    },
                    "files": [
                        "thashx4.h",
                        "merkle.c",
                        "hashx4.h",
                        "utilsx4.c",
                        "utilsx4.h",
                        "wots.h",
                        "wotsx4.h",

                    ]
                }
            )
    return duplicates


def gen_consistency_files(sphincs: Sphincs, impl: ImplementationLiteralT):
    filename = f"{sphincs.basefile}_{get_pqclean_impl_name(impl)}.yml"
    with (Path("pqclean-export/test/duplicate_consistency") / filename).open("w") as fh:
        fh.write(yaml.dump({"consistency_checks": get_duplicates_basic(sphincs, impl)},
                           default_flow_style=False,
                           sort_keys=False))


def main():
    for sphincs in list(get_sphincses()):
        for impl in sphincs.implementations:
            print(f"{sphincs.basefile}_{get_pqclean_impl_name(impl)}.yml")
            gen_consistency_files(sphincs, impl)


if __name__ == "__main__":
    import sys

    main()
