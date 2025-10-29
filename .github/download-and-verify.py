#!/bin/env/python

import argparse
import hashlib
import http.client
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from tempfile import TemporaryDirectory
from typing import Any, Dict, Optional
from os.path import isfile


RELEASE_URL = "https://api.github.com/repos/AppImage/appimagetool/releases/tags/continuous"
PUBKEY_FILENAME = None


def download_and_verify(release_url: str, pubkey_filename: Optional[str], dest: str = "") -> None:
    # make output nice for cwd
    if dest == ".":
        dest = ""

    # ensure we don't go through a proxy
    os.environ["no_proxy"] = "*"

    # check that gpg gnupg is available
    gpg_exe = shutil.which("gpg")
    if not gpg_exe:
        print("Please install GnuPG", file=sys.stderr)
        sys.exit(1)

    # download release json
    with urllib.request.urlopen(release_url) as response:
        assert isinstance(response, http.client.HTTPResponse), "Invalid URL"
        if response.status != http.client.OK:
            raise ValueError(f"Unexpected HTTP response: {response.status}")
        release_data: Dict[str, Any] = json.load(response)

    if release_data["draft"] or release_data["prerelease"]:
        raise ValueError("Unexpected release state")
    if release_data["author"]["login"] != "github-actions[bot]":
        raise ValueError("Unexpected release author")
    if not isinstance(release_data["target_commitish"], str) or not release_data["target_commitish"].isalnum():
        raise ValueError("Unexpected release commit")

    # print release commit; the only thing on stdout
    print(release_data["target_commitish"])

    # download all relevant assets and signatures and verify them
    runtimes = []
    sigs = []

    try:
        asset: Dict[str, Any]
        for asset in release_data["assets"]:
            name: str = asset["name"]
            if "/" in name or "\\" in name:
                raise ValueError(f"Invalid filename: {name}")
            if name.endswith(".debug"):
                continue
            url: str = asset["browser_download_url"]
            digest: str = asset["digest"]
            if not digest.startswith("sha256:"):
                raise ValueError(f"Unsupported digest: {digest.split(':')[0]}")
            expected_sha256: str = digest[7:].lower()
            if name.endswith(".asc"):
                # compare sha256 of provided and expected pub keys
                if pubkey_filename is None:
                    raise ValueError("Did not expected pubkey")
                with open(pubkey_filename, "rb") as pubkey_file:
                    sig_sha256 = hashlib.file_digest(pubkey_file, "sha256").hexdigest().lower()
                if sig_sha256 != expected_sha256:
                    raise ValueError("Unexpected signing pub key")
                continue
            elif name.endswith(".sig"):
                sigs.append(os.path.join(dest, name))
            elif "." in name and not name.endswith(".AppImage"):
                raise ValueError(f"Unexpected filename: {name}")
            else:
                runtimes.append(os.path.join(dest, name))
            print(f"Downloading {name}", file=sys.stderr)
            with open(os.path.join(dest, name), "wb") as download_file:
                with urllib.request.urlopen(url) as response:
                    assert isinstance(response, http.client.HTTPResponse), "Invalid URL"
                    if response.status != http.client.OK:
                        raise ValueError(f"Unexpected HTTP response: {response.status} for {url}")
                    shutil.copyfileobj(response, download_file)
            with open(os.path.join(dest, name), "rb") as verify_file:
                actual_sha256 = hashlib.file_digest(verify_file, "sha256").hexdigest().lower()
                if actual_sha256 != expected_sha256:
                    raise ValueError(f"Unexpected sha256 for {url}")
        if pubkey_filename is not None and len(runtimes) != len(sigs):
            raise ValueError("Number of signatures does not match number of runtimes")
        if pubkey_filename is None and len(sigs) != 0:
            raise ValueError("Did not expect any signatures")
        with TemporaryDirectory() as tmpdir:
            if sigs:
                # setup gnupg
                env = {"GNUPGHOME": tmpdir}
                proc = subprocess.run(
                    [gpg_exe, "--import", pubkey_filename],
                    shell=False,
                    check=True,
                    env=env,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                print(
                    "\n".join([line for line in proc.stderr.split("\n") if "imported" in line.lower()]),
                    file=sys.stderr,
                )
                for runtime in runtimes:
                    sig_filename = f"{runtime}.sig"
                    if not sig_filename in sigs:
                        raise ValueError(f"Missing signature for: {runtime}")
                    print(f"Verifying {runtime}", file=sys.stderr)
                    proc = subprocess.run(
                        [gpg_exe, "--trust-model", "always", "--verify", sig_filename],
                        shell=False,
                        check=False,
                        env=env,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    if proc.returncode != 0:
                        print(proc.stderr, file=sys.stderr)
                        raise ValueError(f"Failed to verify {runtime}")
                    else:
                        print(
                            "\n".join([line for line in proc.stderr.split("\n") if "signature" in line.lower()]),
                            file=sys.stderr,
                        )
    except:
        for runtime in runtimes:
            if isfile(runtime):
                os.unlink(runtime)
        for sig in sigs:
            if isfile(sig):
                os.unlink(sig)
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--out", type=str, default="", help="Output directory")
    args = parser.parse_args()
    dir_created = False
    if args.out:
        if not os.path.isdir(args.out):
            dir_created = True
            os.makedirs(args.out, exist_ok=True)
    try:
        download_and_verify(RELEASE_URL, PUBKEY_FILENAME, args.out)
    except:
        if dir_created:
            os.rmdir(args.out)
        raise


if __name__ == "__main__":
    main()
