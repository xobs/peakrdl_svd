from typing import TYPE_CHECKING
import re

from peakrdl.plugins.importer import ImporterPlugin #pylint: disable=import-error

from .importer import SVDImporter

if TYPE_CHECKING:
    import argparse
    from systemrdl import RDLCompiler
    from systemrdl.node import AddrmapNode


class Importer(ImporterPlugin):
    file_extensions = ["svd"]

    def is_compatible(self, path: str) -> bool:
        # Could be any XML file.
        # See if file contains an ipxact or spirit component tag
        with open(path, "r", encoding="utf-8") as f:
            if re.search(r"<(spirit|ipxact):component\b", f.read()):
                return True
        return False

    def add_importer_arguments(self, arg_group: 'argparse.ArgumentParser') -> None:
        arg_group.add_argument(
            "--remap-state",
            metavar="STATE",
            default=None,
            help="Optional remapState string that is used to select memoryRemap regions that are tagged under a specific remap state."
        )

    def do_import(self, rdlc: 'RDLCompiler', options: 'argparse.Namespace', path: str) -> None:
        i = SVDImporter(rdlc)
        i.import_file(
            path,
            remap_state=options.remap_state
        )
