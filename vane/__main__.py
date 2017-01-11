from argparse import ArgumentParser
from .core import Vane

actions_available = ["request", "scan", "import_data"]

parser = ArgumentParser(description="vane 2.0")
parser.add_argument("action", choices=actions_available)
parser.add_argument("--url", dest="url")
parser.add_argument("--import_path", dest="database_path")
args = parser.parse_args()

vane = Vane()
vane.perfom_action(**vars(args))
