# CASDA Python API

Provides a simple Python API to access images hosted on the CSIRO ASKAP Science Data
Archive ([CASDA](https://data.csiro.au/)).

## Installation

`casdapy` has the following dependencies:

- python>=3.6
- astropy
- click
- pandas
- requests
- tqdm

Download this repository and install with pip, e.g.

```bash
git clone https://github.com/askap-vast/casdapy.git
pip install ./casdapy
```

or install directly from GitHub, e.g.

```bash
pip install git+https://github.com/askap-vast/casdapy.git
```

## Examples

`casdapy` is primarily intended to be used as a library, but an example script is included
to demonstrate its use. You may find this script does what you need.

### The `casda_download` script

A script named `casda_download` is installed with the package. Run it with `--help` to
see usage details. It searches for images and catalogues on CASDA that match various
search criteria (e.g. image polarisation, SBID number, cone search), and optionally
downloads the search results.

The source of the script can be found [here](casdapy/scripts/download.py).

### Use as a library

You can use `casdapy` in your own scripts to perform CASDA queries and download results.
There are a number of functions defined in `casdapy.casdapy` but generally the most useful
will be `query` and `download_data`. Refer to the function docstrings and provided script
for example usage. Note that this package follows PEP8 naming conventions where interfaces
that are not intended to be public (and therefore are not guaranteed to remain stable) are
named with a leading underscore, `_`.

## Feedback

Feedback is very welcome! Please report any issues or suggestions using the GitHub issue
tracker.
