# CASDA Python API

Provides a simple Python API to access images hosted on the CSIRO ASKAP Science Data
Archive ([CASDA](https://data.csiro.au/)).

## Installation

`casdapy` has the following dependencies which will be downloaded automatically if installed with pip.

- python>=3.8
- astropy
- astroquery
- click
- PyPika

Download this repository and install with pip, e.g.

```bash
git clone https://github.com/askap-vast/casdapy.git
pip install ./casdapy
```

or install directly from GitHub, e.g.

```bash
pip install git+https://github.com/askap-vast/casdapy.git
```

## The `casdapy` CLI

`casdapy` is primarily intended to be used as a library, but a CLI is included for common tasks. You may find this CLI does what you need.

An executable script named `casdapy` is installed with the package. Run it with `--help` to see usage details.

```bash
$ casdapy --help
Usage: casdapy [OPTIONS] COMMAND [ARGS]...

Options:
  --verbose  Show more logging information. Useful for debugging. Defaults to
             False.

  --help     Show this message and exit.

Commands:
  download  Query CASDA and download results.
  retry     Download files from an existing CASDA job.
  verify    Verify CASDA download checksums.
```

Note that `--verbose` is an option for the parent `casdapy` command. To turn on verbose logging, pass it as an option to `casdapy`, not the subcommand.

### Subcommands

#### download

Search for images and catalogues on CASDA that match various search criteria (e.g. image polarisation, SBID number, cone search) and downloads the results. Will split the data download into several CASDA jobs for large result sets. Run `casdapy download --help` for more details.

#### retry

Retry downloading the data files from an existing CASDA job. Run `casdapy retry --help` for more details.

#### verify

Verify data files downloaded from CASDA by calculating their checksums and comparing them to the `.checksum` files provided by CASDA. Run `casdapy verify --help` for more details.

### Examples

Download the component catalogue, island catalogue, restored Stokes I image, and the Stokes I noise image for ASKAP SBID 11427.

```bash
casdapy --verbose download --sbid 11427 --image-type cont.restored.t0 --image-type cont.noise.t0 --image-pol I \
--catalogue-type catalogue.continuum.component --catalogue-type catalogue.continuum.island
```

## Use as a library

You can use `casdapy` in your own scripts to perform CASDA queries and download results. There are a number of functions defined in `casdapy.casdapy`. Refer to the function docstrings. Note that this package follows PEP8 naming conventions where interfaces that are not intended to be public (and therefore are not guaranteed to remain stable) are named with a leading underscore, `_`.

## Feedback

Feedback is very welcome! Please report any issues or suggestions using the GitHub issue
tracker.
