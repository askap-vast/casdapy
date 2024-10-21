import binascii
from functools import partial
import hashlib
from http.client import HTTPException
from math import ceil
import os
from pathlib import Path, PurePath
from typing import ByteString, Dict, List, Optional, Tuple, Iterable, Sequence
from urllib.parse import unquote, urlparse
import warnings

from astropy.coordinates import SkyCoord, Angle
from astropy.io.votable.exceptions import VOTableChangeWarning, VOTableSpecWarning
from astropy.table import Table
from astropy.utils.console import human_file_size
import astropy.utils.data
import astroquery.casda
from astroquery.utils.tap.core import TapPlus
import pypika
import requests.exceptions
from retrying import retry
from tqdm.auto import tqdm

from casdapy._logging import logger

from pypika import Criterion

CASDA_TAP_URL = "https://casda.csiro.au/casda_vo_tools/tap"


obscore_table = pypika.Table("ivoa.obscore")
adql_query: pypika.queries.QueryBuilder = pypika.Query.from_(obscore_table).select(
    "*"
)

adql_query = adql_query.where(obscore_table.dataproduct_type == 'visibility')

field_names = ["1806-25", "1739-25"]
beams = [33,24]

beam_field_pairs = []

for beam, field_name in zip(beams, field_names):
    query = obscore_table.filename.like(f"%{field_name}%beam{beam}%")
    beam_field_pairs.append(query)

adql_query = adql_query.where(Criterion.any(beam_field_pairs))








sbid = [47253]
beam = 33
field_name = "1806-25"
adql_query = adql_query.where(obscore_table.obs_id.isin([str(x) for x in sbid]))    

adql_query = adql_query.where(obscore_table.filename.like(f"%{field_name}%beam{beam}%"))

adql_query_str = adql_query.get_sql(quote_char=None)
logger.info("Querying CASDA TAP server ...")
logger.debug("ADQL query: %s", adql_query_str)
casdatap = TapPlus(url=CASDA_TAP_URL, verbose=False)
try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", VOTableChangeWarning)
        warnings.simplefilter("ignore", VOTableSpecWarning)
        job = casdatap.launch_job_async(adql_query_str)
    r = job.get_results()
except requests.exceptions.HTTPError as e:
    logger.error("CASDA returned an HTTP error: %s", e)
    r = Table()
    
    
print(r)
