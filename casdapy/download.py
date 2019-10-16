from io import BytesIO
import argparse
from pathlib import Path, PurePath
import time
import getpass
from xml.etree import ElementTree
from urllib.parse import unquote, urlsplit
import requests
import pyvo
from astropy.io import votable
from astropy.utils.console import human_file_size
from tqdm import tqdm
import warnings
from typing import List
import logging

logging.basicConfig(format="%(asctime)-15s %(module)s: %(levelname)s %(message)s")
logger = logging.getLogger("casdapy")

class CasdaSbidImageQuery():
    """Hides the insanity involved in querying CASDA for images.

    Args:
        sbid (int): The scheduling block ID to query.
        username (str): CASDA account username. Required for downloading images. May be an ATNF OPAL, CSIRO NEXUS or Partner account.
        password (str): CASDA account password. Required for downloading images. May be an ATNF OPAL, CSIRO NEXUS or Partner account.
        polarizations (List[str], optional): List of polarizations (Stokes parameters). Defaults to ["I",].
        dataproducts (List[str], optional): List of image data product types. See `CasdaImageQuery.IMAGE_CUBE_SUBTYPES` for possible values. Defaults to ["cont.restored.t0",].
    """
    TAP_URL = "https://casda.csiro.au/casda_vo_tools/tap"
    IMAGE_CUBE_SUBTYPES = [
        "cont.components.t0",
        "cont.components.t1",
        "cont.cleanmodel.t0",
        "cont.cleanmodel.t1",
        "cont.cleanmodel.3d",
        "cont.fitresidual.t0",
        "cont.fitresidual.t1",
        "cont.noise.t0",
        "cont.noise.t1",
        "cont.residual.t0",
        "cont.residual.t1",
        "cont.residual.3d",
        "cont.restored.t0",
        "cont.restored.t1",
        "cont.restored.3d",
        "cont.weight.t0",
        "cont.weight.t1",
        "cont.weight.3d",
    ]
    _UWS_NAMESPACES = {'uws': 'http://www.ivoa.net/xml/UWS/v1.0'}

    def __init__(self, sbid: int, username: str, password: str, polarizations: List[str]=["I",], dataproducts: List[str]=["cont.restored.t0",]):
        self._session = requests.Session()
        self._session.auth = (username, password)
        self._tap_service = pyvo.dal.TAPService(self.TAP_URL, session=self._session)
        self._async_job_url = None
        self._dataproducts = [dataproduct for dataproduct in dataproducts if dataproduct in self.IMAGE_CUBE_SUBTYPES]
        self._polarizations = polarizations
        self.sbid = sbid
        # only allow recognized image data product types
    
    @property
    def dataproducts(self):
        if len(self._dataproducts) == 1:
            return f"('{self._dataproducts[0]}')"
        else:
            return tuple(self._dataproducts)
    
    @property
    def polarizations(self):
        if len(self._polarizations) == 1:
            return f"('/{self._polarizations[0]}/')"
        else:
            return tuple([f"/{pol}/" for pol in self._polarizations])
    
    def run(self, download_destination: Path, adql_query: str=None, poll_period: int=30):
        tap_results = self._query(adql_query)
        downloaded_files = self._download_images_async(tap_results, download_destination, poll_period)
        logger.info("Downloaded %d files into %s", len(downloaded_files), download_destination)

    def _query(self, adql_query: str=None) -> pyvo.dal.tap.TAPResults:
        if adql_query is None:
            adql_query = f"SELECT * FROM ivoa.obscore WHERE obs_id = '{self.sbid}' AND dataproduct_type = 'cube' AND dataproduct_subtype IN {self.dataproducts} AND pol_states IN {self.polarizations}"
        logger.info("ADQL query: %s", adql_query)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # ignore votable warnings
            results: pyvo.dal.tap.TAPResults = self._tap_service.search(adql_query)
        logger.info("TAP result returned with %d records", len(results))
        return results

    def _async_job_details(self) -> ElementTree:
        response = requests.get(self._async_job_url)
        return ElementTree.fromstring(response.text)

    def async_job_status(self):
        return self._async_job_details().find("uws:phase", namespaces=self._UWS_NAMESPACES).text
    
    def async_job_result_file_links(self):
        results = self._async_job_details().find("uws:results", namespaces=self._UWS_NAMESPACES).findall("uws:result", namespaces=self._UWS_NAMESPACES)
        return [unquote(result.get("{http://www.w3.org/1999/xlink}href")) for result in results]

    def _download_images_async(self, tap_results: pyvo.dal.TAPResults, destination: Path, poll_period) -> List[Path]:
        download_tokens = []
        for i, result in enumerate(tap_results):
            logger.info("Processing TAP result %d of %d", i+1, len(tap_results))
            result._session = self._session  # manually set the HTTP session to provide auth as pyvo doesn't pass this on
            response = result.getdataset()
            datalinks_votable = votable.parse(BytesIO(response.data))

            # get the async_service access URL via an ugly traversal
            # only do this once, it's not going to change for each result as all results will come from CASDA
            access_url = None
            if access_url is None:
                for resource in datalinks_votable.resources:
                    if resource.ID == "async_service":
                        for param in resource.params:
                            if param.ID == "accessURL":
                                access_url = param.value.decode('utf-8')
            
            # get the datalink tokens
            datalinks_table = datalinks_votable.get_first_table().to_table()
            for row in datalinks_table:
                if row['service_def'].decode('utf-8') == "async_service" and row['description'].decode("utf-8") == "Scripted file access via Web":
                    download_tokens.append(row["authenticatedIdToken"])
        
        downloaded_files = []
        if len(download_tokens) > 0:
            # create the async download job on CASDA
            response = requests.post(access_url, params=[('ID', token) for token in download_tokens])
            self._async_job_url = response.url

            # start the async job on CASDA
            response = requests.post(self._async_job_url + "/phase", data={'phase': 'RUN'})

            # wait for the CASDA job to finish
            job_status = self.async_job_status()
            while job_status in ('EXECUTING', 'QUEUED', 'PENDING'):
                time.sleep(poll_period)
                job_status = self.async_job_status()

            # download the result from CASDA
            if job_status != 'ERROR':
                for link in self.async_job_result_file_links():
                    response = requests.get(link, stream=True)
                    try:
                        response.raise_for_status()  # raise exception if something bad happened
                    except requests.exceptions.HTTPError as e:
                        logger.error("Error encountered while attempting to download %s", link)
                        logger.error("%s", e)
                        continue  # next file
                    filename = PurePath(urlsplit(link).path).name
                    output_file: Path = destination / filename
                    # TODO: check Content-Disposition in header to override filename? I'm not sure when this happens.
                    filesize = int(response.headers.get('Content-Length', 0))  # bytes
                    logger.info("Downloading %s (%s)", filename, human_file_size(filesize))
                    with output_file.open(mode='wb') as fout, tqdm(desc=filename, total=filesize, unit="B", unit_scale=True) as pbar:
                        for chunk in response.iter_content(chunk_size=64*1024):
                            fout.write(chunk)
                            pbar.update(len(chunk))
                    logger.info("Downloading %s completed.", filename)
                    downloaded_files.append(output_file)
                    response.close()
            else:
                logger.error("CASDA async job ended with status %s", job_status)
        else:
            logger.warn("No files to download.")
        return downloaded_files

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sbid", help="The ASKAP SBID.")
    parser.add_argument("--credentials_file", type=Path, help="Read ATNF OPAL account credentials from a file containing the username and password on separate lines. If not supplied, user will be prompted to enter these via stdin.")
    parser.add_argument("--destination_dir", type=Path, help="Directory to save downloaded images. Defaults to current directory.", default=".")
    parser.add_argument("--verbose", action="store_true", help="Show more logging information. Useful for debugging.")
    args = parser.parse_args()

    # get the user's OPAL account login
    if args.credentials_file:
        opal_username, opal_password, *_ = args.credentials_file.read_text().split("\n")
    else:
        opal_username = input("ATNF OPAL username: ")
        opal_password = getpass.getpass("ATNF OPAL password: ")
    
    if args.verbose:
        logger.setLevel(logging.INFO)

    casda_query = CasdaSbidImageQuery(args.sbid, opal_username, opal_password)
    casda_query.run(args.destination_dir.expanduser().resolve())
    
    # TODO: verify checksums
if __name__ == "__main__":
    main()
