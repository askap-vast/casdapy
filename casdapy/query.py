from abc import ABC, abstractmethod
from io import BytesIO
import logging
from pathlib import Path, PurePath
import tarfile
import time
from typing import List
from urllib.parse import unquote, urlsplit
import warnings
from xml.etree import ElementTree

from astropy.io import votable
from astropy.utils.console import human_file_size
import pyvo
import requests
from tqdm import tqdm

from .utils import verify_casda_checksum


class _CasdaSbidQuery(ABC):
    TAP_URL = "https://casda.csiro.au/casda_vo_tools/tap"
    _UWS_NAMESPACES = {"uws": "http://www.ivoa.net/xml/UWS/v1.0"}
    logger: logging.Logger = logging.getLogger("casdapy")

    def __init__(self, sbid: int, username: str, password: str):
        self._session = requests.Session()
        self._session.auth = (username, password)
        self._tap_service = pyvo.dal.TAPService(self.TAP_URL, session=self._session)
        self._dataproducts = []  # filled by subclass init
        self.sbid = sbid

    @property
    def dataproducts(self):
        if len(self._dataproducts) == 1:
            return f"('{self._dataproducts[0]}')"
        else:
            return tuple(self._dataproducts)

    def _query(self, adql_query: str = None) -> pyvo.dal.tap.TAPResults:
        if adql_query is None:
            adql_query = self.adql_query
        self.logger.info("ADQL query: %s", adql_query)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # ignore votable warnings
            results: pyvo.dal.tap.TAPResults = self._tap_service.search(adql_query)
        self.logger.info("TAP result returned with %d records", len(results))
        return results

    def _async_job_details(self) -> ElementTree:
        response = requests.get(self._async_job_url)
        return ElementTree.fromstring(response.text)

    def async_job_status(self):
        return (
            self._async_job_details()
            .find("uws:phase", namespaces=self._UWS_NAMESPACES)
            .text
        )

    @abstractmethod
    def _download_files_async(
        self, tap_results: pyvo.dal.TAPResults, destination: Path, poll_period: int
    ) -> List[Path]:
        pass

    def run(
        self,
        download_destination: Path,
        adql_query: str = None,
        poll_period: int = 30,
        dry_run: bool = False,
    ):
        tap_results = self._query(adql_query)

        log_level = self.logger.level
        if dry_run:
            self.logger.setLevel(logging.INFO)
        self.logger.info(
            "%s",
            tap_results.to_table()[
                [
                    "obs_id",
                    "access_estsize",
                    "dataproduct_subtype",
                    "quality_level",
                    "filename",
                ]
            ],
        )
        self.logger.setLevel(log_level)

        if dry_run:
            return

        downloaded_files: List[Path] = self._download_files_async(
            tap_results, download_destination, poll_period
        )
        self.logger.info(
            "Downloaded %d files into %s",
            len(downloaded_files),
            download_destination,
        )

        # verify the checksums (should be downloaded automatically)
        n_passed = 0
        for file in downloaded_files:
            checksum_passed = verify_casda_checksum(file)
            if not checksum_passed:
                self.logger.error("Checksum failed for %s", file)
            else:
                n_passed += 1
        self.logger.info(
            "%d of %d files passed checksum verification.",
            n_passed,
            len(downloaded_files),
        )


class CasdaSbidCatalogueQuery(_CasdaSbidQuery):
    CATALOGUE_SUBTYPES = ["catalogue.continuum.component", "catalogue.continuum.island"]

    def __init__(
        self,
        sbid: int,
        username: str,
        password: str,
        dataproducts: List[str] = ["catalogue.continuum.component"],
    ):
        super().__init__(sbid, username, password)
        # only allow recognized catalogue data product types
        self._dataproducts = [
            dataproduct
            for dataproduct in dataproducts
            if dataproduct in self.CATALOGUE_SUBTYPES
        ]

    @property
    def adql_query(self):
        return (
            f"SELECT * FROM ivoa.obscore WHERE obs_id = '{self.sbid}' "
            f"AND dataproduct_subtype IN {self.dataproducts}"
        )

    def _download_files_async(
        self, tap_results: pyvo.dal.TAPResults, destination: Path, poll_period
    ) -> List[Path]:
        # query ivoa.obscore as we did for the images, get the obs_publisher_did for
        # each result
        catalogue_ids = [
            _id.decode("utf-8") for _id in tap_results["obs_publisher_did"]
        ]
        self.logger.info("Found %d catalogues.", len(catalogue_ids))

        # query DAP API to get the download link e.g.
        # https://data.csiro.au/dap/ws/v2/domains/casdaObservation/download?downloadMode=WEB&downloadFormat=VOTABLE_INDIVIDUAL&id=catalogue-90&id=catalogue-91
        response = requests.post(
            "https://data.csiro.au/dap/ws/v2/domains/casdaObservation/download",
            params={
                "downloadMode": "WEB",
                "downloadFormat": "VOTABLE_INDIVIDUAL",
                "id": catalogue_ids,
            },
        )
        # will return a download link
        # e.g. https://casda.csiro.au/casda_data_access/requests/<job_id>/page/1
        # get the job_id out of the above link
        job_id = PurePath(urlsplit(response.json()["jobLink"]).path).parts[-3]
        self._async_job_url = (
            f"https://casda.csiro.au/casda_data_access/data/async/{job_id}"
        )

        # check status in the same way the image async jobs are checked
        # e.g. https://casda.csiro.au/casda_data_access/data/async/<job_id> and read the phase
        job_status = self.async_job_status()
        while job_status in ("EXECUTING", "QUEUED", "PENDING"):
            time.sleep(poll_period)
            job_status = self.async_job_status()

        # when complete, download a TAR of the requested files (incl checksums) with
        # https://casda.csiro.au/casda_data_access/downloadtar/<job_id>
        if job_status != "ERROR":
            link = f"https://casda.csiro.au/casda_data_access/downloadtar/{job_id}"
            response = requests.get(link, stream=True)
            try:
                response.raise_for_status()
            except requests.exceptions.HTTPError as error:
                self.logger.error(
                    "Error encountered while attempting to download %s", link
                )
                self.logger.error("%s", error)
                raise error
            filename = f"{job_id}.tar"
            output_file: Path = destination / filename
            filesize = int(response.headers.get("Content-Length", 0))  # bytes
            self.logger.info("Downloading %s (%s)", filename, human_file_size(filesize))
            with output_file.open(mode="wb") as fout, tqdm(
                desc=filename, total=filesize, unit="B", unit_scale=True
            ) as pbar:
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    fout.write(chunk)
                    pbar.update(len(chunk))
            self.logger.info("Downloading %s completed.", filename)

            # untar the file and delete the tarball
            with tarfile.open(output_file) as tf:
                extracted_filenames = tf.getnames()
                tf.extractall(path=destination)
            output_file.unlink()

            return [destination / f for f in extracted_filenames]

        else:
            self.logger.error("CASDA async job ended with status %s", job_status)
            return []


class CasdaSbidImageQuery(_CasdaSbidQuery):
    """Hides the insanity involved in querying CASDA for images.

    Args:
        sbid (int): The scheduling block ID to query.
        username (str): CASDA account username. Required for downloading images. May be
            an ATNF OPAL, CSIRO NEXUS or Partner account.
        password (str): CASDA account password. Required for downloading images. May be
            an ATNF OPAL, CSIRO NEXUS or Partner account.
        polarizations (List[str], optional): List of polarizations (Stokes parameters).
            Defaults to ["I",].
        dataproducts (List[str], optional): List of image data product types. See
            `CasdaImageQuery.IMAGE_CUBE_SUBTYPES` for possible values. Defaults to
            ["cont.restored.t0",].
    """

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
    IMAGE_CUBE_POLARIZATIONS = ["I", "Q", "U", "V"]

    def __init__(
        self,
        sbid: int,
        username: str,
        password: str,
        polarizations: List[str] = ["I"],
        dataproducts: List[str] = ["cont.restored.t0"],
    ):
        super().__init__(sbid, username, password)
        self._async_job_url = None
        # only allow recognized image data product types and polarizations
        self._dataproducts = [
            dataproduct
            for dataproduct in dataproducts
            if dataproduct in self.IMAGE_CUBE_SUBTYPES
        ]
        self._polarizations = [
            pol for pol in polarizations if pol in self.IMAGE_CUBE_POLARIZATIONS
        ]

    @property
    def polarizations(self):
        if len(self._polarizations) == 1:
            return f"('/{self._polarizations[0]}/')"
        else:
            return tuple([f"/{pol}/" for pol in self._polarizations])

    @property
    def adql_query(self):
        return (
            f"SELECT * FROM ivoa.obscore WHERE obs_id = '{self.sbid}' "
            f"AND dataproduct_type = 'cube' AND dataproduct_subtype IN {self.dataproducts} "
            f"AND pol_states IN {self.polarizations}"
        )

    def async_job_result_file_links(self):
        results = (
            self._async_job_details()
            .find("uws:results", namespaces=self._UWS_NAMESPACES)
            .findall("uws:result", namespaces=self._UWS_NAMESPACES)
        )
        return [
            unquote(result.get("{http://www.w3.org/1999/xlink}href"))
            for result in results
        ]

    def _download_files_async(
        self, tap_results: pyvo.dal.TAPResults, destination: Path, poll_period
    ) -> List[Path]:
        download_tokens = []
        for i, result in enumerate(tap_results):
            self.logger.info("Processing TAP result %d of %d", i + 1, len(tap_results))
            # manually set the HTTP session to provide auth as pyvo doesn't pass this on
            result._session = self._session
            response = result.getdataset()
            datalinks_votable = votable.parse(BytesIO(response.data))

            # get the async_service access URL via an ugly traversal
            # only do this once, it's not going to change for each result as all results
            # will come from CASDA
            access_url = None
            if access_url is None:
                for resource in datalinks_votable.resources:
                    if resource.ID == "async_service":
                        for param in resource.params:
                            if param.ID == "accessURL":
                                access_url = param.value.decode("utf-8")

            # get the datalink tokens
            datalinks_table = datalinks_votable.get_first_table().to_table()
            for row in datalinks_table:
                if (
                    row["service_def"].decode("utf-8") == "async_service"
                    and row["description"].decode("utf-8")
                    == "Scripted file access via Web"
                ):
                    download_tokens.append(row["authenticatedIdToken"])

        downloaded_files = []
        if len(download_tokens) > 0:
            # create the async download job on CASDA
            response = requests.post(
                access_url, params=[("ID", token) for token in download_tokens]
            )
            self._async_job_url = response.url
            self.logger.info("async job URL: %s", self._async_job_url)

            # start the async job on CASDA
            response = requests.post(
                self._async_job_url + "/phase", data={"phase": "RUN"}
            )

            # wait for the CASDA job to finish
            job_status = self.async_job_status()
            while job_status in ("EXECUTING", "QUEUED", "PENDING"):
                time.sleep(poll_period)
                job_status = self.async_job_status()

            # download the result from CASDA
            if job_status != "ERROR":
                for link in self.async_job_result_file_links():
                    response = requests.get(link, stream=True)
                    try:
                        response.raise_for_status()
                    except requests.exceptions.HTTPError as error:
                        self.logger.error(
                            "Error encountered while attempting to download %s", link
                        )
                        self.logger.error("%s", error)
                        continue  # next file
                    filename = PurePath(urlsplit(link).path).name
                    output_file: Path = destination / filename
                    filesize = int(response.headers.get("Content-Length", 0))  # bytes
                    self.logger.info(
                        "Downloading %s (%s)", filename, human_file_size(filesize)
                    )
                    with output_file.open(mode="wb") as fout, tqdm(
                        desc=filename, total=filesize, unit="B", unit_scale=True
                    ) as pbar:
                        for chunk in response.iter_content(chunk_size=64 * 1024):
                            fout.write(chunk)
                            pbar.update(len(chunk))
                    self.logger.info("Downloading %s completed.", filename)
                    downloaded_files.append(output_file)
                    response.close()
            else:
                self.logger.error("CASDA async job ended with status %s", job_status)
        else:
            self.logger.warn("No files to download.")
        return downloaded_files
