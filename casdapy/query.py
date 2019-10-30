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


class CasdaSbidQuery:
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

    TAP_URL = "https://casda.csiro.au/casda_vo_tools/tap"
    _UWS_NAMESPACES = {"uws": "http://www.ivoa.net/xml/UWS/v1.0"}
    _IMAGE_CUBE_SUBTYPES = [
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
    _CATALOGUE_SUBTYPES = [
        "catalogue.continuum.component",
        "catalogue.continuum.island",
    ]
    DATAPRODUCT_SUBTYPES = _IMAGE_CUBE_SUBTYPES + _CATALOGUE_SUBTYPES
    IMAGE_CUBE_POLARIZATIONS = ["I", "Q", "U", "V"]
    logger: logging.Logger = logging.getLogger("casdapy")

    def __init__(
        self,
        sbid: int,
        username: str,
        password: str,
        polarizations: List[str] = ["I"],
        dataproducts: List[str] = ["cont.restored.t0", "catalogue.continuum.component"],
    ):
        self.sbid = sbid
        self._session = requests.Session()
        self._session.auth = (username, password)
        self._tap_service = pyvo.dal.TAPService(self.TAP_URL, session=self._session)
        self._async_job_url = None
        # only allow recognized image data product types and polarizations
        self._dataproducts = [
            dataproduct
            for dataproduct in dataproducts
            if dataproduct in self.DATAPRODUCT_SUBTYPES
        ]
        self._polarizations = [
            pol for pol in polarizations if pol in self.IMAGE_CUBE_POLARIZATIONS
        ]

    @property
    def dataproducts(self) -> str:
        """The data product types requested in the query as a string suitable for
            insertion into an ADQL statement.
        See `{self.classname}.DATAPRODUCT_SUBTYPES` for available options.
        """
        if len(self._dataproducts) == 1:
            return f"('{self._dataproducts[0]}')"
        else:
            return str(tuple(self._dataproducts))

    @property
    def polarizations(self) -> str:
        """The Stokes polarizations requested in the query as a string suitable for
            insertion into an ADQL statement.
        See `{self.classname}.IMAGE_CUBE_POLARIZATIONS` for available options.
        """
        if len(self._polarizations) == 1:
            return f"('/{self._polarizations[0]}/')"
        else:
            return str(tuple([f"/{pol}/" for pol in self._polarizations]))

    @property
    def adql_query_images(self) -> str:
        """The ADQL query string to search CASDA for images based on the given SBID,
            data products and polarizations.
        """
        return (
            f"SELECT * FROM ivoa.obscore WHERE obs_id = '{self.sbid}' "
            f"AND dataproduct_type = 'cube' AND dataproduct_subtype IN {self.dataproducts} "
            f"AND pol_states IN {self.polarizations}"
        )

    # do separately from images as async isn't needed here (nor is it provided by CASDA)
    @property
    def adql_query_catalogues(self):
        """The ADQL query string to search CASDA for catalogues based on the given SBID
            and data products.
        """
        return (
            f"SELECT * FROM ivoa.obscore WHERE obs_id = '{self.sbid}' "
            f"AND dataproduct_subtype IN {self.dataproducts}"
        )

    def async_job_result_file_links(self) -> List[str]:
        """Extract the data file links from a completed async CASDA job.
        """
        results = (
            self._async_job_details()
            .find("uws:results", namespaces=self._UWS_NAMESPACES)
            .findall("uws:result", namespaces=self._UWS_NAMESPACES)
        )
        return [
            unquote(result.get("{http://www.w3.org/1999/xlink}href"))
            for result in results
        ]

    def _query(
        self, query_type: str = "catalogues", log_results: bool = False
    ) -> pyvo.dal.tap.TAPResults:
        """Send the requested query type to CASDA and return the results table.

        Args:
            query_type (str, optional): Either "catalogues" or "images. Defaults to "catalogues".
            log_results (bool, optional): Print the results table to the logger. Defaults to False.

        Returns:
            pyvo.dal.tap.TAPResults: The results table of matching files in CASDA.
        """
        if query_type == "images":
            adql_query = self.adql_query_images
        else:
            adql_query = self.adql_query_catalogues
        self.logger.info("ADQL query: %s", adql_query)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # ignore votable warnings
            results: pyvo.dal.tap.TAPResults = self._tap_service.search(adql_query)
        self.logger.info("TAP result returned with %d records", len(results))

        if log_results:
            log_level = self.logger.level
            self.logger.setLevel(logging.INFO)
            self.logger.info(
                "\n%s",
                results.to_table()[
                    [
                        "obs_id",
                        "access_estsize",
                        "dataproduct_subtype",
                        "quality_level",
                        "filename",
                    ]
                ],
            )
            # report the total file sizes for images (catalogues don't have their sizes
            # recorded)
            if query_type == "images":
                self.logger.info(
                    "Total file size %s",
                    human_file_size(results.to_table()["access_estsize"].to("b").sum()),
                )
            self.logger.setLevel(log_level)
        return results

    def _async_job_details(self) -> ElementTree:
        """Return the async job details.
        """
        response = requests.get(self._async_job_url)
        return ElementTree.fromstring(response.text)

    def async_job_status(self):
        """Return the async job status, i.e. PENDING, QUEUED, EXECUTING, ERROR, COMPLETED"""
        return (
            self._async_job_details()
            .find("uws:phase", namespaces=self._UWS_NAMESPACES)
            .text
        )

    def _download_image_files_async(
        self, tap_results: pyvo.dal.TAPResults, destination: Path, poll_period: int
    ) -> List[Path]:
        """Download the images given in the CASDA results table.

        Args:
            tap_results (pyvo.dal.TAPResults): The CASDA results table. i.e. the output
                of `self._query("images", ...)`.
            destination (Path): Path to download destination.
            poll_period (int): Period to poll CASDA for job status updates in seconds.

        Returns:
            List[Path]: the downloaded files.
        """
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
                    output_file = self._download_casda_link(link, destination)
                    downloaded_files.append(output_file)
            else:
                self.logger.error("CASDA async job ended with status %s", job_status)
        else:
            self.logger.warn("No files to download.")
        return downloaded_files

    def _download_catalogue_files_async(
        self, tap_results: pyvo.dal.TAPResults, destination: Path, poll_period: int
    ) -> List[Path]:
        """Download the catalogues given in the CASDA results table. Files will be
            downloaded as a tarball and automatically extracted. The tarball will be
            deleted.

        Args:
            tap_results (pyvo.dal.TAPResults): The CASDA results table. i.e. the output
                of `self._query("catalogues", ...)`.
            destination (Path): Path to download destination.
            poll_period (int): Period to poll CASDA for job status updates in seconds.

        Returns:
            List[Path]: the downloaded files.
        """
        # query ivoa.obscore as we did for the images, get the obs_publisher_did for
        # each result
        catalogue_ids = [
            _id.decode("utf-8") for _id in tap_results["obs_publisher_did"]
        ]
        self.logger.info("Found %d catalogues.", len(catalogue_ids))

        # query DAP API to get the download link
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
            output_file = self._download_casda_link(
                link, destination, filename=f"{job_id}.tar"
            )

            # untar the file and delete the tarball
            with tarfile.open(output_file) as tf:
                extracted_filenames = tf.getnames()
                tf.extractall(path=destination)
            output_file.unlink()

            return [destination / f for f in extracted_filenames]

        else:
            self.logger.error("CASDA async job ended with status %s", job_status)
            return []

    def _download_casda_link(
        self, link: str, destination: Path, filename: str = None
    ) -> Path:
        """Download the data file for the given link from CASDA.

        Args:
            link (str): link to data file.
            destination (Path): download destination.
            filename (str, optional): rename the downloaded file to this filename. If
                `None`, use the filename from CASDA.. Defaults to None.

        Returns:
            Path: the downloaded file.
        """
        response = requests.get(link, stream=True)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as error:
            self.logger.error("Error encountered while attempting to download %s", link)
            self.logger.error("%s", error)
            return None
        filename = PurePath(urlsplit(link).path).name if filename is None else filename
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
        response.close()
        return output_file

    def run(
        self, download_destination: Path, poll_period: int = 30, dry_run: bool = False
    ):
        """Perform the requested ADQL queries and download the matching files.

        Args:
            download_destination (Path): download destination.
            poll_period (int, optional): period to poll CASDA for async job status in
                seconds. Defaults to 30.
            dry_run (bool, optional): do not download any files, only perform the queries
                and log the matching files. Defaults to False.
        """
        do_images = any([x in self._IMAGE_CUBE_SUBTYPES for x in self._dataproducts])
        do_catalogues = any([x in self._CATALOGUE_SUBTYPES for x in self._dataproducts])
        downloaded_files: List[Path] = []

        if do_images:
            tap_results = self._query("images", log_results=dry_run)
            if not dry_run:
                downloaded_image_files: List[Path] = self._download_image_files_async(
                    tap_results, download_destination, poll_period
                )
                self.logger.info(
                    "Downloaded %d image files into %s",
                    len(downloaded_image_files),
                    download_destination,
                )
                downloaded_files.extend(downloaded_image_files)

        if do_catalogues:
            tap_results = self._query("catalogues", log_results=dry_run)
            if not dry_run:
                downloaded_catalogue_files: List[
                    Path
                ] = self._download_catalogue_files_async(
                    tap_results, download_destination, poll_period
                )
                self.logger.info(
                    "Downloaded %d catalogue files into %s",
                    len(downloaded_catalogue_files),
                    download_destination,
                )
                downloaded_files.extend(downloaded_catalogue_files)

        if not dry_run:
            # verify the checksums (should be downloaded automatically)
            n_passed = 0
            downloaded_data_files = [
                f for f in downloaded_files if f.suffix != ".checksum"
            ]
            for file in downloaded_data_files:
                checksum_passed = verify_casda_checksum(file)
                if not checksum_passed:
                    self.logger.error("Checksum failed for %s", file)
                else:
                    n_passed += 1
            self.logger.info(
                "%d of %d files passed checksum verification.",
                n_passed,
                len(downloaded_data_files),
            )
