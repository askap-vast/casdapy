from io import BytesIO
import logging
from pathlib import Path, PurePath
import tarfile
import time
from typing import List, Union, NewType, Optional
from urllib.parse import unquote, urlsplit, urljoin
import warnings
from xml.etree import ElementTree

from astropy.coordinates import SkyCoord
from astropy.io import votable
from astropy.utils.console import human_file_size
import pandas as pd
import pyvo
import requests
from tqdm import tqdm

from .utils import verify_casda_checksum

ElementTreeType = NewType("ElementTreeType", ElementTree.ElementTree)


class BearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r: requests.PreparedRequest):
        r.headers["Authorization"] = f"Bearer {self.token}"
        return r


class CasdaDownloadException(Exception):
    pass


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
    DAP_API_BASE = "https://data.csiro.au/dap"
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
    logger = logging.getLogger(__name__)

    def __init__(
        self,
        sbid: int,
        username: str,
        password: str,
        polarisations: List[str] = ["I"],
        dataproducts: List[str] = ["cont.restored.t0", "catalogue.continuum.component"],
    ):
        self.sbid = sbid
        self._session = requests.Session()
        self._session.auth = (username, password)
        self._tap_service = pyvo.dal.TAPService(self.TAP_URL, session=self._session)
        self._async_job_url: str = ""
        # only allow recognized image data product types and polarizations
        self._dataproducts = [
            dataproduct
            for dataproduct in dataproducts
            if dataproduct in self.DATAPRODUCT_SUBTYPES
        ]
        self._polarisations = [
            pol for pol in polarisations if pol in self.IMAGE_CUBE_POLARIZATIONS
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
    def polarisations(self) -> str:
        """The Stokes polarisations requested in the query as a string suitable for
            insertion into an ADQL statement.
        See `{self.classname}.IMAGE_CUBE_POLARIZATIONS` for available options.
        """
        if len(self._polarisations) == 1:
            return f"('/{self._polarisations[0]}/')"
        else:
            return str(tuple([f"/{pol}/" for pol in self._polarisations]))

    # appease the Yanks
    @property
    def polarizations(self) -> str:
        return self.polarisations

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
        async_job_results = self._async_job_details().find(
            "uws:results", namespaces=self._UWS_NAMESPACES
        )
        if async_job_results is not None:
            results = async_job_results.findall(
                "uws:result", namespaces=self._UWS_NAMESPACES
            )
            links = [
                result.get("{http://www.w3.org/1999/xlink}href") for result in results
            ]
            return [unquote(link) for link in links if link is not None]
        else:
            return []

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

    def _async_job_details(self) -> ElementTree.Element:
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
    ) -> List[Optional[Path]]:
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
            access_url: str = ""
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
            f"{self.DAP_API_BASE}/ws/v2/domains/casdaObservation/download",
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
            if output_file is not None:
                # untar the file and delete the tarball
                with tarfile.open(output_file) as tf:
                    extracted_filenames = tf.getnames()
                    tf.extractall(path=destination)
                output_file.unlink()

                return [destination / f for f in extracted_filenames]
            else:
                return []

        else:
            self.logger.error("CASDA async job ended with status %s", job_status)
            return []

    def _download_casda_link(
        self, link: str, destination: Path, filename: str = None
    ) -> Optional[Path]:
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
        downloaded_files = []

        if do_images:
            tap_results = self._query("images", log_results=dry_run)
            if not dry_run:
                downloaded_image_files = self._download_image_files_async(
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
                f for f in downloaded_files if f and f.suffix != ".checksum"
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


class CasdaPositionQuery:
    """I want to be able to see and optionally download all public ASKAP datasets
    (images, catalogues, MS) for a a given position.

    I want to be able to filter results based on catalogue type, image type, polarisation.
    """

    DAP_API_BASE = "https://data.csiro.au/dap/ws/v2/"
    DAP_API_SEARCH = urljoin(DAP_API_BASE, "domains/casdaObservation/search")
    DAP_API_DOWNLOAD = urljoin(DAP_API_BASE, "domains/casdaObservation/download")
    DAP_REST_USERNAME = "DAP_UI_User@DAPPrd"
    DAP_REST_PASSWORD = ""
    DAP_TOKEN_URL = "https://data.csiro.au/dap/oauth/token"
    CASDA_DATA_ACCESS_BASE_URL = "https://casda.csiro.au/casda_data_access/"
    CASDA_DATA_ASYNC_URL = urljoin(CASDA_DATA_ACCESS_BASE_URL, "data/async/")
    CASDA_DATA_DOWNLOAD_TAR_URL = urljoin(CASDA_DATA_ACCESS_BASE_URL, "downloadtar/")
    CASDA_DATA_DOWNLOAD_LINKS_URL = urljoin(CASDA_DATA_ACCESS_BASE_URL, "download/")
    _UWS_NAMESPACES = {"uws": "http://www.ivoa.net/xml/UWS/v1.0"}
    _CATALOGUE_SUBTYPES = ["Continuum Island", "Continuum Component"]
    _IMAGE_CUBE_SUBTYPES = [
        x.replace(".", "_") for x in CasdaSbidQuery._IMAGE_CUBE_SUBTYPES
    ]
    IMAGE_CUBE_POLARISATIONS = ["I", "Q", "U", "V"]
    DATAPRODUCT_SUBTYPES = _IMAGE_CUBE_SUBTYPES + _CATALOGUE_SUBTYPES
    logger = logging.getLogger(__name__)

    def __init__(
        self,
        ra: Union[str, float, int],
        dec: Union[str, float, int],
        radius: float,
        username: str,
        password: str,
        polarisations: List[str] = ["I"],
        dataproducts: List[str] = ["cont.restored.t0", "catalogue.continuum.component"],
    ):
        if isinstance(ra, str) and isinstance(dec, str):
            unit = "hourangle,deg"
        elif isinstance(ra, (float, int)) and isinstance(dec, (float, int)):
            unit = "deg"
        else:
            raise TypeError(
                f"{self.__class__.__name__} must be initialized with coordinates of the "
                "same type. i.e. Both `ra` and `dec` must be either sexigesimal strings "
                "or in degrees as floats or ints."
            )
        self._async_job_id: Optional[str] = None
        self.coord = SkyCoord(ra=ra, dec=dec, unit=unit)
        self.radius = radius
        self.logger.info(
            "Searching CASDA for data products within %s arcmin of RA %s Dec %s",
            self.radius,
            self.coord.ra.to_string(unit="hourangle", sep=":"),
            self.coord.dec.to_string(unit="deg", sep=":"),
        )
        self._username = username
        self._password = password
        self._session = requests.Session()
        self._session.auth = (self._username, self._password)
        self._auth_token = None
        self.dataproducts = [
            dataproduct.replace(".", "_")
            for dataproduct in dataproducts
            if dataproduct in self.DATAPRODUCT_SUBTYPES
        ]
        self.polarisations = [
            pol for pol in polarisations if pol in self.IMAGE_CUBE_POLARISATIONS
        ]

    # appease the Yanks
    @property
    def polarizations(self):
        return self.polarisations

    @property
    def auth_token(self):
        if self._auth_token is None:
            response = requests.post(
                self.DAP_TOKEN_URL,
                data={
                    "username": f"opal/{self._username}",
                    "password": self._password,
                    "grant_type": "password",
                },
                headers={"Accept": "application/json"},
                auth=(self.DAP_REST_USERNAME, self.DAP_REST_PASSWORD),
            )
            try:
                response.raise_for_status()
            except requests.exceptions.HTTPError as error:
                self.logger.error(
                    "Error encountered while attempting to get auth token"
                )
                self.logger.error("%s", error)
                return None

            self._auth_token = response.json()["access_token"]
        return self._auth_token

    @property
    def async_job_url(self):
        if self._async_job_id is not None:
            return urljoin(self.CASDA_DATA_ASYNC_URL, self._async_job_id)
        else:
            raise ValueError(
                (
                    "Cannot get async job url: no async job ID has been created for "
                    "this query. Call download() first."
                )
            )

    def _async_job_details(self) -> ElementTree.Element:
        """Return the async job details.
        """
        if self._async_job_id is not None:
            response = requests.get(self.async_job_url)
            return ElementTree.fromstring(response.text)
        else:
            raise ValueError(
                (
                    "Cannot get async job details: no async job ID has been created for "
                    "this query. Call download() first."
                )
            )

    def _download_casda_link(
        self, link: str, destination: Path, filename: str = None
    ) -> Path:
        """Download the data file for the given link from CASDA.

        Args:
            link (str): link to data file.
            destination (Path): download destination.
            filename (str, optional): rename the downloaded file to this filename. If
                `None`, use the filename from CASDA. Defaults to None.

        Returns:
            Path: the downloaded file.
        """
        response = requests.get(link, stream=True)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as error:
            self.logger.error("Error encountered while attempting to download %s", link)
            self.logger.error("%s", error)
            raise
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

    def async_job_status(self):
        """Return the async job status, i.e. PENDING, QUEUED, EXECUTING, ERROR, COMPLETED"""
        return (
            self._async_job_details()
            .find("uws:phase", namespaces=self._UWS_NAMESPACES)
            .text
        )

    def async_job_result_file_links(self) -> List[str]:
        """Extract the data file links from a completed async CASDA job.
        """
        async_job_results = self._async_job_details().find(
            "uws:results", namespaces=self._UWS_NAMESPACES
        )
        if async_job_results is not None:
            results = async_job_results.findall(
                "uws:result", namespaces=self._UWS_NAMESPACES
            )
            links = [
                result.get("{http://www.w3.org/1999/xlink}href") for result in results
            ]
            return [unquote(link) for link in links if link is not None]
        else:
            return []

    def query(self) -> List[str]:
        """Perform the cone search query on catalogues and image cubes stored in CASDA.

        Returns:
            List[str]: list of CASDA data object IDs.
        """
        # image and catalogue facets must be queried independently as the facet filters
        # appear to be ANDed, not ORed.
        search_payload = {
            "coneSearches": [
                {
                    "rightAscension": self.coord.ra.to_string(
                        unit="hourangle", sep=":"
                    ),
                    "declination": self.coord.dec.to_string(unit="deg", sep=":"),
                    "radius": self.radius,
                }
            ],
            "facets": [{"label": "Collection Types", "values": ["observational"]}],
            "dataProducts": [
                {"dataProduct": "IMAGE_CUBE", "page": 1, "pageSize": 500},
                {"dataProduct": "CATALOGUE", "page": 1, "pageSize": 500},
            ],
        }
        self.logger.debug("CASDA search payload:")
        self.logger.debug("%s", search_payload)
        response = self._session.post(self.DAP_API_SEARCH, json=search_payload)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as error:
            self.logger.error("Error encountered while sending cone search query.")
            self.logger.error(f"{error}")
            raise

        # query interface is limited: polarisation filtering must be done as a second step
        # locally after receiving the results from the DAP API

        data_object_ids: List[str] = []

        # get results and apply filters
        results_images = response.json()["imageCubeResultDto"]
        results_catalogues = response.json()["catalogueResultDto"]
        df_images = pd.DataFrame(data=results_images["files"])
        df_catalogues = pd.DataFrame(data=results_catalogues["files"])

        if len(df_images) > 0:
            self.logger.debug(
                "%d images found in cone search (before filtering by type, pol, etc)",
                len(df_images),
            )

            df_images = df_images.query(
                (
                    "type.str.lower() in @self.dataproducts and "
                    "polarisation.str.strip('/') in @self.polarizations"
                )
            )
            self.logger.debug("%d images remain after filtering", len(df_images))
            data_object_ids.extend(df_images["dataObjectId"].to_list())
        else:
            self.logger.warning("No images found for given coordinate.")

        if len(df_catalogues) > 0:
            self.logger.debug(
                "%d catalogues found in cone search (before filtering by type, pol, etc)",
                len(df_catalogues),
            )

            df_catalogues = df_catalogues.query("catalogueType in @self.dataproducts")
            self.logger.debug(
                "%d catalogues remain after filtering", len(df_catalogues)
            )
            data_object_ids.extend(df_catalogues["dataObjectId"].to_list())
        else:
            self.logger.warning("No catalogues found for given coordinate.")

        return data_object_ids

    def download(
        self, data_object_ids: List[str], destination: Path, poll_period: int = 30
    ) -> List[Path]:
        """Download the files matching the query parameters from CASDA.

        Args:
            data_object_id_filenames (Mapping[str, str]): a map of CASDA data object IDs
                to their filenames. i.e. the expected output of `.query()`.
            destination (Path): download destination.
            poll_period (int, optional): CASDA async job poll period in seconds. Checks
                the async job status every `poll_period` seconds. Defaults to 30.
            rename (bool, optional): rename the extracted files from the CASDA tarball
                to their proper filenames. Defaults to True.

        Raises:
            CasdaDownloadException: when the downloaded tarball does not contain the
                expected number of files.
            CasdaDownloadException: when no tarball was downloaded at all.
            CasdaDownloadException: when the CASDA async job returns an ERROR status.

        Returns:
            List[Path]: the files downloaded from CASDA.
        """
        self.logger.debug(
            "found %d data object IDs: %s", len(data_object_ids), data_object_ids
        )
        response = self._session.post(
            self.DAP_API_DOWNLOAD,
            params={
                "id": data_object_ids,
                "downloadMode": "WEB",
                "downloadFormat": "VOTABLE_INDIVIDUAL",
            },
            auth=BearerAuth(self.auth_token),
        )
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as error:
            self.logger.error("Error encountered while creating CASDA async job.")
            self.logger.error(f"{error}")
            raise

        self._async_job_id = PurePath(urlsplit(response.json()["jobLink"]).path).parts[
            -3
        ]

        # poll CASDA for async job status, stop when either completed or failed
        job_status = self.async_job_status()
        while job_status in ("EXECUTING", "QUEUED", "PENDING"):
            time.sleep(poll_period)
            job_status = self.async_job_status()

        # when complete, download the requested files (incl checksums)
        downloaded_files: List[Path] = []
        if job_status != "ERROR":
            response = requests.get(
                urljoin(self.CASDA_DATA_DOWNLOAD_LINKS_URL, self._async_job_id)
            )
            response.raise_for_status()
            for link in response.text.split():
                output_file = self._download_casda_link(link, destination)
                if output_file is not None:
                    downloaded_files.append(output_file)
            if len(data_object_ids) != len(downloaded_files) // 2:
                self.logger.error(
                    (
                        "Number of downloaded files (%d) does not match the number of "
                        "requested files (%d). Download was likely interrupted!"
                    ),
                    len(downloaded_files) // 2,
                    len(data_object_ids),
                )
                raise CasdaDownloadException(
                    (
                        "Number of files downloaded from CASDA did not match the number "
                        "of search results."
                    )
                )

            return downloaded_files
        else:
            raise CasdaDownloadException("CASDA async job failed with status: ERROR.")

    # API supports providing multiple coordinates for cone searches, but the results
    # do not indicate which have matches and which do not. Best to handle multi-coord
    # case with multiple queries, combine the results, then proceed to downloading
    # together
