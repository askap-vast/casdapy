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


uws_namespaces = {'uws': 'http://www.ivoa.net/xml/UWS/v1.0'}
def get_job_details(job_url):
    r = requests.get(job_url)
    return ElementTree.fromstring(r.text)

def get_job_status(job_url):
    job_details = get_job_details(job_url)
    return job_details.find("uws:phase", namespaces=uws_namespaces).text

def get_job_result_file_links(job_url):
    job_details = get_job_details(job_url)
    results = job_details.find("uws:results", namespaces=uws_namespaces).findall("uws:result", namespaces=uws_namespaces)
    return [unquote(result.get("{http://www.w3.org/1999/xlink}href")) for result in results]

# TODO: logging
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sbid", help="The ASKAP SBID.")
    parser.add_argument("--credentials_file", type=Path, help="Read ATNF OPAL account credentials from a file. Username and password on separate lines.")
    parser.add_argument("--destination_dir", type=Path, help="Directory to save downloaded images. Defaults to current directory.", default=".")
    args = parser.parse_args()

    # get the user's OPAL account login
    if args.credentials_file:
        opal_username, opal_password, *_ = args.credentials_file.read_text().split("\n")
    else:
        opal_username = input("ATNF OPAL username: ")
        opal_password = getpass.getpass("ATNF OPAL password: ")

    session = requests.Session()
    session.auth = (opal_username, opal_password)
    casda_tap_service = pyvo.dal.TAPService("https://casda.csiro.au/casda_vo_tools/tap", session=session)

    # TODO: allow user to customise this query
    data_product_id_query = f"SELECT * FROM ivoa.obscore WHERE obs_id = '{args.sbid}' AND dataproduct_type = 'cube' AND dataproduct_subtype = 'cont.restored.t0'"

    # TODO: more data filters can be applied here, e.g. polarisation
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # ignore votable warnings
        results = casda_tap_service.search(data_product_id_query)

    # collect the datalink auth tokens for async download
    download_tokens = []  # list of auth tokens
    for result in results:
        result._session = session  # manually set the HTTP session to provide auth as pyvo doesn't pass this on
        r = result.getdataset()
        datalinks_votable = votable.parse(BytesIO(r.data))

        # get the async_service access URL
        access_url = None
        if access_url is None:  # only do this once, it's not going to change for each result as all results will come from CASDA
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

    if len(download_tokens) > 0:
        # create the async download job on CASDA
        r = requests.post(access_url, params=[('ID', token) for token in download_tokens])
        job_url = r.url

        # start the async job on CASDA
        r = requests.post(job_url + "/phase", data={'phase': 'RUN'})

        # wait for the CASDA job to finish
        job_status = get_job_status(job_url)
        while job_status in ('EXECUTING', 'QUEUED', 'PENDING'):
            time.sleep(30)
            job_status = get_job_status(job_url)

        # download the result from CASDA
        if job_status != 'ERROR':
            download_links = get_job_result_file_links(job_url)
            for link in download_links:
                response = requests.get(link, stream=True)
                try:
                    response.raise_for_status()  # raise exception if something bad happened
                except requests.exceptions.HTTPError as e:
                    print(f"Error encountered while trying to download {link}")
                    print(e)
                    continue  # next file
                filename = PurePath(urlsplit(link).path).name
                output_file: Path = args.destination_dir / filename
                # TODO: check Content-Disposition in header to override filename? I'm not sure when this happens.
                filesize = int(response.headers.get('Content-Length', 0))  # bytes
                print(f"Downloading {filename} ({human_file_size(filesize)})")
                with output_file.open(mode='wb') as fout, tqdm(desc=filename, total=filesize, unit="B", unit_scale=True) as pbar:
                    for chunk in response.iter_content(chunk_size=64*1024):
                        fout.write(chunk)
                        pbar.update(len(chunk))
                print(f"Downloading {filename} completed.")
                response.close()
        else:
            print("Error encountered in CASDA async job.")
    else:
        print(f"No files to download for SBID {args.sbid}")
    
    # TODO: verify checksums
if __name__ == "__main__":
    main()
