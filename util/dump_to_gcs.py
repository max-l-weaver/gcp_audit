# pylint: disable=no-member
"""Module for writing and uploading reports to a GCS bucket"""
import os

import datetime
import json
import socket

from typing import List, Tuple
import logging

from googleapiclient.http import MediaIoBaseUpload
from googleapiclient.errors import HttpError
import googleapiclient.discovery

from util.generate import generate_session, generate_dict_message
from util.generate import generate_upload_message
from util.slack import notify_alerts_security

NOW = datetime.datetime.now()
LOG = logging.getLogger(__name__)
BUCKET = 'gcp-audit-dumps'

class EmptyRecordsError(Exception):
    """Custom exception for empty records"""
    pass

class EmptyDumpFileError(Exception):
    """Custom exception for empty dump file"""
    pass

def _generate_session(keyfile: str) -> googleapiclient.discovery.Resource:
    """Generates a Google storage session

    Args:
        keyfile (str): path to service file
        required for generating session.

    """

    session = generate_session(keyfile, service='storage')
    return session


def write_file(records: List[Tuple]) -> str:
    """Writes dict file for dumping to json

    Args:
        records (List[Tuple]): generated by util.gcp.Gcp via gcp_audit

    """

    if not records:
        LOG.exception('No input data. Please check input')
        raise EmptyRecordsError('No files to be written - please check input')

    # time in 2018-03-01_00:00:00 format
    now_full = NOW.strftime('%Y-%m-%d_%H%M%S')
    file_name = f'{now_full}_violation_dump.json'
    base_path = os.path.abspath('tmp')
    local_path = os.path.join(base_path, file_name)

    message = generate_dict_message(records)

    with open(local_path, 'w') as dump_file:
        json.dump(message,
                  dump_file, indent=4)
        LOG.info('file %s created - ready for upload' % dump_file)

    return local_path


def upload_to_bucket(records: List[Tuple],
                     keyfile: str,
                     project: str):
    """Takes the file generated in _write_file and uploads it to a
    bucket for analysis.
    If the upload fails it will keep the local copy, orherwise it'll
    delete it.

    Args:
        records (List[Tuple]): passed from gcp_audit
        keyfile (str): path to service file
        project (str): purely for name generation

    """

    dump_file = write_file(records)
    # Generating file path and name for uploading to GCS
    file_name = dump_file.split('/')[-1]
    remote_path = os.path.join(NOW.strftime('%Y'),
                               NOW.strftime('%B'),
                               file_name)

    if dump_file:
        try:
            fbytes = os.stat(dump_file).st_size
            fbytes_to_kb = fbytes / 1000
            LOG.info('file size to upload: %s kb' % fbytes_to_kb)
        except FileNotFoundError as error:
            LOG.error(error, 'dump file does not exist!')

    if fbytes:
        body = {'name': remote_path}
    else:
        raise EmptyDumpFileError('Dump file is empty. Aborting!')

    session = _generate_session(keyfile=keyfile)

    LOG.info("let's try and upload this mother")
    LOG.info('uploading %s' % dump_file)
    with open(dump_file, 'rb') as filez:
        try:
            req = session.objects().insert(
                bucket=f'{BUCKET}-{project}',
                body=body,
                media_body=MediaIoBaseUpload(
                    filez, 'application/json'))
            resp = req.execute()
        except (HttpError, socket.timeout) as error:
            LOG.error(error, 'local copy %s kept' % dump_file)
        else:
            LOG.info('%r uploaded, now deleting local copy' % dump_file)
            os.remove(dump_file)

    # generates a specific alert in Slack
    resp['total'] = len(records)
    notify_alerts_security(generate_upload_message(resp, project=project))
