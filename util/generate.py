"""Generation modules for session generation and message generation"""
import logging

from typing import Tuple, List

from googleapiclient import discovery
from oauth2client.service_account import ServiceAccountCredentials

LOG = logging.getLogger(__name__)


def generate_session(key_file='', service='compute'):
    """generates GCP session from keyfile"""

    session = None

    if key_file:
        try:
            credentials = ServiceAccountCredentials.from_json_keyfile_name(
                key_file
            )
            session = discovery.build(service, 'v1', credentials=credentials)
        except FileNotFoundError as error:
            LOG.error(error)

    return session


def generate_message(items: List[Tuple],
                     project: str) -> str:
    """generates a message with the payload from gcp_audit

    Args:
        items (List[namedtuple])

    Returns:
       Str for processing in Slack

    """


    if len(items) > 1:
        req = 'require'
    else:
        req = 'requires'

    base_msg = "The following in project: {project} {req} attention:\n".format(
        project=project,
        req=req)

    info = []
    all_others = []

    for item in items:
        info = ["*%s*: `%s`\n" % (k, v) for k, v in item.info.items()]
        all_others.extend(["*Name*: `{}`\n*Type*: `{}`\n{}\n\n".format(
            item.name,
            item.type_,
            ' '.join(info)
        )])

    return base_msg + ' '.join(all_others)

def generate_dict_message(items: List[Tuple]) -> dict:
    """generates json for writing to file if violations exceed set limit

    Args:
        items (List[Tuple])

    Returns:
        json formatted dict

    """

    result_list = []

    if isinstance(items, list):
        for item in items:
            result = {}
            result[item.type_] = {
                'name': item.name,
                'info': item.info
                }
            result_list.append(result)
    else:
        raise TypeError('items must be a list of tuples')

    return result_list

def generate_upload_message(resp: dict,
                            project: str):
    """Generates message for when violation results are too large
    to attach to a slack message. Args generated from util.upload_to_bucket.

    Args:
        resp: dict

    Returns:
        str
    """

    # stripping ms as superflous
    time = resp['timeCreated'].split('.')[0]

    base_msg = (f"Too many violations in *{project}* to list here - "
                "results have been uploaded to the following:\n")

    info = """*Bucket*: `{}`\n*Total Violations*: `{}`
*ID*: `{}`\n*Size* _(kb)_: `{}`\n*Created*: `{}`""".format(
    resp['bucket'],
    resp['total'],
    resp['id'],
    int(resp['size']) / 1000, # original is in bytes
    time.replace('T', ' '))

    return base_msg + info
