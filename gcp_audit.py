#!/usr/bin/env python3
"""
This program runs through a list of specified checks to ensure firewalls,
buckets and bucket objects are secure.

Checks are run sequentially in main method
"""
import logging

from argparse import ArgumentParser

from util.gcp import Gcp
from util.slack import notify_alerts_security
from util.generate import generate_message
from util.dump_to_gcs import upload_to_bucket

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)

# A list to collect all the insecure objects
LIST_OF_SHAME = []

def check_firewall_rules(obj):
    """checks all firewall rules for insecure protocols"""

    LOG.info('checking firewall in %r', obj.project)
    for rule in obj.get_full_firewall_rules():
        if rule.info['protocol'] == 'all' and '0.0.0.0/0' in rule.info['ranges']:
            LIST_OF_SHAME.append(rule)


def check_bucket_acl(obj):
    """checks bucket acls"""

    LOG.info('checking bucket acls in %r', obj.project)
    for acl in obj.get_all_bucket_acl():
        if 'allUsers' in acl.info['entity']:
            LIST_OF_SHAME.append(acl)


def check_objects_acl(obj):
    """checks objects acls"""

    LOG.info('checking bucket object acls in %r', obj.project)
    for acl in obj.get_all_objects_acls():
        if 'allUsers' in acl.info['entity']:
            LIST_OF_SHAME.append(acl)

def argument_parser():
    """Arguments for project and keyfile"""
    #TODO: whitelist option for buckets and/or objects

    parser = ArgumentParser(description='Run checks on GCP for firewall/bucket security issues')
    parser.add_argument('-p', '--project', help='Specify project you wish to scan')
    parser.add_argument('-k', '--keyfile', help='Specify GCP credentials keyfile')
    parser.add_argument('--whitelist', help="""whitelists one or more buckets.
Whitelist should be in a yaml format. Please see documentation!""")

    options = parser.parse_args()

    return options

def main():
    """runs all checks"""

    options = argument_parser()

    LOG.info('Starting to run check')
    run_check = Gcp(options.project,
                    options.keyfile,
                    options.whitelist)
    checks = [
        check_firewall_rules,
        check_bucket_acl,
        check_objects_acl
    ]

    for check in checks:
        check(run_check)

    # Getting total number of violations
    length = len(LIST_OF_SHAME)

    if 0 < length < 15:
        msg = generate_message(LIST_OF_SHAME, options.project)
        notify_alerts_security(msg)
        LOG.info('submitted %r checks' % length)
    elif length > 15:
        LOG.info('too many violations - dumping to file')
        upload_to_bucket(records=LIST_OF_SHAME,
                         keyfile=options.keyfile,
                         project=options.project)
    else:
        LOG.info('all clear. No violations found')

    LOG.info('checks completed')

if __name__ == '__main__':
    main()
