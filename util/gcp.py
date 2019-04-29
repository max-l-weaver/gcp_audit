# pylint: disable=no-member
"""get gcp storage/firewall data"""
import socket
import os
import logging
from collections import namedtuple
import yaml
import time
from random import randint

from googleapiclient.errors import HttpError

from .generate import generate_session

LOG = logging.getLogger(__name__)

AllTuple = namedtuple('AllTuple', ['name', 'type_', 'info'])

class Gcp(object):
    """Generates returners for buckets and firewalls. Unfortunately
    you have to specify different services, so compute for firewall
    and storage for buckets."""

    def __init__(self,
                 project='',
                 kfile='',
                 whitelist=''):
        self.storage_session = generate_session(kfile, service='storage')
        self.compute_session = generate_session(kfile, service='compute')
        self.project = project
        self.config_results = {'buckets': False,
                               'objects': False}
        self.whitelist = self._load_whitelist_file(whitelist) if whitelist else None
        self.buckets = self._get_all_buckets()

    def _load_whitelist_file(self, whitelist):
        """loads config file in ./gcp-audit/config"""

        # Expand homedir
        if whitelist[0] == '~':
            homedir = os.path.expanduser('~')
            whitelist = whitelist.replace('~', homedir)

        try:
            with open(whitelist, 'r') as w_l:
                whitelist = yaml.load(w_l)
        except OSError as error:
            LOG.error(error, 'whitelist file not found - Not whitelisting!')
            return None

        try:
            whitelist = whitelist[self.project]
        except KeyError:
            LOG.error('%r not specified in config whitelist - please check!' %
                      self.project)
            whitelist = {}
        else:
            for item in ['buckets', 'objects']:
                try:
                    whitelist[item]
                except KeyError:
                    LOG.info('%r not specified in whitelist so ignoring' % item)
                else:
                    self.config_results[item] = True

        return whitelist

    def _get_all_buckets(self):
        """gets a list of all buckets for the subsequent bucket tasks.
        Also removes any whitelisted buckets"""

        buckets = []

        if self.storage_session:
            all_buckets = self.storage_session.buckets().list(
                project=self.project).execute()
            buckets = [bucket['name'] for bucket in all_buckets['items']]

        if self.config_results['buckets']:
            buckets_to_remove = self.whitelist['buckets']
            for index, item in enumerate(buckets_to_remove):
                try:
                    bucket = item
                    buckets.remove(item)
                except ValueError:
                    LOG.info('Whitelist: %r not found so ignoring' % bucket)
                    continue

        return buckets


    def _get_all_objects(self):
        """gets all objects from each bucket in a damn inefficient way"""

        objects = namedtuple('AllObjects', ['bucket', 'name'])
        all_objects_list = []
        object_whitelist = []

        if self.config_results['objects']:
            object_whitelist = self.whitelist['objects']

        for bucket in self.buckets:
            for i in range(5):
                try:
                    all_objects = self.storage_session.objects().list(
                        bucket=bucket).execute()
                    all_objects = all_objects['items']
                except KeyError:
                    # Bucket is empty so we'll skip
                    continue
                except (socket.timeout, HttpError) as error:
                    LOG.error(error, 'retry number %r' % i)
                    if i < 5:
                        time.sleep(i + randint(0, 100) / 1000)
                    else:
                      time.sleep(i/i + randint(0, 100) / 1000)
                        
                else:
                    for obj in all_objects:
                        if obj not in object_whitelist:
                            all_objects_list.append(
                                objects(bucket=obj['bucket'], name=obj['name'])
                                )
                break

        return all_objects_list

    def get_all_bucket_acl(self):
        """Gets the access control lists for all buckets listed via
        _get_all_buckets function"""

        bucket_acl_list = []

        for bucket in self.buckets:
            for i in range(5):
                try:
                    bucket_session = self.storage_session.bucketAccessControls
                    bucket_session = bucket_session(
                        ).list(bucket=bucket).execute()
                    request = bucket_session['items']
                except (socket.timeout, HttpError) as error:
                    i += 1
                    LOG.error(error, 'retry number %r' % i)
                    time.sleep(i + randint(0, 100) / 1000)
                else:
                    for item in request:
                        info = {
                            'id': item['id'],
                            'entity': item['entity'],
                            'role': item['role']
                        }
                        acl_tuple = AllTuple(name=item['bucket'],
                                             type_='Bucket',
                                             info=info
                                            )
                        bucket_acl_list.append(acl_tuple)
                break

        LOG.info('processing %r buckets' % len(bucket_acl_list))
        return bucket_acl_list

    def get_all_objects_acls(self):
        """gets access control lists for all bucket objects and appends them
        to a list"""

        all_acls = []

        for i in range(5):
            for obj in self._get_all_objects():
                try:
                    bucket = obj.bucket
                    object_name = obj.name
                    object_acl = self.storage_session.objectAccessControls(
                        ).list(bucket=bucket,
                               object=object_name).execute()
                except (socket.timeout, HttpError) as error:
                    i += 1
                    if i < 5:
                        time.sleep(i + randint(0, 100) / 1000)
                    else:
                      time.sleep(i/i + randint(0, 100) / 1000)
                    LOG.error(error, 'retry number %r' % i)
                else:
                    object_acl = object_acl['items']

                    for obj_acl in object_acl:
                        info = {
                            'bucket': obj_acl['bucket'],
                            'entity': obj_acl['entity'],
                            'id': obj_acl['id']
                        }

                        acl_tuple = AllTuple(
                            name=obj_acl['object'],
                            type_='Bucket Object',
                            info=info
                        )

                        all_acls.append(acl_tuple)
            break

        LOG.info('processing %r objects' % len(all_acls))
        return all_acls


    def _get_all_firewall_rules(self):
        """gets all firewall rules and appends to rules list"""

        rules_list = []
        all_firewalls = namedtuple('AllFirewalls', ['name'])

        for i in range(5):
            try:
                all_rules = self.compute_session.firewalls().list(
                    project=self.project).execute()
            except (socket.timeout, HttpError) as error:
                i += 1
                LOG.error(error, 'retry number %r' % i)
                time.sleep(i + randint(0, 100) / 1000)
            else:
                for rules in all_rules['items']:
                    rules_list.append(
                        all_firewalls(name=rules['name'])
                    )
            break

        return rules_list

    def get_full_firewall_rules(self):
        """gets full firewall rules"""

        firewall_full_list = []
        firewall_full = namedtuple('FirewallFull', ['info',
                                                    'name',
                                                    'type_'])

        for i in range(5):
            for firewall in self._get_all_firewall_rules():
                try:
                    all_rules = self.compute_session.firewalls
                    all_rules = all_rules(
                        ).get(firewall=firewall.name,
                              project=self.project).execute()
                    protocol = all_rules['allowed'][0]
                    ports = protocol['ports']
                     # If they're open to everyone this will be empty
                except KeyError:
                    ports = 'all'
                    continue
                except (socket.timeout, HttpError) as error:
                    i += 1
                    LOG.error(error, 'retry number %r' % i)
                    time.sleep(i + randint(0, 100) / 1000)
                else:
                    info = {'protocol': protocol['IPProtocol'],
                            'ranges': all_rules['sourceRanges'],
                            'ports': ports
                           }

                    firewall_full_list.append(
                        firewall_full(name=all_rules['name'],
                                      info=info,
                                      type_=all_rules['kind'])
                    )
            break

        LOG.info('processing %r rules' % len(firewall_full_list))
        return firewall_full_list
