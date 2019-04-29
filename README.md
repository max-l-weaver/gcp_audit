#GCP Audit

Runs checks on GCP buckets and firewalls.
inspired in part by Spotify's gcp_udit tool, only simplified and not in Python 2.7

Pretty simple to use:

```
usage: gcp_audit.py [-h] [-p PROJECT] [-k KEYFILE]

Run checks on GCP for firewall/bucket security issues

optional arguments:
  -h, --help            show this help message and exit
  -p PROJECT, --project PROJECT
                        Specify project you wish to scan
  -k KEYFILE, --keyfile KEYFILE
                        Specify GCP credentials keyfile
  --whitelist WHITELIST
                          whitelists one or more buckets. Whitelist should be in
                          a yaml format. Please see documentation!
```

checks all buckets, bucket objects and firewalls and alerts to slack if there
are any issues.

## Whitelisting

As of time of writing you can whitelist buckets via the whitelist
config file in `./config`.

Format is as follows:

```
project:
  bucket:
    - bucket1
    - bucket2
```

So if you wanted to whitelist the bucket `useless-bucket` in project `infectious-db`
your whitelist file would look like:

```
infectious-db:
  bucket:
    - useless-bucket

```

And if you wanted to whitelist `useless-object` in the same project:

```
infectious-db:
  bucket:
    - useless-bucket
  object:
    - useless-object
```

The above would miss out any object called `useless-object` and any bucket called
`useless-bucket`

## Command Line Examples:

Basic Usage:

```
./gcp_audit -k /path/to/keyfile.json -p project-name

```

With Whitelist:

```
./gcp_audit -k /path/to/keyfile.json -p project-name --whitelist /path/to/file.yaml

```

If the bucket doesn't exist in a particular project it ignores it.

## Setting up

```
git clone git@bitbucket.org:infectious/gcp_audit.git
cd gcp_audit
python3.6 -m venv venv
. /venv/bin/activate
pip install -r requirements.txt
pip install -r dev_requirements.txt

```
