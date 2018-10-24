[![Build Status](https://travis-ci.org/delvelabs/vane2.svg?branch=master)](https://travis-ci.org/delvelabs/vane2)
[![PyPi](https://badge.fury.io/py/vane2.svg)](https://badge.fury.io/py/vane2)

# Vane 2.0
A WordPress vulnerability scanner

## Installation

From pypy:

```bash
python -m venv .
source bin/activate
pip install vane2

vane --help
```

From source:

```bash
git clone https://github.com/delvelabs/vane2
cd vane2
python -m venv .
source bin/activate
pip install -r requirements.txt

python -m vane --help
```

## Getting started

Doing a standard scan:
```bash
vane scan --url http://example.com/
```

Using a HTTP proxy for the scan (replace http://127.0.0.1:8080 with the proxy URL):
```bash
vane scan --url http://example.com/ --proxy http://127.0.0.1:8080
```

Printing output in JSON format:
```bash
vane scan --url http://example.com/ --output-format json
```

Only check for popular plugins and themes:
```bash
vane scan --url http://example.com/ -p
```

Updating the database:
```bash
vane import-data
```

Printing help message:
```bash
vane --help
```

## Available options

* ``--url`` URL of the target Web site of the scan. Not used for import-data.
* ``--import-path`` Path to the database. By default, the current directory is used.
* ``-p`` Only check for popular plugins and themes. Can be used with ``-v``
* ``-v`` Only check for vulnerable plugins and themes. Can be used with ``-p``
* ``--passive`` Only find plugins and themes with a passive scan.
* ``--proxy`` URL of the HTTP proxy to use for the scan.
* ``--no-ssl-validation`` Do not verify if the certificate of target website is valid.
* ``--ca-cert`` The certification authority certificate to use to validate the SSL certificate of the target.
* ``--auto-update-frequency`` The delay in days between two auto updates of the database. Default is 7.
* ``--no-update`` No data update will be done. Scan will not be performed if no database is found locally.
* ``--output-format`` Format for the scan output ("pretty" or "json"). Default is "pretty".

## Source of the data

See [add the URL to openwebvulndb when it is public] for more details.

## Contributing
Most contributions are welcome. Simply submit a pull request on [GitHub](https://github.com/delvelabs/vane2/).

Instruction for contributors:
* Accept the contributor license agreement.
* Write tests for your code. Untested code will be rejected.

To report a bug or suggest a feature, open an issue.

## License

Copyright 2017- Delve Labs inc.

This software is published under the GNU General Public License, version 2.
