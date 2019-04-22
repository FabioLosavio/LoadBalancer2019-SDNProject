Topology-Yaml
=============

.. image:: https://img.shields.io/pypi/v/topology-yaml.svg
    :target: https://pypi.python.org/pypi/topology-yaml
    :alt: Latest PyPI version

Opinionated topology file generator and parser.


Requirements
~~~~~~~~~~~~

- Python 2.7

Installation
~~~~~~~~~~~~

>From Source:

::

$ git clone https://github.com/lumina-networks/topology-yaml
$ cd topology-yaml
$ sudo pip install .

>From PyPi

::

$ pip install topology-yaml


Usage
~~~~~

**topology-yaml** will be the command after installation. For example:
::

    $ Usage: topology-yaml [OPTIONS] COMMAND [ARGS]...

    Options:
      --help  Show this message and exit.

    Commands:
      create  Create Topology File
      delete  Delete Topology File
      read    Read Topology File


Documentation
~~~~~~~~~~~~~

To build documentation:

::

$ make documentation

Or

::

$ cd docs
$ make html


Licence
-------

MIT

Authors
-------

`topology-yaml` was written by `Lumina NetDev <oss-dev@luminanetworks.com>`_.


