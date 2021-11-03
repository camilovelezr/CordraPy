.. CordraPy documentation master file, created by
   sphinx-quickstart on Tue Nov  2 20:03:31 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

CordraPy
====================================

A simple Python library for interacting with the REST
interface of an instance of Cordra.

This is a library to manage digital objects and
access to an instance of Cordra through its REST API.

Typical usage example:

.. code-block:: python

   CordraObject.create("https://localhost:8443",
                      {"myfirst":"object"}, "debug", token=my_token)

.. toctree::
   :maxdepth: 2
   :caption: Contents:


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
