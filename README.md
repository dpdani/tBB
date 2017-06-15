# tBB

[![Travis Status](https://travis-ci.org/dpdani/tBB.svg?branch=master)](https://travis-ci.org/dpdani/tBB)

An open-source Intrusion Detection System written in Python.

![screenshot](/docs/screenshot.png)


## Installation

Please, refer to the installation section of the [User's Manual](http://tbb.readthedocs.io/en/latest/gettingstarted.html).


## Usage

This repo contains the tBB server which is what performs the monitoring.

In order to actually see the results of monitoring, you want to connect to the running server with a front-end.
The only available front-end as of today is [tBB_cli](https://github.com/dpdani/tBB_cli) which uses command line for human interface.

To run the tBB server use the following command from within tBB's installation folder:

``$ sudo ./run 192.168.0.0/24``
or
``$ sudo ./daemon 192.168.0.0/24``
if you wish to run the server as a daemon.


## Configuration

There are many settings you can adjust in tBB using a simple JSON format.
Refer to the [Manual](http://tbb.readthedocs.io/en/latest/config.html) for further details.


## Contributing

Feel free to contribute!

Open an issue, a pull request or take a look at the Projects section to look at what I'm working on right now.

Before contributing, please read the [Contributor Covenant Code of Conduct](https://github.com/dpdani/tBB/blob/master/CODE_OF_CONDUCT.md).
