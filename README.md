# DNAC Config Export Tool

<p align="center">
<a href="https://wwwin-github.cisco.com/pages/AIDE/User-Guide/"><img alt="AIDE: essentials" src="./docs/images/aide-essentials.svg"></a>
<a href="https://cxtools.cisco.com/cxestore/#/toolDetail/81262"><img alt="CX eStore Tool ID" src="https://img.shields.io/badge/TOOL%20ID-81262-blue"></a>

</p>

This tool accesses a running DNAC server and collects Clear-text-configs (Running/Startup) for devices managed by DNAC.
To access the server, use the REST API that comes standard with DNAC.
Download the collected Config as an encrypted ZIP file and store it in the same directory as the py file.

This tool can be used on a server or laptop if it meet Prerequisites.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.
See deployment section below for notes on how to deploy the project on a live system.

### Prerequisites

You need to have a server that meets the following requirements.

* It have accessible to target DNAC server.
* It have Python 3.7.x or later and installed following libraries:
  - requests
  - aide (and other libraries for aide to work properly)

See here for how to install the aide library: [AIDE-PYTHON-AGENT](https://wwwin-github.cisco.com/AIDE/aide-python-agent)

### Installing

1. Get latest files from repository.
2. Put files to specific server.
3. Update 'dnac/config.json' for access the correct DNAC server.
* hostname
* username
* password

4. Update 'dnac/dnacdriver.py' to identity PID.
* `aide.submit_statistics( pid=951227,  <<<< here`

## Deployment

Not need.

## Usage

1. Execute following command. (Commands may differ depending on the environment)
  * `python3 ./dnac/dnacdriver.py --get-device-config`

2. Get the encrypted ZIP file located in the 'dnac' directory

## Contributing

If there is a process for others to contribute to this tool, detail it in a CONTRIBUTING.rst file and reference it here using syntax like:

[Contribution guidelines for this project](./.github/CONTRIBUTING.rst)

## Authors

## License

This project is covered under the terms described in [LICENSE](./LICENSE)

## Acknowledgments

- Hat tip to anyone whose code was used
- Inspiration
- etc
