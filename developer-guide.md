# Developer: Setup the environment
-----------------------------------------------------

## Requirements
1. [Snort 2.x](https://snort.org)
1. [Python3](https://python.org)

## Installation
1. Install snort 2.x
1. Install python3 and virtualenv
1. Clone this project
1. Create a virtual environment
    `virtualenv -p python3 venv`
1. Download Snort Rules
    https://snort.org/download
1. Extract and then copy the rule into /etc/snort
1. Modify snort.conf
    1. Change HOME_NET value into your local subnet
    1. Change this variables with the following value
        ```
        var RULE_PATH rules
        var SO_RULE_PATH so_rules
        var PREPROC_RULE_PATH preproc_rules
        ```

## How to Run
# TODO: 
