#!/bin/bash

# http://stackoverflow.com/questions/59895/can-a-bash-script-tell-what-directory-its-stored-in
SCRIPT_DIR="$(cd "$( dirname "$0" )" && pwd)"

SITE_DIR=

err_quit() {
    echo 1>&2 ${1}
    exit 1
}

usage() {
    cat 1>&2 << EOF

Starts uWSGI managed wwwhisper instance for a given site.

   The script accepts a single argument - a path to a site-specific
   directory that was generated with 'add_protected_site.py'.
   Example usage:
      ${0} -d ./sites/https.example.com/
EOF
    exit 1
}

assert_dir_exists() {
    if [[ ! -d "${1}" ]]; then
        err_quit "Directory '${1}' does not exist."
    fi
}

while getopts “hd:” OPTION
do
    case ${OPTION} in
        h)
            usage
            ;;
        d)
            SITE_DIR=${OPTARG}
            ;;
    esac
done

if [[ -z ${SITE_DIR} ]]; then
    usage
    exit 1
fi

if [[ -z ${VENV_DIR} ]]; then
    VIRTUALENV_DIR=${SCRIPT_DIR}/venv
fi

assert_dir_exists ${SITE_DIR}
# Transform site dir to be an absolute path.
SITE_DIR="$(cd "${SITE_DIR}" && pwd)"
# Sanity check.
assert_dir_exists ${SITE_DIR}

source ${VIRTUALENV_DIR}/bin/activate \
    || err_quit "Failed to activate virtualenv in ${VIRTUALENV_DIR}."

exec uwsgi  --socket="${SITE_DIR}/uwsgi.sock"\
 --chdir="${SCRIPT_DIR}/"\
 --module="wwwhisper_service.wsgi:application"\
 --master\
 --vacuum\
 --processes=1\
 --chmod-socket=660\
 --buffer-size=16384\
 --plugins=python\
 --python-path="${SITE_DIR}/django/"\
 --virtualenv="${VIRTUALENV_DIR}"\
    || err_quit "Failed to start uwsgi."
