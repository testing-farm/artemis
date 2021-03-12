Changelog
=========

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.0.0/>`_.


2019-09-13
----------

Fixed
~~~~~

- pipeline-install-ancestors: handle no entries and entry state==0 (Martin Kluson)
- test-schedule-runner-restraint: add missing output.directory to artifact path (mprchlik)

Added
~~~~~

- openstack-job: add option `pipeline-install-ancestors-options` (Martin Kluson)


2019-09-06
----------

Fixed
~~~~~

- Missing coldstore module caused problems with artifact path (Martin Kluson)
- covscan: use log_dict instead of log_blob to log structure (Milos Prchlik)
- koji_fedora: document wait as 'int', not 'bool' (Ondrej Ptak)

Added
~~~~~

- CI: profile Ansible playbooks (mprchlik)
- test_schedule_runner_restraint: add --ignore-avc option (Anna Khaitovich)

Changed
~~~~~~~

- Removing setuptools-scm as it is not used at all, and complicates things (Milos Prchlik)
- Update/fix tests to actually work with Python3-capable gluetool (Milos Prchlik)
- Install citool directly from its repository (Milos Prchlik)
- openstack: raise exception when resource is in ERROR state (mprchlik)


2019-08-23
----------

Added
~~~~~

- koji_fedora: Add check for canceled and failed tasks (jhavlin@redhat.com)
- openstack-job: add `test-schedule-sti-options` option (Martin Kluson)
- sti scheduler and runner: pass custum variables to playbook (Martin Kluson)
- Added log setup, log propagation, and return value propagation (jhavlin@redhat.com)
- Provide installation logs location aside from their local path (mprchlik)

Changed
~~~~~~~

- use newer psycopg2 version (jhavlin@redhat.com)
- pipeline-install-ancestors: remove playbook call (Martin Kluson)

Fixed
~~~~~

- restraint: fix deprecated function warning (jhavlin@redhat.com)
- copr: builder-live.log was moved to builder-live.log.gz (Martin Kluson)
- Check empty guest_setup_output (jhavlin@redhat.com)
- openstack: init logger early (jhavlin@redhat.com)


2019-08-13
----------

Changed
~~~~~~~

- [ansible] Use guest.username as login for ansible connection (Jakub Haruda)
- [covscan] Load covscan URL from config (Jakub Haruda)

Fixed
~~~~~

- [test-schedule-runner-restraint] fix broken check for snapshot support (mprchlik)


2019-08-07
----------

Added
~~~~~

- [install-mbs-build-execute] add odcs options (jhavlin@redhat.com)

Changed
~~~~~~~

- Use LoggerMixin instead of logger.connect (mprchlik)
- [jenkins] refactored jenkins_rest to use requests (mprchlik)
- [jenkins] small tweaks of jenkins_rest to accept other status codes (mprchlik)
- [jenkins] use jenkins_rest helper for invoke, instead of yet-another "http request" (mprchlik)
- [jenkins] "lazy" wrappers over jenkinsapi job and build (mprchlik)
- [jenkins] add retry for REST API requests (Anna Khaitovich)
- [rpminspect] enable repos in moduleinfo (Evgeny Fedin)
- [rpminspect] polishing (Evgeny Fedin)


2019-07-26
----------

Added
~~~~~

- Wrapping more points in brew-ts_restraint-openstack pipeline with actions (mprchlik)

Changed
~~~~~~~

- [notify-email] Treat x-headers as templates (Jakub Haruda)

Fixed
~~~~~

copr: fix JSONDecodeError (Evgeny Fedin)
mbs: fix nvr for scratch builds (Evgeny Fedin)
pipeline-install-ancestors: fix handling of ansible playbooks (Martin Kluson)
wow: fix typo (Martin Kluson)
test-scheduler: require provisioner_capabilities() (omosnace)
test_scheduler_sti: Get rid of NoTestAvailableError (Robin Hack)
rpminspect-job: new job module for rpminspect (Evgeny Fedin)


2019-06-28
----------

Added
~~~~~

- [ansible] focus on a single guest (mprchlik)
- [guest-setup] focus on a single guest (mprchlik)
- [mbs] wrap API calls with Actions (mprchlik)
- [pipeline-install-koji-build] install koji build in pipeline (Miroslav Vadkerti)
- [rpminspect] serialize results to xunit (Anna Khaitovich)
- [test-schedule-runner] wrap few interesting points with Actions (mprchlik)

Changed
~~~~~~~

- Update wait call sites to use Result (mprchlik)
- [test-batch-planner] set artifact_id (Miroslav Vadkerti)

Fixed
~~~~~

- [beaker-jobwatch]: Better exctracting of matrix url (Evgeny Fedin)
- [build-dependencies] always use current_task_ids (Miroslav Vadkerti)
- [test-schedule-runner-sti]: pass guest to run_playbook not wrapped by a list (Milos Prchlik)
- [wow] add handling of invalid archs (Miroslav Vadkerti)


2019-06-14
----------

Added
~~~~~

- [ansible] add logging of ansible output (Miroslav Vadkerti)
- [guess-environment] find out what environments we should use (mprchlik)
- [jenkins] fetch build params via direct endpoint (Milos Prchlik)
- [wow] move --environment to a configuration (mprchlik)
- [pes] Provides access to Package Evolution Sevice (PES) (Martin Kluson)
- [pipeline-state-reporter] use map to enhance "overall result" decisions (mprchlik)
- [rpminspect] new module rpminspect (Evgeny Fedin)
- [wow] let configuration modify "upstream" options (mprchlik)
- [wow-artifact-installation-options-koji-build] order installation tasks (mprchlik)


Fixed
~~~~~

- [beaker] fix wrong use of self._module in TaskAggregator (mprchlik)
- [beaker] retry when fetching tasks' journal (mprchlik)
- [restraint] change index.html permissions only when it really exists (mprchlik)
- [sti] fix git and workdir permissions to allow 3rd party to read our files (mprchlik)
- [test-schedule-runner-sti] fix inventory file permissions to make it readable by other (mprchlik)

Changed
~~~~~~~

- [git] return relative path instead of absolute (mprchlik)
- [test-schedule-runner] a state machine \o/ (mprchlik)


2019-05-03
----------

Added
~~~~~

- [pagure] support dry run level ``DRY``
- [rules-engine] ANY & ALL helper functions
- [wow] add WowCommand to the context 

Changed
~~~~~~~

- [mbs] get tags from brew, target from platform stream
- [semaphore] use `eval_context` correctly

Fixed
~~~~~

- [covscan] fix minor issues with xunit export
- [test-batch-planner] cleaner handling of stages and options
- [test-scheduler-beaker-xml] if there is no distro_name from bkr, use distro_family



2019-04-25
----------

Added
~~~~~

- [coldstore] artifacts location rendering

Changed
~~~~~~~

- instead of plain artifact ID, new "dispatch ID" is used when dispatching jobs to workaround OSBS/Brew integration flaws
- unified code behind Copr and MBS installation
- unify ``srpm_names`` and ``srpm_urls`` properties of koji and copr modules
- [covscan] do not send no baselibe error to Sentry
- [guest-setup] always autodetect ansible_python_intepreter with playbooks
- [wow] moving --decision option to configuration
- [wow] use --dry-run instead of --dry
- [wow] overwrite options from wow-options-map with command line options

Fixed
~~~~~

- [beaker] remove superfluous quotes around reservesys task
- [copr] use non-unicode version of Copr API response
- [covscan] fix for RHEL-6 failures
- [notes] avoid adding duplicit notes


2019-04-10
----------

Added
~~~~~

- [dist-git] add has_tests check
- [test-batch-planner] ci.fmf support

Changed
~~~~~~~

- [install-mbs-execute-execute] reset module, optionally install profile
- [koji] do not report to sentry failures of retries
- [koji] do not report no tasks to Sentry
- [pagure] errors during build report as a test fail
- [test-batch-planner] make use of new has_sti_tests check

Fixed
~~~~~

- [koji] do not use destination tag for latest released
- [koji] do not detect git commit issuer if built from source rpm
- [koji] fix name/tag option
- [restraint] rough edges of index.html permissions and service start
- [task-dispatcher] enhance test type and category obtaining


2019-04-02
----------

Added
~~~~~

- [covscan] export result to xUnit
- [dist-git] "has CI config" check
- [install-copr-build] running curl in verbose mode
- [koji-fedora] new task methods, ``compare_nvr`` and ``is_newer_than_latest``

Changed
~~~~~~~

- [pagure-srpm] using ``uid`` instead of ``pr_id`` when constructing SRPM name
- [sti] refactored to use test-scheduler workflow
- [test-scheduler] keep separate list of constraitn arches instead of usign valid arches list for constraints

Fixed
~~~~~

- [mbs] NVR regular expression fixed


2019-03-01
----------

Added
~~~~~

- [install-mbs-build-execute] new option, ``--use-devel-module``, to include ``foo-devel`` in the module repository as well
- [test-batch-planner] support recipients syntax to be a YAML list of strings
- [testing-thread-id] export thread ID over eval context


2019-02-26
----------

Added
~~~~~

- [openstack] uses template for instance names

Changed
~~~~~~~

- [guess-environment] new module, merge of guess-beaker-distro, guess-image and guess-product


2019-02-19
----------

Added
~~~~~

- [beaker-provisioner] utility commands for cache control
- [install-koji-docker-build] use relocated tasks
- [jenkins] support for dry-run mode
- [openstack] support for v3 authentication API
- [openstack-job] new option, ``--dist-git``
- [rules-engine] support for including variables

Fixed
~~~~~

- [install-koji-docker-build] force compose when constructing installation recipe


2019-02-12
----------

Added
~~~~~

- [dist-git] add ``force`` method
- [pipeline-state-reporter] uses instruction mapping for content of the ``run`` field
- [rules-engine] test coverage & type annotations
- [rules-engine] allow ``... if ... else ...`` expressions
- [test-batch-planner] support for multiple ``--config`` files

Fixed
~~~~~

- [build-dependencies] fix Copr variant
- [install-koji-build] require shared function ``beaker_job_xml``
- [memcached] fix rare conflict when fetching cache dump
- [sti] fix spurious traceback with failed tests


2019-02-06
----------

Added
~~~~~

- [beaker-provisioner] when asked, show state of cached guests formatted as a table
- [coldstore] new module - propagates and logs coldstore location of artifacts
- [test-scheduler] after each change, show progress of provisioning formatted as a table

Changed
~~~~~~~

- test schedule entry code moved into common libraries
- [guest-setup] try to detect Python interpreter for Ansible when not told explicitly
- [install-copr-build] refactored to use direct commands instead of Ansible playbook
- [memcached] dump cache with ``DEBUG`` severity, not ``INFO``
- [restraint] use template when emitting the final location of artifacts
- [smtp] ``Sender`` and ``Reply-To`` checks updated to emit warnings in a later stage, giving ``smtp`` chance to set them
- [test-schedule-runner-restraint] use template when emitting the final location of artifacts


2019-01-23
----------

Added
~~~~~

- [guess-openstack-image] supports variables in the mapping
- [guess-product] supports variables in the mapping
- [install-mbs-build-execute] new module, using direct commands instead of Ansible playbook to install MBS builds

Fixed
~~~~~

- [wow] when no distro/arch/variant is possible, instead of failing, emit a warning and leave the decision to the caller


2019-01-17
----------

Changed
~~~~~~~

- [jenkins] the module does not try to fetch Jenkins build parameters, in the current settings it's consuming too many resources


2019-01-15
----------

Added
~~~~~

- [dashboard] new module - handles and displays Dashboard URL in the log
- [jenkins] new option ``--jenkins-api-timeout`` for controlling ``jenkinsapi`` request timeout length

Changed
~~~~~~~

- artifact providers no longer check whether the artifact has any testable artifact, this is now left to the consumers like ``test-scheduler``
- [jenkins] bumped version of ``jenkinsapi`` to 0.3.8 - this should fix problem with fetching Jenkins build parameters for some build


2019-01-09
----------

Fixed
~~~~~

- [beaker] in exported results, preserve the order of the tasks
- [test-schedule-runner-restraint] in exported results, preserve the order of the tasks
- [static-guest] testing environment replaced with the one provided by a library, fixing a ``distro`` vs ``compose`` issue

Added
~~~~~

- test schedule entries' and guests' environment is now propagated into exported results
- type annotations were added to common libraries
- [ansible] type annotations were added
- [install-copr-build] detect Python interpreter when calling Ansible
- [jenkins] new shared function, ``get_jenkins_build``, providing Jenkins build API
- [msb] it is possible to initialize build using new options, ``--nsvc`` and ``--nvr``
- [notify-email] list of recipients is now available in templates
- [pipeline-state-reporter] include serialized pipeline and Jenkins build parameters in the messages
- [test-scheduler] log arch compatibility decisions

Changed
~~~~~~~

- [ansible] version of Ansible bumped to 2.7.5
- [beaker] obsolete ``run_command`` was replaced by ``Command.run``
- [mbs] extract architectures from a ``modulemd`` property of build metadata

Removed
~~~~~~~

- [test-scheduler] option ``--unsupported-arches`` removed


2019-01-03
----------

Fixed
~~~~~

- [test-scheduler] if the only valid arch is ``noarch``, use arches supported by the provisioner only


2018-12-18
----------

Added
~~~~~

- [wow] add-note mapping command
- [sut_installation_fail] new module for sharing error class
- [notes] add level name property for levels of logging
- [libs] new _UniqObject for better logging, <ANY> object


Changed
~~~~~~~

- [openstack] fix weird IMAGE name value "<Image:...>"
- [odcs] ask for repo including deps
- [install-mbs-build] improve ansible output processing (error detection)
- [testing_environment] Testing environment constraints, include into beaker and test_scheduler


2018-12-11
----------

Added
~~~~~

- [guess-beaker-distro] enable use of variables in distro pattern map

Changed
~~~~~~~

- [koji-fedora] retry for fetching commit web page
- [koji-fedora] allow_releases can be None


2018-12-04
----------

Added
~~~~~

- [notify-recipients] new option, ``--recipients``, adds generic recipients, not tied to any result type

Changed
~~~~~~~

- [ansible] being more verbose when Ansible fails
- [testing-thread] using full-blown template for thread ID generation


2018-11-30
----------

Added
~~~~~

- [brew] display link to Brew website, showing details of the artifact
- [copr] display link to Copr website, showing details of the artifact
- [koji] display link to Koji website, showing details of the artifact
- [test-batch-planner] supports STI

Changed
~~~~~~~

- [mbs] update the displayed link to MBS website to match other artifact modules


2018-11-27
----------

Added
~~~~~

- [notes] new module - add various notes and warning to inform users about unexpected issues
- [notify-email] support for adding custom X-* headers
- [smtp] new module - SMTP support (sending e-mails) moved to a separate module


Fixed
~~~~~

- [beah-xunit] status and result checks must be case-insensitive
- [install-mbs-build] request repository with architectures matching given set of guests
- [mysql] fix source of connector, now using one from PyPI
- [sti] fix packaging issue


2018-11-20
----------

Changed
~~~~~~~

- ``distro`` property of testing environment renamed to ``compose`` to better reflect its content

Added
~~~~~

- [dist-git] new module - provides access to a dist-git repository of a component
- [notify-email] support ``do`` keyword in templates ("expression statement" extension)
- [static-guest] new module - wrap static guests, without any provisioning
- [sti] new module - run tests as specified by STI
- [test-scheduler] tweaked logging when provisioning and setting up guests

Fixed
~~~~~

- [build-dependencies] when primary component is listed among companions, remove it to avoid build collisions
- when running tests, ``test_`` pattern was skipped, which ignored multiple genuine modules


2018-11-13
----------

Changed
~~~~~~~

- [ansible] JSON output is the default now
- [ansible] ``run_playbook`` accepts newly also a list of playbooks
- [test-scheduler] renamed from ``restraint-scheduler``, not tied to ``restraint`` anymore
- [test-scheduler-beaker-xml] test scheduler plugin producing Restraint/Beaker XML
- [test-scheduler-runner-restraint] renamed from ``restraint-runner``
- [test-schedule-runner-restraint] report watchdog triggerings to use as a failed testing, not a crash


Added
~~~~~

- [ansible] new shared function ``detect_ansible_interpreter`` to auto-detect suitable interpreters for Ansible
- [beaker-provisioner] support direct provisioning via ``--provision``
- [beaker-provisioner] start another ``restraintd`` instance on specified port (``--restraintd-port`` option)
- [copr] handle and report failures in artifact installation as a specific exception
- [mbs] handle and report failures in artifact installation as a specific exception
- [restraint] allow change of default port on which the module expects running ``restraintd`` (``--restraintd-port`` option)
- [rules-engine] new ``filter``-like shared function, ``evaluate_filter``


Fixed
~~~~~

- [beaker] require ``evaluate_instructions`` shared function before checking degraded services
- [beaker-provisioner] check for ``extendtesttime.sh`` script before starting extend refresh loop to avoid race condition
- [docker-provisioner] updated to the latest "standards" of usage and testing environment handling
- [openstack] require ``evaluate_instructions`` shared function before checking degraded services

Removed
~~~~~~~

- [ansible] "smart" picking of failed tasks from the log was removed, detailed exception messages are no longer provided


2018-10-30
----------

Changed
~~~~~~~

- [beaker-provisioner] use PHASE to inform wow that we're provisioning guests

Added
~~~~~

- [ansible] parse failues from YAML Ansible output
- [ansible] ``cwd`` parameter to control Ansible's working directory
- [events] new module - let modules trigger and subscribe to events
- [execute-command] export functionality as a shared function
- [openstack] extract metadata and compose name from image
- [openstack] export list of guests via eval context
- [publisher-umb-bus] on error, without a link, create dummy error description

Fixed
~~~~~

- [composetest] fix handling default configuration


2018-10-23
----------

Changed
~~~~~~~

- [mbs] use full module NSVC to install it, instead of NSV
- [publisher-umb-bus] retry on *all* errors, not just on auth* related ones

Added
~~~~~

- [ansible] let user specify the inventory file instead of generating the default inventory based on given guests
- [beaker-provisioner] keep track of the age of guests in the cache
- [mbs] provide common artifact properties like ``nvr``, ``nsvc``, or ``component``
- [pipeline-state-reporter] state version of the generated message

Fixed
~~~~~

- [ansible] to process ``--ansible-playbook-options``, use gluetool's ``normalize_multistring_option``


2018-10-15
----------

Changed
~~~~~~~

- [koji-fedora] when build is available, extract source from it, otherwise task's ``request`` field is used
- [restraint-scheduler] guest provisioning and setup are completely paralelized
- [restraint-scheduler] check and report progress of provisioning/guest setup as soon as possible
- [rules-engine] context is now logged using ``verbose`` severity
- [wow] "No test available" error will not be reported to Sentry anymore

Added
~~~~~

- Optional type check job in Gitlab CI
- [beaker-jobwatch] allow caller disable live streaming of ``beaker-jobwatch`` output
- [beaker-provisioner] when provisioning, log the requested testing environment
- [beaker-provisioner] support the real provisioning of guests ("dynamic" guests, as oposed to "static" ones already supported)
- [bkr] access to job results
- [bkr] matrix URL parser
- [build-dependencies] support for companions from Copr
- [mbs] new module - experimental support for Module Building Service (future ``redhat-module`` artifacts)
- [memcached] new module - access to Memcached cache API
- [openstack] when provisioning, log the requested testing environment
- [openstack] when guests are provisioned, log them with INFO level to display their properties, namely their IP addresses
- [pipeline-state-reporter] publish value of ``--label`` in eval context
- [restraint-scheduler] guest provisioning and setup are completely paralelized
- [restraint-scheduler] check and report progress of provisioning/guest setup as soon as possible
- [restraint-scheduler] "No testable artifacts error" gained access to supported arches, providing more descriptive e-mail notification
- [rules-engine] allow creation of dictionaries in rules
- [wow] user of ``beaker_job_xml`` can now force use of a specific distro

Removed
~~~~~~~

- [beaker-jobwatch] don't log the last line of ``beaker-jobwatch`` output, module has its own messages
- [test-batch-planner] disable warning on match not being equal to the component

Fixed
~~~~~

- [beaker-provisioner] avoid using ``message`` attribute of an exception, it has been deprecated for ``BaseException`` and its children
- [brew] don't raise error when asked for eval context before ``execute`` gets called
- [build-on-commit] better handling of situation when the remote branch has been removed from the repository
- [copr] better check for possible missing build task info in Copr API
- [copr] adds NVR check after artifact installation
- [copr] don't raise error when asked for eval context before ``execute`` gets called
- [mbs] don't raise error when asked for eval context before ``execute`` gets called
- [restraint-scheduler] apply ``decode()`` on distro name and architecture when extracting them from recipe XML
- [restraint-scheduler] "No testable artifacts error" gained access to supported arches, providing more descriptive e-mail notification


2018-09-19
----------

Changed
~~~~~~~

- Versions of several required Python packages were bumped to match the most recent Gluetool release
- [copr] refactored internal use of Copr API
- [covscan] refactored to be less tied to Brew, allowing the use with other artifact providers like Copr
- [restraint-scheduler] flow of guest provisioning and setup process has been changed to setup all provisioned guests - for all jobs and recipes - in parallel


Added
~~~~~

- Re-enabled Ansible Tower integration
- [ansible] it is now possible to provide additional options to be given to Ansible when running playbooks (``--ansible-playbook-options``)
- [ansible] custom exception wrapping Ansible errors
- [beaker-job-xml] new module - allow the use of static XML describing Beaker jobs
- [bkr] new module - wrapper of (low-level) Beaker API and commands (e.g. ``bkr job-submit``)
- [install-koji-docker-image] export PHASE=artifact-installation variable to Beaker XML provider
- [notify-email] when formatting an error e-mail, body header and footer now have access to a Failure instance
- [notify-email] SMTP port is now configurable (``--smtp-port``)


Fixed
~~~~~

- [beaker-provisioner] when provisioning guests, honor testing environment architecture specified by a requestor
- [copr] even incomplete information about the task can be now used in error handling process
- [openstack] when creating an instance, multiple images of the same name are now handled correctly
- [openstack] fixed removal of inactive images
- [pipeline-state-reporter] fixed processing of ``--dont-report-running`` option
- [test-batch-planner] safer handling of regular expressions made of a component name when searching component tasks
