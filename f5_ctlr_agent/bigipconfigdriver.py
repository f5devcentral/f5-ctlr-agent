#!/usr/bin/env python

# Copyright (c) 2018-2021 F5 Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import argparse
import fcntl
import hashlib
import json
import logging
import os
import os.path
import signal
import socket
import sys
import threading
import time
import traceback
import copy
import pyinotify

from urllib.parse import urlparse
from f5_cccl.api import F5CloudServiceManager
from f5_cccl.exceptions import F5CcclError
from f5_cccl.utils.mgmt import mgmt_root
from f5_cccl.utils.profile import (delete_unused_ssl_profiles,
                                   create_client_ssl_profile,
                                   create_server_ssl_profile)

from f5.bigip import ManagementRoot

log = logging.getLogger(__name__)
console = logging.StreamHandler()
console.setFormatter(
    logging.Formatter("[%(asctime)s %(name)s %(levelname)s] %(message)s"))
root_logger = logging.getLogger()
root_logger.addHandler(console)


class ResponseStatusFilter(logging.Filter):
    def filter(self, record):
        return not record.getMessage().startswith("RESPONSE::STATUS")


class CertFilter(logging.Filter):
    def filter(self, record):
        return "CERTIFICATE" not in record.getMessage()


class KeyFilter(logging.Filter):
    def filter(self, record):
        return "PRIVATE KEY" not in record.getMessage()


root_logger.addFilter(ResponseStatusFilter())
root_logger.addFilter(CertFilter())
root_logger.addFilter(KeyFilter())


DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_VERIFY_INTERVAL = 30.0
NET_SCHEMA_NAME = 'cccl-net-api-schema.yml'


class CloudServiceManager():
    """CloudServiceManager class.

    Applies a configuration to a BigIP

    Args:
        bigip: ManagementRoot object
        partition: BIG-IP partition to manage
    """

    def __init__(self, bigip, partition, user_agent=None, prefix=None,
                 schema_path=None, gtm=False):
        """Initialize the CloudServiceManager object."""
        self._mgmt_root = bigip
        self._schema = schema_path
        self._is_gtm = gtm
        if gtm:
            self._gtm = GTMManager(
                bigip,
                partition,
                user_agent=user_agent)
            self._cccl = None
        else:
            self._cccl = F5CloudServiceManager(
                bigip,
                partition,
                user_agent=user_agent,
                prefix=prefix,
                schema_path=schema_path)
            self._gtm = None

    def is_gtm(self):
        """ Return is gtm config"""
        return self._is_gtm

    def mgmt_root(self):
        """ Return the BIG-IP ManagementRoot object"""
        return self._mgmt_root

    def get_partition(self):
        """ Return the managed partition."""
        return self._cccl.get_partition()

    def get_schema_type(self):
        """Return 'ltm' or 'net', based on schema type."""
        if self._schema is None:
            return 'ltm'
        elif 'net' in self._schema:
            return 'net'

    def _apply_ltm_config(self, config):
        """Apply the ltm configuration to the BIG-IP.

        Args:
            config: BIG-IP config dict
        """
        return self._cccl.apply_ltm_config(config)

    def _apply_net_config(self, config):
        """Apply the net configuration to the BIG-IP."""
        return self._cccl.apply_net_config(config)

    def get_proxy(self):
        """Called from 'CCCL' delete_unused_ssl_profiles"""
        return self._cccl.get_proxy()


class IntervalTimerError(Exception):
    def __init__(self, msg):
        Exception.__init__(self, msg)


class IntervalTimer(object):
    def __init__(self, interval, cb):
        float(interval)
        if 0 >= interval:
            raise IntervalTimerError("interval must be greater than 0")

        if not cb or not callable(cb):
            raise IntervalTimerError("cb must be callable object")

        self._cb = cb
        self._interval = interval
        self._execution_time = 0.0
        self._running = False
        self._timer = None
        self._lock = threading.RLock()

    def _set_execution_time(self, start_time, stop_time):
        if stop_time >= start_time:
            self._execution_time = stop_time - start_time
        else:
            self._execution_time = 0.0

    def _adjust_interval(self):
        adjusted_interval = self._interval - self._execution_time
        if adjusted_interval < 0.0:
            adjusted_interval = 0.0
        self._execution_time = 0.0
        return adjusted_interval

    def _run(self):
        start_time = time.process_time()
        try:
            self._cb()
        except Exception as e:
            log.exception(f'Unexpected error: {str(e)}')
        finally:
            with self._lock:
                stop_time = time.process_time()
                self._set_execution_time(start_time, stop_time)
                if self._running:
                    self.start()

    def is_running(self):
        return self._running

    def start(self):
        with self._lock:
            if self._running:
                self.stop()
            self._timer = threading.Timer(self._adjust_interval(), self._run)
            self._timer.daemon = True
            self._timer.start()
            self._running = True

    def stop(self):
        with self._lock:
            if self._running:
                self._timer.cancel()
                self._timer = None
                self._running = False


class ConfigError(Exception):
    def __init__(self, msg):
        Exception.__init__(self, msg)


def create_ltm_config(partition, config):
    """Extract a BIG-IP configuration from the LTM configuration."""
    ltm = {}
    if 'resources' in config and partition in config['resources']:
        ltm = config['resources'][partition]
    return ltm


def get_gtm_config(config):
    """Extract a BIG-IP configuration from the GTM configuration."""
    gtm = {}
    if 'gtm' in config:
        gtm = config['gtm']
    return gtm


def create_network_config(config):
    """Extract a BIG-IP Network configuration from the network config."""
    net = {}
    if ('static-routes' in config and 'routes' in config['static-routes']
            and config['static-routes']['routes'] is not None):
        net['routes'] = config['static-routes']['routes']
        if 'cis-identifier' in config['static-routes'] and config['static-routes']['cis-identifier']:
            net['cis-identifier'] = config['static-routes']['cis-identifier']
    if 'vxlan-fdb' in config:
        net['userFdbTunnels'] = [config['vxlan-fdb']]
    if not _is_arp_disabled(config) and ('vxlan-arp' in config and 'arps' in config['vxlan-arp']
            and config['vxlan-arp']['arps'] is not None):
        net['arps'] = config['vxlan-arp']['arps']
    else:
        log.debug("NET Config: %s", json.dumps(net))
    return net


def _create_custom_profiles(mgmt, partition, custom_profiles):
    incomplete = 0
    for profile in custom_profiles:
        caFile = profile.get('caFile', '')
        if profile['context'] == 'serverside' and caFile == "self":
            incomplete += create_server_ssl_profile(mgmt, partition, profile)

    for profile in custom_profiles:
        if profile['context'] == 'clientside':
            incomplete += create_client_ssl_profile(mgmt, partition, profile)
        elif profile['context'] == 'serverside':
            caFile = profile.get('caFile', '')
            if caFile != "self":
                incomplete += create_server_ssl_profile(
                    mgmt, partition, profile)
        else:
            log.error(
                "Only client or server custom profiles are supported.")
    return incomplete


def _delete_unused_ssl_profiles(mgr, partition, config):
    return delete_unused_ssl_profiles(mgr, partition, config)


class ConfigHandler():
    def __init__(self, config_file, managers, verify_interval):
        self._config_file = config_file
        self._managers = managers

        self._condition = threading.Condition()
        self._thread = threading.Thread(target=self._do_reset)
        self._pending_reset = False
        self._stop = False
        self._backoff_time = 1
        self._backoff_timer = None
        self._max_backoff_time = 128

        self._verify_interval = verify_interval
        self._interval = IntervalTimer(self._verify_interval,
                                       self.notify_reset)
        self._thread.start()

    def stop(self):
        self._condition.acquire()
        self._stop = True
        self._condition.notify()
        self._condition.release()
        if self._backoff_timer is not None:
            self.cleanup_backoff()

    def notify_reset(self):
        self._condition.acquire()
        self._pending_reset = True
        self._condition.notify()
        self._condition.release()

    def _do_reset(self):
        log.debug('config handler thread start')

        with self._condition:
            while True:
                self._condition.acquire()
                if not self._pending_reset and not self._stop:
                    self._condition.wait()
                log.debug('config handler woken for reset')

                self._pending_reset = False
                self._condition.release()

                if self._stop:
                    log.info('stopping config handler')
                    if self._backoff_timer is not None:
                        self.cleanup_backoff()
                    break

                start_time = time.time()

                incomplete = 0
                gtmIncomplete = 0

                try:
                    # PERF FIX #5: Parse config file ONCE instead of twice
                    config = _parse_config(self._config_file)

                    if not _is_ltm_disabled(config) and 'resources' not in config:
                        continue

                    if not _is_arp_disabled(config) and ('vxlan-arp' not in config or 'vxlan-fdb' not in config):
                        continue

                    if _is_static_routing_enabled(config) and 'static-routes' not in config:
                        continue

                    if _is_cis_secondary(config) and _is_primary_cluster_status_up(config):
                        continue

                    if _is_cis_in_arbitrator_mode(config) and not _is_leader(config):
                        log.debug("CIS in arbitrator mode and not the leader, skipping cccl config push")
                        continue

                    incomplete = self._update_cccl(config)

                except ValueError:
                    formatted_lines = traceback.format_exc().splitlines()
                    last_line = formatted_lines[-1]
                    log.error('Failed to process the config file {} ({})'
                              .format(self._config_file, last_line))
                    incomplete = 1
                except Exception as e:
                    log.exception(f'Unexpected error: {str(e)}')
                    incomplete = 1

                # PERF FIX #5: Reuse the same parsed config for GTM
                try:
                    gtmIncomplete = self._update_gtm(config)
                except ValueError:
                    gtmIncomplete += 1
                    formatted_lines = traceback.format_exc().splitlines()
                    last_line = formatted_lines[-1]
                    log.error('Failed to process the config file {} ({})'
                              .format(self._config_file, last_line))
                except Exception as e:
                    log.exception(f'Unexpected error: {str(e)}')
                    gtmIncomplete = 1

                if incomplete | gtmIncomplete:
                    self.handle_backoff()
                else:
                    if (self._interval and self._interval.is_running()
                            is False):
                        self._interval.start()
                    self._backoff_time = 1
                    if self._backoff_timer is not None:
                        self.cleanup_backoff()

                perf_enable = os.environ.get('SCALE_PERF_ENABLE')
                if perf_enable:  # pragma: no cover
                    test_data = {}
                    app_count = 0
                    backend_count = 0
                    for service in config['resources']['test'][
                            'virtualServers']:
                        app_count += 1
                        backends = 0
                        for pool in config['resources']['test']['pools']:
                            if service['name'] in pool['name']:
                                backends = len(pool['members'])
                                break
                        test_data[service['name']] = backends
                        backend_count += backends
                    test_data['Total_Services'] = app_count
                    test_data['Total_Backends'] = backend_count
                    test_data['Time'] = time.time()
                    json_data = json.dumps(test_data)
                    log.info('SCALE_PERF: Test data: %s',
                             json_data)

                log.debug('updating tasks finished, took %s seconds',
                          time.time() - start_time)

        if self._interval:
            self._interval.stop()

    def _update_gtm(self, config):
        gtmIncomplete = 0
        for mgr in self._managers:
            if mgr.is_gtm():
                oldGtmConfig = mgr._gtm.get_gtm_config()
                partition = "Common"
                try:
                    # RETRY FIX: Check for pending cleanup BEFORE isConfigSame check
                    # This allows cleanup retry even when config hasn't changed
                    if mgr._gtm._pending_cleanup is not None:
                        log.info("GTM: Retrying pending cleanup from previous failed operation")
                        gtm = mgr._gtm.mgmt_root().tm.gtm
                        mgr._gtm.retry_pending_cleanup(gtm)
                        # If retry succeeded, pending_cleanup is cleared in retry method
                        # If retry failed, it will raise F5CcclError again
                    
                    allConfig = get_gtm_config(config)
                    if bool(allConfig):
                        newGtmConfig = allConfig["config"]
                        self._deleted_tenants = allConfig["deletedTenants"]
                        mgr._gtm.pre_process_gtm(newGtmConfig)
                        isConfigSame = sorted(oldGtmConfig.items()) == sorted(newGtmConfig.items())
                        if not isConfigSame and len(oldGtmConfig) == 0:
                            if partition in newGtmConfig:
                                mgr._gtm.create_gtm(
                                    partition,
                                    newGtmConfig)
                            mgr._gtm.replace_gtm_config(allConfig)
                            log.info("GTM: Initial push/sync on restart completed successfully ({} wideIPs)".format(
                                len(newGtmConfig.get(partition, {}).get('wideIPs', []) or [])))
                        elif not isConfigSame:
                            log.info("New changes observed in gtm config")
                            if partition in newGtmConfig:
                                mgr._gtm.delete_update_gtm(
                                    partition,
                                    newGtmConfig)
                            mgr._gtm.replace_gtm_config(allConfig)
                            log.info("GTM: Config sync completed successfully ({} wideIPs)".format(
                                len(newGtmConfig.get(partition, {}).get('wideIPs', []) or [])))

                except F5CcclError as e:
                    log.error("GTM Error.....:%s", e.msg)
                    gtmIncomplete += 1
        return gtmIncomplete

    def _update_cccl(self, config):
        _handle_vxlan_config(config)
        cfg_net = create_network_config(config)
        incomplete = 0
        for mgr in self._managers:
            if mgr.is_gtm():
                continue
            partition = mgr.get_partition()
            cfg_ltm = create_ltm_config(partition, config)
            try:
                if 'customProfiles' in cfg_ltm and \
                        mgr.get_schema_type() == 'ltm':
                    tmp = 0
                    tmp = _create_custom_profiles(
                        mgr.mgmt_root(),
                        partition,
                        cfg_ltm['customProfiles'])
                    incomplete += tmp

                if mgr.get_schema_type() == 'net':
                    incomplete += mgr._apply_net_config(cfg_net)
                else:
                    incomplete += mgr._apply_ltm_config(cfg_ltm)

                if mgr.get_schema_type() == 'ltm':
                    _delete_unused_ssl_profiles(
                        mgr,
                        partition,
                        cfg_ltm)

            except F5CcclError as e:
                log.error("CCCL Error: %s", e.msg)
                incomplete += 1

        return incomplete

    def cleanup_backoff(self):
        """Cleans up canceled backoff timers."""
        self._backoff_timer.cancel()
        self._backoff_timer.join()
        self._backoff_timer = None

    def handle_backoff(self):
        """Wrapper for calls to retry_backoff."""
        if (self._interval and self._interval.is_running() is
                True):
            self._interval.stop()
        if self._backoff_timer is None:
            self.retry_backoff()

    def retry_backoff(self):
        """Add a backoff timer to retry in case of failure."""
        def timer_cb():
            self._backoff_timer = None
            self.notify_reset()

        self._backoff_timer = threading.Timer(
            self._backoff_time, timer_cb
        )
        log.error("Error applying config, will try again in %s seconds",
                  self._backoff_time)
        self._backoff_timer.start()
        if self._backoff_time < self._max_backoff_time:
            self._backoff_time *= 2


class ConfigWatcher(pyinotify.ProcessEvent):
    def __init__(self, config_file, on_change):
        basename = os.path.basename(config_file)
        if not basename or 0 == len(basename):
            raise ConfigError('config_file must be a file path')

        self._config_file = config_file
        self._on_change = on_change

        self._config_dir = os.path.dirname(self._config_file)
        self._config_stats = None
        if os.path.exists(self._config_file):
            try:
                self._config_stats = self._digest()
            except IOError as ioe:
                log.warning('ioerror during sha sum calculation: {}'.
                            format(ioe))

        self._running = False
        self._polling = False
        self._user_abort = False
        signal.signal(signal.SIGINT, self._exit_gracefully)
        signal.signal(signal.SIGTERM, self._exit_gracefully)

    def _exit_gracefully(self, signum, frame):
        self._user_abort = True
        self._running = False

    def _loop_check(self, notifier):
        if self._polling:
            log.debug('inotify loop ended - returning to polling mode')
            return True
        else:
            return False

    def loop(self):
        self._running = True
        if not os.path.exists(self._config_dir):
            log.info(
                'configured directory doesn\'t exist {}, entering poll loop'.
                format(self._config_dir))
            self._polling = True

        while self._running:
            try:
                while self._polling:
                    if self._polling:
                        if os.path.exists(self._config_dir):
                            log.debug('found watchable directory - {}'.format(
                                self._config_dir))
                            self._polling = False
                            break
                        else:
                            log.debug('waiting for watchable directory - {}'.
                                      format(self._config_dir))
                            time.sleep(1)

                _wm = pyinotify.WatchManager()
                _notifier = pyinotify.Notifier(_wm, default_proc_fun=self)
                _notifier.coalesce_events(True)
                mask = (pyinotify.IN_CREATE | pyinotify.IN_DELETE |
                        pyinotify.IN_MOVED_FROM | pyinotify.IN_MOVED_TO |
                        pyinotify.IN_CLOSE_WRITE | pyinotify.IN_MOVE_SELF |
                        pyinotify.IN_DELETE_SELF)
                _wm.add_watch(
                    path=self._config_dir,
                    mask=mask,
                    quiet=False,
                    exclude_filter=lambda path: False)

                log.info('entering inotify loop to watch {}'.format(
                    self._config_file))
                _notifier.loop(callback=self._loop_check)

                if (not self._polling and _notifier._fd is None):
                    log.info('terminating')
                    self._running = False
            except Exception as e:
                log.warning(e)

        if self._user_abort:
            log.info('Received user kill signal, terminating.')

    def _digest(self):
        sha = hashlib.sha256()

        with open(self._config_file, 'rb') as f:
            fcntl.lockf(f.fileno(), fcntl.LOCK_SH, 0, 0, 0)
            while True:
                buf = f.read(4096)
                if not buf:
                    break
                sha.update(buf)
            fcntl.lockf(f.fileno(), fcntl.LOCK_UN, 0, 0, 0)
        return sha.digest()

    def _should_watch(self, pathname):
        if pathname == self._config_file:
            return True
        return False

    def _is_changed(self):
        changed = False
        cur_hash = None
        if not os.path.exists(self._config_file):
            if cur_hash != self._config_stats:
                changed = True
            else:
                changed = False
        else:
            try:
                cur_hash = self._digest()
                if cur_hash != self._config_stats:
                    changed = True
                else:
                    changed = False
            except IOError as ioe:
                log.warning('ioerror during sha sum calculation: {}'.
                            format(ioe))

        return (changed, cur_hash)

    def process_default(self, event):
        if (pyinotify.IN_DELETE_SELF == event.mask or
                pyinotify.IN_MOVE_SELF == event.mask):
            log.warn(
                'watchpoint {} has been moved or destroyed, using poll loop'.
                format(self._config_dir))
            self._polling = True

            if self._config_stats is not None:
                log.debug('config file {} changed, parent gone'.format(
                    self._config_file))
                self._config_stats = None
                self._on_change()

        if self._should_watch(event.pathname):
            (changed, sha) = self._is_changed()

            if changed:
                log.debug('config file {0} changed - signalling bigip'.format(
                    self._config_file, self._config_stats, sha))
                self._config_stats = sha
                self._on_change()


class GTMManager(object):
    """F5 Common Controller Cloud Service Management.

    The F5 Common Controller Core Library (CCCL) is an orchestration package
    that provides a declarative API for defining BIG-IP LTM and NET services
    in diverse environments (e.g. Marathon, Kubernetes, OpenStack). The
    API will allow a user to create proxy services by specifying the:
    virtual servers, pools, L7 policy and rules, monitors, arps, or fdbTunnels
    as a service description object.  Each instance of the CCCL is initialized
    with namespace qualifiers to allow it to uniquely identify the resources
    under its control.
    """

    def __init__(self, bigip, partition, user_agent=None):
        """Initialize an instance of the F5 CCCL service manager."""
        log.debug("F5GTMManager initialize")

        if user_agent is not None:
            bigip.icrs.append_user_agent(user_agent)
        self._user_agent = user_agent
        self._mgmt_root = bigip
        self._partition = partition
        self._gtm_config = {}
        self._active_tenants = []
        self._deleted_tenants = []
        self._gtm = bigip.tm.gtm
        # PERF FIX #9: Cache BIG-IP version once
        self._bigip_version = None
        # RETRY FIX: Track pending cleanup state for isConfigSame retry scenario
        self._pending_cleanup = None

    def get_gtm_config(self):
        """ Return the GTM config object"""
        return self._gtm_config

    def replace_gtm_config(self, config):
        """ Updating the GTM config object"""
        self._active_tenants = config["activeTenants"]
        self._deleted_tenants = []
        self._gtm_config = config["config"]

    @staticmethod
    def format_server_name(dataserver_ip):
        """ Format GSLB server name from DataServer IP"""
        return "server_{}".format(
            dataserver_ip.replace(".", "_")
                         .replace(":", "_")
                         .replace("%", "_")
        )

    @staticmethod
    def _is_transient_error(exception):
        """Determine if an error is transient (retriable) vs permanent (not retriable).
        
        Priority order:
          1. Exception types (isinstance checks) — most reliable
          2. HTTP status codes (if available) — structured data
          3. Permanent patterns in error messages — never retry
          4. Transient patterns in error messages — safe to retry
          5. Nested exception chain — unwrap SDK wrappers
          6. Default: transient (retry is safer than silent failure)
        """
        # ---- Step 1: Check exception type directly (most Pythonic) ----
        try:
            # Standard library connection errors
            if isinstance(exception, (ConnectionError, ConnectionResetError,
                                    ConnectionAbortedError, ConnectionRefusedError,
                                    BrokenPipeError, TimeoutError, OSError)):
                return True
        except NameError:
            # Python < 3.5 compatibility
            pass
        
        # ---- Step 2: Check HTTP status code if available (structured data) ----
        if hasattr(exception, 'response') and exception.response is not None:
            try:
                status_code = exception.response.status_code
                # Transient HTTP errors
                if status_code in {401, 403, 408, 429, 500, 502, 503, 504}:
                    return True
                # Permanent HTTP errors
                if status_code in {400, 404, 409, 422}:
                    return False
            except (AttributeError, TypeError):
                pass
        
        # ---- Step 3: String pattern matching (fallback) ----
        error_str = str(exception).lower()
        error_type = type(exception).__name__.lower()
        
        # Permanent patterns — NEVER retry
        PERMANENT_PATTERNS = (
            '404', 'not found', 'does not exist',
            'was not found', 'is not valid', 'is not allowed',
        )
        if any(p in error_str for p in PERMANENT_PATTERNS):
            return False
        
        # Transient string patterns
        TRANSIENT_PATTERNS = (
            # Auth (session expired, token stale)
            '401', '403',
            # Server errors
            '500', '502', '503', '504',
            # Connection errors
            'connection reset', 'connection refused',
            'connection aborted', 'broken pipe',
            'remotedisconnected', 'incompleteread',
            # Timeout
            'timeout', 'timed out',
        )
        if any(p in error_str for p in TRANSIENT_PATTERNS):
            return True
        
        # Exception type name matching (catches wrapped exceptions)
        TRANSIENT_TYPES = (
            'connectionerror', 'connectionreset', 'connectionaborted',
            'connectionrefused', 'brokenpipe', 'timeout',
        )
        if any(t in error_type for t in TRANSIENT_TYPES):
            return True
        
        # ---- Step 4: Walk nested exception chain (F5 SDK wraps errors in args) ----
        if hasattr(exception, 'args'):
            for arg in exception.args:
                if isinstance(arg, BaseException):
                    # Recursive check on nested exception
                    return GTMManager._is_transient_error(arg)
        
        # ---- Step 5: Default to transient (retry is safer) ----
        return True

    def _parse_member_spec(self, member_spec, pool_dataserver=None):
        """Centralized member spec parsing - single source of truth."""
        separator = '|' if '|' in member_spec else ':'
        parts = member_spec.split(separator)

        if len(parts) == 3:
            dataserver, member_ip, member_port = parts
        elif len(parts) == 2:
            if not pool_dataserver:
                log.warning("GTM: Member '{}' has no DataServer".format(member_spec))
                return None, None, None, None
            dataserver = pool_dataserver
            member_ip, member_port = parts
        else:
            log.warning("GTM: Invalid member format: {}".format(member_spec))
            return None, None, None, None

        destination = "{}:{}".format(member_ip, member_port)
        return dataserver, member_ip, member_port, destination

    @staticmethod
    def _format_vs_name(destination):
        """Generate a BIG-IP-safe virtual server name from a destination."""
        return "vs-{}".format(
            destination.replace(".", "-")
                       .replace(":", "-")
                       .replace("%", "-")
        )

    def _parse_gtm_config_once(self, gtmConfig, partition):
        """Single-pass config parsing to extract ALL needed data structures."""
        result = {
            'dataservers': set(),
            'vs_inventory': {},
            'members_by_pool': {},
            'all_member_refs': set(),
            'all_server_names': set(),
        }

        if partition not in gtmConfig:
            return result

        wideips = gtmConfig[partition].get('wideIPs', [])
        if not wideips:
            return result

        for wideip in wideips:
            pools = wideip.get('pools', [])
            if not pools:
                continue

            for pool in pools:
                pool_name = pool.get('name')
                pool_dataserver = pool.get('DataServer')
                members = pool.get('members', [])

                if pool_name and pool_name not in result['members_by_pool']:
                    result['members_by_pool'][pool_name] = set()

                if not members:
                    continue

                for member_spec in members:
                    dataserver, member_ip, member_port, destination = \
                        self._parse_member_spec(member_spec, pool_dataserver)

                    if dataserver is None:
                        continue

                    result['dataservers'].add(dataserver)

                    server_name = self.format_server_name(dataserver)
                    vs_name = self._format_vs_name(destination)

                    if server_name not in result['vs_inventory']:
                        result['vs_inventory'][server_name] = set()
                    result['vs_inventory'][server_name].add(
                        (member_ip, vs_name, destination))

                    member_ref = "{}:{}".format(server_name, vs_name)
                    if pool_name:
                        result['members_by_pool'][pool_name].add(member_ref)
                    result['all_member_refs'].add(member_ref)
                    result['all_server_names'].add(server_name)

        return result

    def mgmt_root(self):
        """ Return the BIG-IP ManagementRoot object"""
        return self._mgmt_root

    def gtm(self):
        """Return the GTM object for API operations."""
        return self._gtm

    def get_partition(self):
        """ Return the managed partition."""
        return self._partition

    @staticmethod
    def pre_process_gtm(gtmConfig):
        """Pre-process GTM config to escape special characters in monitor send strings.
        
        Converts \r and \n to their escaped versions (\\r and \\n) in monitor send strings
        to ensure proper transmission via iControlREST API.
        """
        for partition in gtmConfig:
            if "wideIPs" in gtmConfig[partition]:
                if gtmConfig[partition]['wideIPs'] is not None:
                    for config in gtmConfig[partition]['wideIPs']:
                        for pool in config['pools']:
                            if "monitors" in pool.keys():
                                for monitor in pool['monitors']:
                                    if "send" in monitor.keys():
                                        monitor["send"] = monitor["send"].replace("\r", "\\r")
                                        monitor["send"] = monitor["send"].replace("\n", "\\n")

    def delete_update_gtm(self, partition, gtmConfig):
        """ Update GTM object in BIG-IP """
        try:
            oldConfig = self._gtm_config
            mgmt = self.mgmt_root()
            gtm = mgmt.tm.gtm
            if partition in oldConfig and partition in gtmConfig:
                opr_config = self.process_config(oldConfig[partition], gtmConfig[partition])
                rev_map = self.create_reverse_map(oldConfig[partition])

                # NOTE: process_config() always returns all three keys even when their
                # lists are empty (e.g. {"wideIPs":[], "pools":[], "monitors":[]}).
                # We must guard on whether the lists are non-empty, not on key presence,
                # to avoid calling handle_operation_delete() for pure create/update cycles.

                # Process delete ALWAYS before create/update — enforced explicitly
                # rather than relying on dict iteration order (which would be "create" first,
                # since process_config() returns {"create":…, "delete":…, "update":…}).
                # For a wideIP rename the same servers/VSs are shared: passing incoming_config
                # lets handle_operation_delete scope its VS/server cleanup against the NEW
                # config so those resources are NOT deleted before handle_operation_create runs.
                delete_op = opr_config.get("delete", {})
                has_deletes = (
                    bool(delete_op.get("wideIPs")) or
                    bool(delete_op.get("pools")) or
                    bool(delete_op.get("monitors"))
                )
                if has_deletes:
                    self.handle_operation_delete(gtm, partition, delete_op, rev_map,
                                                 incoming_config=gtmConfig)

                    # Process any pending cleanup from delete BEFORE create runs to prevent
                    # create from overwriting delete's pending cleanup state.
                    if self._pending_cleanup is not None:
                        log.info("GTM: Processing pending delete cleanup before create operation")
                        self.retry_pending_cleanup(gtm)

                for opr in ("create", "update"):
                    op_items = opr_config.get(opr, {})
                    if (bool(op_items.get("wideIPs")) or
                            bool(op_items.get("pools")) or
                            bool(op_items.get("monitors"))):
                        self.handle_operation_create(gtm, partition, gtmConfig, op_items, opr)
        except F5CcclError as e:
            raise e

    def handle_operation_delete(self, gtm, partition, opr_config, rev_map, incoming_config=None):
        """ Handle delete operation.

        Args:
            gtm: BIG-IP GTM handle
            partition: partition name
            opr_config: dict with keys wideIPs/pools/monitors listing names to delete
            rev_map: reverse mapping from create_reverse_map()
            incoming_config: the full new GTM config being applied (used to scope VS/server
                             cleanup — resources still referenced by the new config are kept).
                             When provided (e.g. a wideIP rename), the cleanup compares old
                             member-refs against the NEW config so that shared servers/VSs are
                             not deleted before handle_operation_create() can re-attach them.
        """
        # RETRY FIX: Work on a deep copy of config; only commit at the end if all steps succeed
        # This prevents partial mutations from making retry think config is already applied
        working_config = copy.deepcopy(self._gtm_config)

        try:
            # Save old config before making changes
            oldConfig = self._gtm_config

            # Parse OLD config
            log.debug("GTM: Parsing configs for delete operation cleanup")
            old_parsed = self._parse_gtm_config_once(oldConfig, partition)

            # Build the post-delete target config by removing deleted resources from a copy
            # of the old config.  This is used as a fallback when incoming_config is not
            # provided (pure-delete, no concurrent create).
            target_config = copy.deepcopy(self._gtm_config)
            if partition in target_config and target_config[partition].get('wideIPs'):
                deleted_wideip_names = set(opr_config.get("wideIPs", []))
                deleted_pool_names = set(opr_config.get("pools", []))

                surviving_wideips = []
                for wideip in target_config[partition]['wideIPs']:
                    if wideip['name'] in deleted_wideip_names:
                        continue  # This wideIP is being deleted
                    # Remove deleted pools from surviving wideIPs
                    surviving_pools = []
                    for pool in wideip.get('pools', []):
                        if pool['name'] not in deleted_pool_names:
                            surviving_pools.append(pool)
                    wideip['pools'] = surviving_pools
                    surviving_wideips.append(wideip)
                target_config[partition]['wideIPs'] = surviving_wideips

            # RENAME FIX: When incoming_config is provided use it as the reference for
            # VS/server cleanup.  For a wideIP rename the same servers/VSs are reused by
            # the new wideIP; scoping cleanup against incoming_config means
            #   members_to_delete = old_member_refs - new_member_refs = {}
            # so those resources are NOT deleted before handle_operation_create() runs.
            cleanup_config = incoming_config if incoming_config is not None else target_config
            cleanup_new_parsed = self._parse_gtm_config_once(cleanup_config, partition)

            # Keep target_config-based new_parsed for the delete steps themselves (steps 1-3)
            new_parsed = self._parse_gtm_config_once(target_config, partition)

            # Step 1: Delete monitors
            if len(opr_config["monitors"]) > 0:
                for monitor in opr_config["monitors"]:
                    poolName = rev_map["monitors"][monitor]
                    self.remove_monitor_from_gtm_pool(gtm, partition, poolName, monitor)
                    self.delete_gtm_hm(gtm, partition, monitor, working_config=working_config)

            # Step 2: Delete pools (this also removes members)
            # Pass working_config so mutations go to the copy, not self._gtm_config
            if len(opr_config["pools"]) > 0:
                for pool in opr_config["pools"]:
                    wideipForPoolDeleted = rev_map["pools"][pool]
                    for wideip in wideipForPoolDeleted:
                        self.delete_gtm_pool(gtm, partition, wideip, pool, working_config=working_config)

            # Step 3: Delete wideIPs
            # Pass working_config so mutations go to the copy, not self._gtm_config
            if len(opr_config["wideIPs"]) > 0:
                for wideip in opr_config["wideIPs"]:
                    self.delete_gtm_wideip(gtm, partition, wideip, working_config=working_config)

        except F5CcclError as e:
            log.error("GTM: Error while handling delete operation (Steps 1-3): %s", e)
            # Do NOT commit working_config; self._gtm_config remains unchanged for retry
            raise e

        # CRITICAL FIX: Commit BEFORE cleanup phase
        # This ensures successful deletes are recorded even if cleanup fails
        self._gtm_config = working_config
        log.debug("GTM: Committed config changes after successful delete operation")

        # Step 4: Clean up unused virtual servers.
        # RENAME FIX: Use cleanup_config (= incoming_config when provided) so that
        # VS/server cleanup is scoped against the new full config, not just the
        # post-delete stub.  For a rename this prevents deleting servers/VSs that
        # the new wideIP still needs.
        vs_cleanup_error = None
        datacenter_name = None
        if partition in cleanup_config:
            datacenter_name = cleanup_config[partition].get('dataCenter', None)
            if datacenter_name and '/' in datacenter_name:
                datacenter_name = datacenter_name.split('/')[-1]

        try:
            log.info("GTM: Cleaning up unused virtual servers")
            self.cleanup_unused_virtual_servers(gtm, partition, oldConfig, cleanup_config,
                                               old_parsed=old_parsed, new_parsed=cleanup_new_parsed)
        except Exception as e:
            log.error("GTM: VS cleanup failed, will still attempt server cleanup: %s", e)
            vs_cleanup_error = e

        # Step 5: Clean up unused GSLB servers.
        # RESILIENCE FIX: Always attempt, even if VS cleanup failed
        server_cleanup_error = None
        try:
            log.info("GTM: Cleaning up unused GSLB servers")
            self.cleanup_unused_gslb_servers(gtm, datacenter_name, oldConfig, cleanup_config,
                                            old_parsed=old_parsed, new_parsed=cleanup_new_parsed)
        except Exception as e:
            log.error("GTM: GSLB server cleanup also failed: %s", e)
            server_cleanup_error = e

        # RETRY FIX: Record pending cleanup state before re-raising
        # This allows retry to work even when isConfigSame == True
        if vs_cleanup_error or server_cleanup_error:
            self._pending_cleanup = {
                'partition': partition,
                'oldConfig': oldConfig,
                'target_config': cleanup_config,
                'old_parsed': old_parsed,
                'new_parsed': cleanup_new_parsed,
                'datacenter_name': datacenter_name
            }
            log.debug("GTM: Saved pending cleanup state for retry")
        else:
            # Cleanup succeeded - clear any stale pending state
            self._pending_cleanup = None
            log.debug("GTM: Cleared pending cleanup state after successful cleanup")
        
        # Re-raise cleanup errors (transient errors will trigger retry)
        if vs_cleanup_error:
            raise F5CcclError(msg="Virtual server cleanup failed: {}".format(str(vs_cleanup_error)))
        if server_cleanup_error:
            raise F5CcclError(msg="GSLB server cleanup failed: {}".format(str(server_cleanup_error)))

    def handle_operation_create(self, gtm, partition, gtmConfig, opr_config, opr):
        """ Handle create operation """
        # RETRY FIX: Work on a deep copy of config; only commit at the end if all steps succeed
        working_config = copy.deepcopy(self._gtm_config)
         # PERF FIX: Use direct reference — oldConfig is read-only, never mutated
        oldConfig = self._gtm_config

        # PERF FIX: Defer parsing until we know there is actual work to do
        old_parsed = None
        new_parsed = None
        
        try:
            if len(opr_config["pools"]) > 0 or len(opr_config["monitors"]) > 0 or len(opr_config["wideIPs"]) > 0:
                log.debug("GTM: Parsing configs for create/update operation")
                old_parsed = self._parse_gtm_config_once(oldConfig, partition)
                new_parsed = self._parse_gtm_config_once(gtmConfig, partition)

                log.info("GTM: Ensuring infrastructure for create/update operation")
                self.orchestrate_gtm_infrastructure(gtm, partition, gtmConfig, parsed=new_parsed)

                if partition in gtmConfig and "wideIPs" in gtmConfig[partition]:
                    if gtmConfig[partition]['wideIPs'] is not None:
                        # FIX 2: Build set of wideIPs that need processing
                        changed_pools = set(opr_config.get("pools", []))
                        changed_wideips = set(opr_config.get("wideIPs", []))

                        # Map pool names to their parent wideIP names
                        pool_to_wideip = {}
                        for wip in gtmConfig[partition]['wideIPs']:
                            for p in wip.get('pools', []):
                                pool_to_wideip[p['name']] = wip['name']

                        # Include wideIPs that contain changed pools
                        wideips_to_process = set(changed_wideips)
                        for pool_name in changed_pools:
                            if pool_name in pool_to_wideip:
                                wideips_to_process.add(pool_to_wideip[pool_name])

                        # Also include wideIPs that contain changed monitors
                        changed_monitors = set(opr_config.get("monitors", []))
                        if changed_monitors:
                            for wip in gtmConfig[partition]['wideIPs']:
                                for p in wip.get('pools', []):
                                    for m in p.get('monitors', []):
                                        if m.get('name') in changed_monitors:
                                            wideips_to_process.add(wip['name'])

                        log.info("GTM: Processing {} changed wideIP(s) out of {} total".format(
                            len(wideips_to_process), len(gtmConfig[partition]['wideIPs'])))

                        for config in gtmConfig[partition]['wideIPs']:
                            # SKIP wideIPs that haven't changed
                            if config['name'] not in wideips_to_process:
                                continue

                            monitor = ""
                            newPools = dict()
                            for pool in config['pools']:
                                newPools[pool['name']] = {
                                    'name': pool['name'], 'partition': partition, 'ratio': 1, 'order': pool['order']
                                }
                                all_monitors = ""
                                if "monitors" in pool.keys():
                                    for monitor in pool["monitors"]:
                                        if opr == "update" and monitor['name'] in opr_config["monitors"]:
                                            self.remove_monitor_from_gtm_pool(gtm, partition, pool['name'],
                                                                              monitor['name'])
                                            self.delete_gtm_hm(gtm, partition, monitor['name'], working_config=working_config)
                                        self.create_HM(gtm, partition, monitor, config['name'])
                                        all_monitors += "/" + partition + "/" + monitor['name']
                                        if monitor["name"] != pool["monitors"][-1]["name"]:
                                            all_monitors += " and "

                                # PERF FIX #11: Pre-load pool once for batch member deletion
                                if partition in oldConfig and "wideIPs" in oldConfig[partition]:
                                    if oldConfig[partition]['wideIPs'] is not None:
                                        for index, oldWideIP in enumerate(oldConfig[partition]['wideIPs']):
                                            if oldWideIP['name'] == config['name']:
                                                for pool_index, oldPool in enumerate(oldWideIP['pools']):
                                                    if oldPool['name'] == pool['name']:
                                                        if oldPool['members'] is not None and pool['members'] is not None:
                                                            oldPoolMember = set(oldPool['members'])
                                                            newPoolMember = set(pool['members'])
                                                            deleteMember = oldPoolMember - newPoolMember
                                                            if deleteMember:
                                                                log.info("GTM: Members to delete from pool {}: {}".format(
                                                                    pool['name'], deleteMember))
                                                                pool_obj = None
                                                                if gtm.pools.a_s.a.exists(name=oldPool['name'], partition=partition):
                                                                    pool_obj = gtm.pools.a_s.a.load(name=oldPool['name'], partition=partition)
                                                                for member in deleteMember:
                                                                    member_ref = self._convert_member_to_bigip_reference(
                                                                        member, oldPool.get('DataServer'))
                                                                    log.info("GTM: Deleting member {} (BIG-IP ref: {}) from pool {}".format(
                                                                        member, member_ref, oldPool['name']))
                                                                    self.remove_member_to_gtm_pool(
                                                                        gtm,
                                                                        partition,
                                                                        oldPool['name'],
                                                                        member_ref,
                                                                        pool_obj=pool_obj)
                                                            working_config[partition]['wideIPs'][index]["pools"][
                                                                pool_index]['members'] = None
                            try:
                                self.create_gtm_pool(gtm, partition, config, all_monitors, skip_member_validation=True)
                                self.create_wideip(gtm, partition, config, newPools)
                            except F5CcclError as e:
                                raise e

        except F5CcclError as e:
            log.error("GTM: Error while handling create operation: %s", e)
            # Do NOT commit working_config; self._gtm_config remains unchanged for retry
            raise e

        # CRITICAL FIX: Commit BEFORE cleanup phase
        # This ensures successful creates are recorded even if cleanup fails
        self._gtm_config = working_config
        log.debug("GTM: Committed config changes after successful create/update operation")
        if old_parsed is not None and new_parsed is not None:
            # Cleanup phase - separate try blocks so server cleanup runs even if VS cleanup fails
            # Errors here trigger retry but the successful create work is already saved
            vs_cleanup_error = None
            datacenter_name = None
            if partition in gtmConfig:
                datacenter_name = gtmConfig[partition].get('dataCenter', None)
                if datacenter_name and '/' in datacenter_name:
                    datacenter_name = datacenter_name.split('/')[-1]
            
            try:
                log.info("GTM: Cleaning up orphaned infrastructure after update")
                self.cleanup_unused_virtual_servers(gtm, partition, oldConfig, gtmConfig,
                                                old_parsed=old_parsed, new_parsed=new_parsed)
            except Exception as e:
                log.error("GTM: VS cleanup failed during create/update, will still attempt server cleanup: %s", e)
                vs_cleanup_error = e

            server_cleanup_error = None
            try:
                self.cleanup_unused_gslb_servers(gtm, datacenter_name, oldConfig, gtmConfig,
                                                old_parsed=old_parsed, new_parsed=new_parsed)
            except Exception as e:
                log.error("GTM: GSLB server cleanup failed during create/update: %s", e)
                server_cleanup_error = e

            # RETRY FIX: Record pending cleanup state before re-raising
            # This allows retry to work even when isConfigSame == True
            if vs_cleanup_error or server_cleanup_error:
                self._pending_cleanup = {
                    'partition': partition,
                    'oldConfig': oldConfig,
                    'target_config': gtmConfig,
                    'old_parsed': old_parsed,
                    'new_parsed': new_parsed,
                    'datacenter_name': datacenter_name
                }
                log.debug("GTM: Saved pending cleanup state for retry")
            else:
                # Cleanup succeeded - clear any stale pending state
                self._pending_cleanup = None
                log.debug("GTM: Cleared pending cleanup state after successful cleanup")
            
            # Re-raise cleanup errors (transient errors will trigger retry)
            if vs_cleanup_error:
                raise F5CcclError(msg="Virtual server cleanup failed: {}".format(str(vs_cleanup_error)))
            if server_cleanup_error:
                raise F5CcclError(msg="GSLB server cleanup failed: {}".format(str(server_cleanup_error)))

    def remove_unused_poolmembers(self, partition, gtmConfig):
        """Remove unused GTM PoolMembers from BIGIP created by CIS <= v2.7.1 """
        try:
            def _get_value(d, k):
                if d[k] is None:
                    return dict()
                return d[k]

            def _get_virtualNames_from_member(gtm_members):
                list_gtm_virtuals = {}
                for poolName in gtm_members:
                    list_gtm_virtuals[poolName] = []
                    for gtm_member in gtm_members[poolName]:
                        if '/Shared/' in gtm_member:
                            list_gtm_virtuals[poolName].append(gtm_member.split('/Shared/')[1])
                        else:
                            log.debug("GTM: Skipping new format member in legacy cleanup: {}".format(gtm_member))
                return list_gtm_virtuals

            def _find_deleted_members(gtm_members, bigip_members):
                del_gtm_members = {}
                list_gtm_virtuals = _get_virtualNames_from_member(gtm_members)
                for poolName in gtm_members:
                    del_gtm_members[poolName] = []
                    for gtm_member in gtm_members[poolName]:
                        if "ingress_link_" not in gtm_member and '/Shared/' in gtm_member and poolName in bigip_members:
                            gtmPoolObj, gtmMemberName = gtm_member.split('/Shared/')
                            parseSearchStrfromMember = ('_').join(gtmMemberName.split('_')[:-1])
                            extra_bigip_members = list(set(bigip_members[poolName]) - set(list_gtm_virtuals[poolName]))
                            for bigipPoolMember in extra_bigip_members:
                                if bigipPoolMember.startswith(parseSearchStrfromMember):
                                    member = gtmPoolObj + '/Shared/' + bigipPoolMember
                                    del_gtm_members[poolName].append(member)
                return del_gtm_members

            gtm = self.gtm()
            gtm_pools = []
            for wip in _get_value(gtmConfig, "wideIPs"):
                gtm_pools += wip["pools"]

            gtm_members, bigip_members = {}, {}
            for p in gtm_pools:
                if p.get("members"):
                    gtm_members[p['name']] = p["members"]
                    try:
                        exist = gtm.pools.a_s.a.exists(name=p['name'], partition=partition)
                        if not exist:
                            continue
                        pool = gtm.pools.a_s.a.load(name=p['name'], partition=partition)
                        bigip_members[p['name']] = [gtmMember.name for gtmMember in pool.members_s.get_collection()]
                    except Exception as e:
                        log.error("GTM: Error fetching pool {} members during legacy cleanup: {}".format(
                            p['name'], str(e)))
                        raise F5CcclError(
                            msg="Legacy cleanup failed for pool {}: {}".format(
                                p['name'], str(e)))

            del_gtm_members = _find_deleted_members(gtm_members, bigip_members)
            try:
                for poolName in del_gtm_members:
                    for member in del_gtm_members[poolName]:
                        self.remove_member_to_gtm_pool(
                            gtm,
                            partition,
                            poolName,
                            member)
            except F5CcclError as e:
                log.error("GTM: Error while removing gtm pool member: %s", e)
                raise e
        except F5CcclError as e:
            log.error("GTM: Error while processing for list of pool members to delete: %s", e)
            raise e
    
    def _snapshot_bigip_state(self, gtm, partition, gtmConfig):
        """Optimized config-driven BIG-IP state snapshot.
        
        Skips VS fetching — VS existence is inferred from pool member existence.
        If all pool members match, VSs are guaranteed to exist (VSs are prerequisites for members).
        If some wideIPs need processing, VS names are fetched lazily in _orchestrate_with_snapshot.
        
        """
        snapshot = {
            'servers': set(),
            'server_vs': {},
            'pools': set(),
            'pool_members': {},
            'wideips': set(),
        }

        start_time = time.time()
        log.info("GTM: [SNAPSHOT] Starting optimized config-driven snapshot")

        # ---------------------------------------------------------------
        # 1. Servers — names only, NO VS fetching
        #    VS existence inferred from pool member existence
        #    If needed, VSs loaded lazily in _orchestrate_with_snapshot
        # ---------------------------------------------------------------
        all_servers = gtm.servers.get_collection()
        for srv in all_servers:
            snapshot['servers'].add(srv.name)
            snapshot['server_vs'][srv.name] = set()
            # DO NOT fetch VSs here — causes 490KB response + slow SDK parsing

        server_time = time.time()
        log.info("GTM: [SNAPSHOT] Servers: {:.1f}s ({} servers — VS names deferred)".format(
            server_time - start_time,
            len(snapshot['servers'])))

        # ---------------------------------------------------------------
        # 2. Pools + members — load-only pattern
        # ---------------------------------------------------------------
        if partition not in gtmConfig or 'wideIPs' not in gtmConfig[partition]:
            total_time = time.time() - start_time
            log.info("GTM: [SNAPSHOT] Complete in {:.1f}s — no wideIPs in config".format(total_time))
            return snapshot

        wideips = gtmConfig[partition].get('wideIPs', []) or []

        pools_to_check = set()
        for wip in wideips:
            for pool in wip.get('pools', []):
                pools_to_check.add(pool['name'])

        pool_start = time.time()
        pools_found = 0
        pools_missing = 0

        for pool_name in pools_to_check:
            try:
                pool_obj = gtm.pools.a_s.a.load(name=pool_name, partition=partition)
                snapshot['pools'].add(pool_name)
                pools_found += 1
                # CRITICAL: Do NOT return empty set on error - would corrupt snapshot
                snapshot['pool_members'][pool_name] = {
                    m.name for m in pool_obj.members_s.get_collection()
                }
            except Exception as e:
                error_str = str(e).lower()
                if "not found" in error_str or "404" in error_str:
                    # Resource doesn't exist - this is expected, not an error
                    pools_missing += 1
                else:
                    # Transient error (auth, network, etc) - must raise to trigger retry
                    log.error("GTM: [SNAPSHOT] Transient error loading pool {}: {}".format(
                        pool_name, str(e)))
                    raise F5CcclError(msg="Snapshot failed loading pool {}: {}".format(
                        pool_name, str(e)))

        pool_time = time.time()
        log.info("GTM: [SNAPSHOT] Pools: {:.1f}s ({} found, {} missing, {} total members)".format(
            pool_time - pool_start,
            pools_found,
            pools_missing,
            sum(len(m) for m in snapshot['pool_members'].values())))

        # ---------------------------------------------------------------
        # 3. WideIPs — exists() only
        # ---------------------------------------------------------------
        wideip_start = time.time()
        wideips_found = 0
        wideips_missing = 0

        for wip in wideips:
            wip_name = wip['name']
            try:
                if gtm.wideips.a_s.a.exists(name=wip_name, partition=partition):
                    snapshot['wideips'].add(wip_name)
                    wideips_found += 1
                else:
                    wideips_missing += 1
            except Exception as e:
                # Mark as missing - create_wideip() handles "already exists" gracefully
                # (faster than raising and restarting entire config push)
                log.warning("GTM: [SNAPSHOT] Could not check wideIP {}: {}. Marking as needs processing.".format(
                    wip_name, str(e)))
                wideips_missing += 1

        total_time = time.time() - start_time
        log.info("GTM: [SNAPSHOT] WideIPs: {:.1f}s ({} found, {} missing)".format(
            time.time() - wideip_start,
            wideips_found,
            wideips_missing))

        log.info("GTM: [SNAPSHOT] Complete in {:.1f}s — {} servers, {} pools, {} wideips".format(
            total_time,
            len(snapshot['servers']),
            len(snapshot['pools']),
            len(snapshot['wideips'])))

        return snapshot
    
    def _wideip_fully_exists(self, config, partition, snapshot):
        """Check if wideIP fully exists with correct members.
        Zero API calls — pure in-memory comparison.
        """
        # Check wideIP exists (set lookup)
        if config['name'] not in snapshot['wideips']:
            log.debug("GTM: [SNAPSHOT] WideIP {} not found".format(config['name']))
            return False

        # Check all pools exist and members match exactly
        for pool in config.get('pools', []):
            pool_name = pool['name']

            # Check pool exists (set lookup)
            if pool_name not in snapshot['pools']:
                log.debug("GTM: [SNAPSHOT] Pool {} not found".format(pool_name))
                return False

            # Build expected members from config
            pool_dataserver = pool.get('DataServer', '')
            expected_members = set()
            for member_spec in pool.get('members', []) or []:
                dataserver, member_ip, member_port, destination = \
                    self._parse_member_spec(member_spec, pool_dataserver)
                if dataserver is None:
                    continue
                server_name = self.format_server_name(dataserver)
                vs_name = self._format_vs_name(destination)
                expected_members.add("{}:{}".format(server_name, vs_name))

            # Exact member match
            actual_members = snapshot['pool_members'].get(pool_name, set())
            if expected_members != actual_members:
                log.debug("GTM: [SNAPSHOT] Pool {} members differ "
                        "(expected={}, actual={})".format(
                            pool_name, len(expected_members), len(actual_members)))
                return False

        return True
        
    def _cleanup_orphans_with_snapshot(self, gtm, partition, expected_members, snapshot):
        """Remove orphaned pool members using snapshot data."""
        orphan_count = 0
        cleanup_failures = 0
        for pool_name, expected_member_set in expected_members.items():
            actual_members = snapshot['pool_members'].get(pool_name, set())
            members_to_delete = actual_members - expected_member_set

            if not members_to_delete:
                continue

            log.info("GTM: [SNAPSHOT] Removing {} orphaned members from pool {}".format(
                len(members_to_delete), pool_name))

            try:
                pool_obj = gtm.pools.a_s.a.load(name=pool_name, partition=partition)
                for member_name in members_to_delete:
                    self.remove_member_to_gtm_pool(
                        gtm, partition, pool_name, member_name, pool_obj=pool_obj)
                    orphan_count += 1
            except Exception as e:
                log.error("GTM: [SNAPSHOT] Error cleaning up orphans in pool {}: {}".format(
                    pool_name, str(e)))
                cleanup_failures += 1

        if cleanup_failures > 0:
            raise F5CcclError(
                msg="GTM: Orphan cleanup incomplete — {} pool(s) failed".format(
                    cleanup_failures))

        if orphan_count > 0:
            log.info("GTM: [SNAPSHOT] Removed {} total orphaned members".format(orphan_count))
        else:
            log.debug("GTM: [SNAPSHOT] No orphaned members found")
    
    def create_gtm(self, partition, gtmConfig):
        """ Create GTM object in BIG-IP — optimized with config-driven snapshot """
        try:
            gtm = self.gtm()

            total_wideips = len(gtmConfig.get(partition, {}).get('wideIPs', []) or [])
            log.info("GTM: ========== Initial sync starting for partition {} ({} wideIPs) ==========".format(
            partition, total_wideips))

            # Step 0: Parse config once
            log.debug("GTM: Parsing configuration for partition {}".format(partition))
            parsed = self._parse_gtm_config_once(gtmConfig, partition)
            
            log.info("GTM: [INIT-SYNC] Step 2/5: Taking BIG-IP state snapshot (for {} wideIPs)...".format(
            total_wideips))
            # Step 0.5: Snapshot BIG-IP state (config-driven, load-only pattern)
            snapshot = self._snapshot_bigip_state(gtm, partition, gtmConfig)

            # Step 1: Check if ALL wideIPs are fully present on BIG-IP
            # If yes, skip entire infrastructure orchestration (saves ~2-3 min)
            all_wideips_exist = True
            skipped = 0
            processed = 0
            wideips_needing_processing = []
            log.info("GTM: [INIT-SYNC] Step 3/5: Comparing config against BIG-IP snapshot...")
            if "wideIPs" in gtmConfig[partition]:
                if gtmConfig[partition]['wideIPs'] is not None:
                    for config in gtmConfig[partition]['wideIPs']:
                        if self._wideip_fully_exists(config, partition, snapshot):
                            skipped += 1
                        else:
                            all_wideips_exist = False
                            wideips_needing_processing.append(config)
                            processed += 1

            if all_wideips_exist:
                # ALL wideIPs exist with correct members — skip everything
                log.info("GTM: [SNAPSHOT] All {} wideIPs unchanged — skipping infrastructure and processing".format(
                    skipped))

                # Only run orphan cleanup using snapshot data (zero API calls if no orphans)
                expected_members = parsed['members_by_pool']
                self._cleanup_orphans_with_snapshot(gtm, partition, expected_members, snapshot)

                self._gtm_config[partition] = gtmConfig[partition]
                log.info("GTM: Initial sync complete for partition {} — {} wideIPs (0 processed, {} skipped)".format(
                    partition, skipped, skipped))
                return

            # Step 2: Some wideIPs need processing — run full infrastructure orchestration
            log.info("GTM: [SNAPSHOT] {} wideIPs need processing, {} unchanged — running infrastructure orchestration".format(
                processed, skipped))

            log.info("GTM: Orchestrating infrastructure for partition {}".format(partition))
            infrastructure = self._orchestrate_with_snapshot(
                gtm, partition, gtmConfig, parsed, snapshot)
            log.debug("GTM: Infrastructure ready: {}".format(infrastructure))

            expected_members = parsed['members_by_pool']

            # Step 3: Process ONLY wideIPs that need it
            for config in wideips_needing_processing:
                newPools = dict()
                for pool in config['pools']:
                    newPools[pool['name']] = {
                        'name': pool['name'], 'partition': partition,
                        'ratio': 1, 'order': pool['order']
                    }
                    all_monitors = ""
                    if "monitors" in pool.keys():
                        for monitor in pool["monitors"]:
                            all_monitors += "/" + partition + "/" + monitor["name"]
                            if monitor["name"] != pool["monitors"][-1]["name"]:
                                all_monitors += " and "
                            self.create_HM(gtm, partition, monitor, config['name'])
                try:
                    self.create_gtm_pool(gtm, partition, config, all_monitors,
                                        skip_member_validation=True)
                    self.create_wideip(gtm, partition, config, newPools)
                except F5CcclError as e:
                    raise e

            log.info("GTM: [SNAPSHOT] Processed {} wideIPs, skipped {} unchanged".format(
                processed, skipped))

            # Step 4: Clean up orphaned pool members using snapshot
            log.debug("GTM: Cleaning up orphaned pool members after create")
            self._cleanup_orphans_with_snapshot(gtm, partition, expected_members, snapshot)

            # Step 5: Clean up orphaned infrastructure
            log.debug("GTM: Cleaning up orphaned infrastructure")
            self._gtm_config[partition] = gtmConfig[partition]
            self._cleanup_infrastructure_from_bigip(gtm, partition, expected_members)

            log.info("GTM: Initial sync complete for partition {} — {} wideIPs ({} processed, {} skipped)".format(
                partition, processed + skipped, processed, skipped))

        except F5CcclError as e:
            log.error("GTM: Error while creating gtm: %s", e)
            raise e
    

        
    def _orchestrate_with_snapshot(self, gtm, partition, gtmConfig, parsed, snapshot):
        """Orchestrate infrastructure using snapshot to skip existing resources."""
        try:
            datacenter_name = gtmConfig[partition].get("dataCenter", None)
            if not datacenter_name:
                raise F5CcclError(msg="GTM: dataCenter not specified for partition {}".format(partition))
            if "/" in datacenter_name:
                datacenter_name = datacenter_name.split("/")[-1]

            self.ensure_datacenter_exists(gtm, datacenter_name)

            dataservers = parsed['dataservers']
            vs_inventory = parsed['vs_inventory']

            if not dataservers:
                return {"datacenter": datacenter_name, "servers": 0, "virtual_servers": 0}

            log.info("GTM: DataServers to process: {}".format(sorted(dataservers)))

            # Create only MISSING servers (use snapshot for existence check)
            created_server_objects = {}
            servers_created = 0
            servers_skipped = 0

            for dataserver_ip in sorted(dataservers):
                server_name = self.format_server_name(dataserver_ip)

                if server_name in snapshot['servers']:
                    # Server exists — load object for VS creation
                    log.debug("GTM: Server {} exists (from snapshot)".format(server_name))
                    created_server_objects[server_name] = gtm.servers.server.load(name=server_name)
                    servers_skipped += 1
                else:
                    # Server doesn't exist — create it
                    server = self.create_gslb_server(
                        gtm=gtm, server_name=server_name,
                        datacenter_name=datacenter_name,
                        addresses=[dataserver_ip], product='bigip',
                        virtual_server_discovery='disabled',
                        monitor='/Common/gateway_icmp')
                    created_server_objects[server_name] = server
                    servers_created += 1

            log.info("GTM: [SNAPSHOT] Servers: {} created, {} skipped (already exist)".format(
                servers_created, servers_skipped))

                # Create only MISSING VSs — lazy load VS names per server
            total_vs_created = 0
            total_vs_skipped = 0

            for server_name, vs_set in vs_inventory.items():
                if server_name not in created_server_objects:
                    continue

                server_obj = created_server_objects[server_name]

                # Lazy VS load: only fetch when we actually need to check
                existing_vs = snapshot['server_vs'].get(server_name, set())
                if not existing_vs:
                    try:
                        existing_vs = {vs.name for vs in server_obj.virtual_servers_s.get_collection()}
                        snapshot['server_vs'][server_name] = existing_vs
                        log.info("GTM: [SNAPSHOT] Lazy-loaded {} VSs for server {}".format(
                            len(existing_vs), server_name))
                    except Exception as e:
                        # CRITICAL: Distinguish transient vs permanent errors
                        # - Transient error on server with 50 VSs → raising is CHEAPER than 100 create calls
                        # - Permanent error (new server, no VSs) → empty set is correct
                        if self._is_transient_error(e):
                            log.warning("GTM: [SNAPSHOT] Transient error fetching VSs for server {}, "
                                       "raising to avoid 100-call amplification: {}".format(
                                server_name, str(e)))
                            raise F5CcclError(
                                msg="VS fetch failed for {}: {}".format(server_name, str(e)))
                        else:
                            log.debug("GTM: [SNAPSHOT] No existing VSs for server {} (permanent error): {}".format(
                                server_name, str(e)))
                            existing_vs = set()

                for member_ip, vs_name, destination in vs_set:
                    if vs_name in existing_vs:
                        total_vs_skipped += 1
                        continue
                    try:
                        self.create_virtual_server_on_gslb_server(
                            gtm=gtm, server_name=server_name,
                            vs_name=vs_name, destination=destination,
                            enabled=True, server_obj=server_obj)
                        total_vs_created += 1
                    except F5CcclError:
                        continue

            log.info("GTM: [SNAPSHOT] VSs: {} created, {} skipped".format(
                total_vs_created, total_vs_skipped))

            return {
                "datacenter": datacenter_name,
                "servers": len(created_server_objects),
                "virtual_servers": total_vs_created + total_vs_skipped
            }

        except Exception as e:
            log.error("GTM: Critical error during infrastructure orchestration: {}".format(str(e)))
            raise F5CcclError(msg="Infrastructure orchestration failed: {}".format(str(e)))
    
    # PERF FIX #8: Single-pass cleanup instead of two separate loops
    def _cleanup_infrastructure_from_bigip(self, gtm, partition, expected_members):
        """Clean up VSs and servers by comparing BIG-IP state with expected config. Single-pass."""
        try:
            all_expected_members = set()
            all_expected_servers = set()
            for pool_name, member_set in expected_members.items():
                all_expected_members.update(member_set)
                for member_ref in member_set:
                    server_name = member_ref.split(':')[0]
                    all_expected_servers.add(server_name)

            log.debug("GTM: Expected members after create: {}".format(all_expected_members))
            log.debug("GTM: Expected servers after create: {}".format(all_expected_servers))

            for server_name in all_expected_servers:
                try:
                    if not gtm.servers.server.exists(name=server_name):
                        continue

                    server = gtm.servers.server.load(name=server_name)

                    vs_list = list(server.virtual_servers_s.get_collection())

                    remaining_vs = []
                    for vs in vs_list:
                        member_ref = "{}:{}".format(server_name, vs.name)
                        if member_ref not in all_expected_members:
                            log.info("GTM: Deleting orphaned VS {} from server {} (restart cleanup)".format(
                                vs.name, server_name))
                            vs.delete()
                        else:
                            remaining_vs.append(vs)

                    if len(remaining_vs) == 0:
                        log.info("GTM: Deleting server {} with no VSs (restart cleanup)".format(
                            server_name))
                        server.delete()

                except Exception as e:
                    log.error("GTM: Error processing server {} during restart cleanup: {}".format(
                        server_name, str(e)))
                    raise F5CcclError(msg="Restart cleanup failed for server {}: {}".format(
                        server_name, str(e)))

        except Exception as e:
            log.error("GTM: Error during infrastructure cleanup from BIG-IP: {}".format(str(e)))
            raise F5CcclError(msg="Infrastructure cleanup from BIG-IP failed: {}".format(str(e)))

    def create_wideip(self, gtm, partition, config, newPools):
        """ Create wideip and returns the wideip object """
        try:
            exist = gtm.wideips.a_s.a.exists(name=config['name'], partition=partition)
            if not exist:
                log.info('GTM: Creating wideip {}'.format(config['name']))
                gtm.wideips.a_s.a.create(
                    name=config['name'],
                    partition=partition, lastResortPool="none", poolLbMode=config['LoadBalancingMode'])
                self.attach_gtm_pool_to_wideip(gtm, config['name'], partition, list(newPools.values()))
            else:
                wideip = gtm.wideips.a_s.a.load(
                    name=config['name'],
                    partition=partition)
                if wideip.poolLbMode != config['LoadBalancingMode']:
                    wideip.poolLbMode = config['LoadBalancingMode']
                    wideip.update()
                duplicatePools = []
                if hasattr(wideip, 'pools'):
                    for p in newPools.keys():
                        if hasattr(wideip.raw['pools'], p):
                            duplicatePools.append(p)

                for poolName in duplicatePools:
                    del newPools[poolName]

                if len(newPools) > 0:
                    self.attach_gtm_pool_to_wideip(
                        gtm,
                        config['name'],
                        partition,
                        list(newPools.values()))
        except F5CcclError as e:
            log.error("GTM: Error while creating wideip: %s", e)
            raise e

    # PERF FIX #3 & #4: skip_member_validation param; batch pool attribute updates
    def create_gtm_pool(self, gtm, partition, config, monitors, skip_member_validation=False):
        """ Create gtm pools """
        try:
            for pool in config['pools']:
                exist = gtm.pools.a_s.a.exists(name=pool['name'], partition=partition)
                if not exist:
                    log.info('GTM: Creating Pool: {}'.format(pool['name']))
                    pl = gtm.pools.a_s.a.create(
                        name=pool['name'],
                        partition=partition,
                        fallbackMode=pool['fallbackMode'],
                        loadBalancingMode=pool['LoadBalancingMode'])
                else:
                    pl = gtm.pools.a_s.a.load(
                        name=pool['name'],
                        partition=partition)

                # PERF FIX #4: Batch attribute updates into a single .update() call
                needs_update = False
                if monitors != "":
                    pl.monitor = monitors
                    needs_update = True
                if pl.fallbackMode != pool['fallbackMode']:
                    pl.fallbackMode = pool['fallbackMode']
                    needs_update = True
                if pl.loadBalancingMode != pool['LoadBalancingMode']:
                    pl.loadBalancingMode = pool['LoadBalancingMode']
                    needs_update = True
                if needs_update:
                    pl.update()
                    log.debug('GTM: Updated pool {} attributes'.format(pool['name']))

                if bool(pool['members']):
                    pool_dataserver = pool.get('DataServer', '')

                    for member_spec in pool['members']:
                        if '|' in member_spec:
                            separator = '|'
                        else:
                            separator = ':'

                        parts = member_spec.split(separator)

                        if len(parts) == 3:
                            dataserver = parts[0]
                            member_ip = parts[1]
                            member_port = parts[2]
                            destination = "{}:{}".format(member_ip, member_port)
                        elif len(parts) == 2:
                            if not pool_dataserver:
                                log.warning("GTM: Member '{}' in pool {} has no DataServer. Skipping.".format(
                                    member_spec, pool['name']))
                                continue
                            dataserver = pool_dataserver
                            member_ip = parts[0]
                            member_port = parts[1]
                            destination = "{}:{}".format(member_ip, member_port)
                        else:
                            log.warning("GTM: Unrecognized member format '{}' in pool {}. Using as-is.".format(
                                member_spec, pool['name']))
                            self.add_member_to_gtm_pool(
                                gtm, pl, pool['name'], member_spec, partition)
                            continue

                        vs_name = "vs-{}".format(
                            destination.replace(".", "-")
                                       .replace(":", "-")
                                       .replace("%", "-")
                        )
                        server_name = self.format_server_name(dataserver)
                        member_name = "{}:{}".format(server_name, vs_name)

                        # PERF FIX #3: Skip validation when infrastructure is already orchestrated
                        self.add_member_to_gtm_pool(
                            gtm, pl, pool['name'], member_name, partition,
                            skip_validation=skip_member_validation)
        except F5CcclError as e:
            log.error("GTM: Error while creating pool: %s", e)
            raise e

    def attach_gtm_pool_to_wideip(self, gtm, name, partition, poolObj):
        """ Attach gtm pool to the wideip """
        try:
            wideip = gtm.wideips.a_s.a.load(name=name, partition=partition)
            if wideip.lastResortPool == "":
                wideip.lastResortPool = "none"
            if hasattr(wideip, 'pools'):
                wideip.pools.extend(poolObj)
                log.info('GTM: Attaching Pool: {} to wideip {}'.format(poolObj, name))
                try:
                    wideip.update()
                except F5CcclError as e:
                    log.error("GTM: Error while Updating gtm pool to wideip: %s", e)
                    raise e
            else:
                wideip.raw['pools'] = poolObj
                log.info('GTM: Attaching Pool: {} to wideip {}'.format(poolObj, name))
                try:
                    wideip.update()
                except F5CcclError as e:
                    log.error("GTM: Error while Updating gtm pool to wideip: %s", e)
                    raise e
        except F5CcclError as e:
            log.error("GTM: Error while attaching gtm pool to wideip: %s", e)
            raise e

    def remove_monitor_from_gtm_pool(self, gtm, partition, poolName, monitorName):
        """ Remove monitor from gtm pool """
        try:
            pool = gtm.pools.a_s.a.load(name=poolName, partition=partition)
            if hasattr(pool, 'monitor'):
                if f"/{partition}/{monitorName}" in pool.monitor:
                    monitors = pool.monitor.split(" and ")
                    monitors.remove(f"/{partition}/{monitorName}")
                    pool.monitor = " and ".join(monitors)
                    pool.update()
                    log.debug("GTM: Detached monitor {} from pool {}".format(monitorName, poolName))
        except F5CcclError as e:
            log.error("Error while removing monitor from pool: %s", e)
            raise e

    # PERF FIX #3: Added skip_validation param to bypass redundant exists/load checks
    def add_member_to_gtm_pool(self, gtm, pool, poolName, memberName, partition,
                               skip_validation=False):
        """ Add member to gtm pool """
        try:
            if not bool(pool):
                pool = gtm.pools.a_s.a.load(name=poolName, partition=partition)

            # PERF FIX #3: Fast path - infrastructure already guaranteed by orchestrate
            if skip_validation:
                try:
                    pool.members_s.member.create(name=memberName, partition="Common")
                    log.info('GTM: Added member {} to pool {}'.format(memberName, poolName))
                except Exception as e:
                    if "already exists" in str(e).lower():
                        log.debug('GTM: Member {} already in pool {}'.format(memberName, poolName))
                    else:
                        raise F5CcclError(msg="Error adding member: {}".format(str(e)))
                return

            # Original validation path (backward compatibility)
            exist = pool.members_s.member.exists(name=memberName)
            if not exist:
                s = memberName.split(":")
                server = s[0].split("/")[-1]
                vs_name = s[1]
                serverExist = gtm.servers.server.exists(name=server)
                if serverExist:
                    sl = gtm.servers.server.load(name=server)
                    vsExist = sl.virtual_servers_s.virtual_server.exists(name=vs_name)
                    if vsExist:
                        pmExist = pool.members_s.member.exists(
                            name=memberName,
                            partition="Common")
                        if not pmExist:
                            pool.members_s.member.create(name=memberName, partition="Common")
                            log.info('GTM: Added member {} to pool {}'.format(memberName, poolName))
                    else:
                        raise F5CcclError(
                            msg="Virtual Server Resource not Available in BIG-IP")
                else:
                    pool = gtm.pools.a_s.a.load(name=poolName, partition=partition)
                    pool.delete()
                    raise F5CcclError(msg="Server Resource not Available in BIG-IP")
        except (F5CcclError) as e:
            log.debug("GTM: Error while adding member to pool.")
            raise e

    # PERF FIX #9: Cache BIG-IP version
    def get_bigip_version(self):
        """Get BIG-IP version with caching.
        
        Returns:
            float: BIG-IP version (e.g., 16.1, 15.1)
            
        Note:
            Version is cached after first call to avoid repeated API requests.
        """
        try:
            if self._bigip_version is None:
                mgmt = self.mgmt_root()
                verList = mgmt.tmos_version.split('.')
                self._bigip_version = float(verList[0] + '.' + verList[1])
            return self._bigip_version
        except F5CcclError as e:
            log.error("GTM: Could not fetch BigipVersion: %s", e)
            raise e

    def create_gslb_server(self, gtm, server_name, datacenter_name, addresses,
                          product='generic-host', virtual_server_discovery='disabled',
                          description=None, monitor=None):
        """ Create GTM GSLB server """
        try:
            server_exists = gtm.servers.server.exists(name=server_name)

            if server_exists:
                log.info("GTM: GSLB Server {} already exists".format(server_name))
                server = gtm.servers.server.load(name=server_name)
            else:
                log.info("GTM: Creating GSLB server {}".format(server_name))

                create_params = {
                    'name': server_name,
                    'datacenter': datacenter_name,
                    'product': product,
                    'virtualServerDiscovery': virtual_server_discovery
                }

                if addresses:
                    if isinstance(addresses[0], dict):
                        create_params['addresses'] = addresses
                    else:
                        create_params['addresses'] = [{'name': addr} for addr in addresses]

                if description:
                    create_params['description'] = description
                if monitor:
                    create_params['monitor'] = monitor

                server = gtm.servers.server.create(**create_params)
                log.info("GTM: GSLB Server {} created successfully".format(server_name))

            return server

        except Exception as e:
            log.error("GTM: Error creating GSLB server {}: {}".format(server_name, str(e)))
            raise F5CcclError(msg="Error creating GSLB server: {}".format(str(e)))

    # PERF FIX #2: Accept pre-loaded server_obj; use try/create pattern
    def create_virtual_server_on_gslb_server(self, gtm, server_name, vs_name,
                                            destination, enabled=True,
                                            translation_address=None,
                                            translation_port=None, monitor=None,
                                            server_obj=None):
        """ Create a virtual server on an existing GSLB server """
        try:
            # PERF FIX #1: Use pre-loaded server object if available
            if server_obj is None:
                server_obj = gtm.servers.server.load(name=server_name)

            create_params = {
                'name': vs_name,
                'destination': destination,
                'enabled': enabled
            }

            if translation_address:
                create_params['translationAddress'] = translation_address
            if translation_port:
                create_params['translationPort'] = translation_port
            if monitor:
                create_params['monitor'] = monitor

            # PERF FIX #2: Use try/create instead of exists+load
            try:
                virtual_server = server_obj.virtual_servers_s.virtual_server.create(**create_params)
                log.info("GTM: Virtual server {} created successfully on server {}".format(
                    vs_name, server_name))
            except Exception as e:
                if "already exists" in str(e).lower():
                    log.info("GTM: Virtual server {} already exists on server {}".format(
                        vs_name, server_name))
                    virtual_server = server_obj.virtual_servers_s.virtual_server.load(name=vs_name)
                else:
                    raise

            return virtual_server

        except Exception as e:
            log.error("GTM: Error creating virtual server {} on server {}: {}".format(
                vs_name, server_name, str(e)))
            raise F5CcclError(msg="Error creating virtual server: {}".format(str(e)))

    def ensure_datacenter_exists(self, gtm, datacenter_name, location=None, contact=None):
        """ Validate that GTM datacenter exists """
        try:
            dc_exists = gtm.datacenters.datacenter.exists(name=datacenter_name)

            if dc_exists:
                log.debug("GTM: Datacenter {} exists".format(datacenter_name))
                datacenter = gtm.datacenters.datacenter.load(name=datacenter_name)
            else:
                error_msg = "GTM: Datacenter '{}' does not exist. Please create it manually before deploying GTM configuration.".format(datacenter_name)
                log.error(error_msg)
                raise F5CcclError(msg=error_msg)

            return datacenter

        except F5CcclError:
            raise
        except Exception as e:
            log.error("GTM: Error checking datacenter {}: {}".format(
                datacenter_name, str(e)))
            raise F5CcclError(msg="Error validating datacenter: {}".format(str(e)))

    def _convert_member_to_bigip_reference(self, member_spec, pool_dataserver=None):
        """Convert config member format to BIG-IP member reference format."""
        dataserver, member_ip, member_port, destination = \
            self._parse_member_spec(member_spec, pool_dataserver)

        if dataserver is None:
            log.error("GTM: Cannot convert member '{}' to BIG-IP reference".format(member_spec))
            return member_spec

        vs_name = self._format_vs_name(destination)
        server_name = self.format_server_name(dataserver)
        member_ref = "{}:{}".format(server_name, vs_name)

        log.debug("GTM: Converted member '{}' to BIG-IP reference '{}'".format(
            member_spec, member_ref))
        return member_ref

    # PERF FIX #1: Cache server objects; batch-check existing VSs per server
    def orchestrate_gtm_infrastructure(self, gtm, partition, gtmConfig, parsed=None):
        """ Orchestrate the creation of GTM infrastructure """
        try:
            log.info("GTM: Starting infrastructure orchestration for partition {}".format(partition))

            if partition not in gtmConfig:
                log.warning("GTM: Partition {} not found in config".format(partition))
                return {}

            datacenter_name = gtmConfig[partition].get("dataCenter", None)
            if not datacenter_name:
                error_msg = "GTM: dataCenter not specified in configuration for partition {}. Please specify a datacenter.".format(partition)
                log.error(error_msg)
                raise F5CcclError(msg=error_msg)
            if "/" in datacenter_name:
                datacenter_name = datacenter_name.split("/")[-1]

            datacenter = self.ensure_datacenter_exists(gtm, datacenter_name)

            if parsed is None:
                parsed = self._parse_gtm_config_once(gtmConfig, partition)

            dataservers = parsed['dataservers']
            vs_inventory = parsed['vs_inventory']

            if not dataservers:
                log.info("GTM: No DataServers found in configuration")
                return {"datacenter": datacenter_name, "servers": 0, "virtual_servers": 0}

            log.info("GTM: DataServers to process: {}".format(sorted(dataservers)))

            # PERF FIX #1: Cache server objects to avoid reloading in Step 5
            created_server_objects = {}
            for dataserver_ip in sorted(dataservers):
                try:
                    server_name = self.format_server_name(dataserver_ip)

                    if gtm.servers.server.exists(name=server_name):
                        log.debug("GTM: Server {} already exists".format(server_name))
                        server = gtm.servers.server.load(name=server_name)
                        created_server_objects[server_name] = server
                    else:
                        log.info("GTM: Creating new GSLB server {} for DataServer {}".format(
                            server_name, dataserver_ip))
                        server = self.create_gslb_server(
                            gtm=gtm,
                            server_name=server_name,
                            datacenter_name=datacenter_name,
                            addresses=[dataserver_ip],
                            product='bigip',
                            virtual_server_discovery='disabled',
                            monitor='/Common/gateway_icmp'
                        )
                        created_server_objects[server_name] = server
                except F5CcclError as e:
                    log.error("GTM: Failed to create/load GSLB server for {}: {}".format(
                        dataserver_ip, str(e)))
                    raise

            log.debug("GTM: Processed {} servers".format(len(created_server_objects)))

            # PERF FIX #1 & #2: Create virtual servers using cached server objects
            total_vs_created = 0
            for server_name, vs_set in vs_inventory.items():
                if server_name not in created_server_objects:
                    log.warning("GTM: Server {} was not created, skipping virtual servers".format(
                        server_name))
                    continue

                server_obj = created_server_objects[server_name]

                # PERF FIX #1: Fetch ALL existing VSs on this server in ONE call
                # CRITICAL: Distinguish transient vs permanent errors
                # - Transient error on server with 50 VSs → raising is CHEAPER than 100 create calls
                # - Permanent error (new server, no VSs) → empty set is correct
                try:
                    existing_vs_names = {vs.name for vs in server_obj.virtual_servers_s.get_collection()}
                except Exception as e:
                    if self._is_transient_error(e):
                        log.warning("GTM: Transient error fetching VSs for server {}, "
                                   "raising to avoid 100-call amplification: {}".format(
                            server_name, str(e)))
                        raise F5CcclError(
                            msg="VS fetch failed for {}: {}".format(server_name, str(e)))
                    else:
                        log.debug("GTM: No existing VSs for server {} (permanent error): {}".format(
                            server_name, str(e)))
                        existing_vs_names = set()

                for member_ip, vs_name, destination in vs_set:
                    # PERF FIX #2: Skip if VS already exists
                    if vs_name in existing_vs_names:
                        log.info("GTM: Virtual server {} already exists on server {}, skipping".format(
                            vs_name, server_name))
                        total_vs_created += 1
                        continue
                    try:
                        self.create_virtual_server_on_gslb_server(
                            gtm=gtm,
                            server_name=server_name,
                            vs_name=vs_name,
                            destination=destination,
                            enabled=True,
                            server_obj=server_obj
                        )
                        total_vs_created += 1
                    except F5CcclError as e:
                        log.error("GTM: Failed to create virtual server {} on {}: {}".format(
                            vs_name, server_name, str(e)))
                        raise

            summary = {
                "datacenter": datacenter_name,
                "servers": len(created_server_objects),
                "virtual_servers": total_vs_created
            }

            log.info("GTM: Infrastructure orchestration complete: {}".format(summary))
            return summary

        except Exception as e:
            log.error("GTM: Critical error during infrastructure orchestration: {}".format(str(e)))
            raise F5CcclError(msg="Infrastructure orchestration failed: {}".format(str(e)))

    def create_HM(self, gtm, partition, monitor, wideIPName):
        """ Create Health Monitor """
        try:
            if bool(monitor):
                if monitor['type'] == "http":
                    exist = gtm.monitor.https.http.exists(
                        name=monitor['name'],
                        partition=partition)
                if monitor['type'] == "https":
                    exist = gtm.monitor.https_s.https.exists(
                        name=monitor['name'],
                        partition=partition)
                if monitor['type'] == "tcp":
                    exist = gtm.monitor.tcps.tcp.exists(
                        name=monitor['name'],
                        partition=partition)
                if not exist:
                    if monitor['type'] == "http":
                        try:
                            gtm.monitor.https.http.create(
                                name=monitor['name'],
                                partition=partition,
                                send=monitor['send'],
                                recv=monitor['recv'],
                                interval=monitor['interval'],
                                timeout=monitor['timeout'])
                        except F5CcclError as e:
                            log.debug("GTM: Error while creating http Health Monitor: %s", e)
                            raise e
                    if monitor['type'] == "https":
                        try:
                            if self.get_bigip_version() >= 16.1:
                                gtm.monitor.https_s.https.create(
                                    name=monitor['name'],
                                    partition=partition,
                                    send=monitor['send'],
                                    recv=monitor['recv'],
                                    sniServerName=wideIPName,
                                    interval=monitor['interval'],
                                    timeout=monitor['timeout'])
                            else:
                                gtm.monitor.https_s.https.create(
                                    name=monitor['name'],
                                    partition=partition,
                                    send=monitor['send'],
                                    recv=monitor['recv'],
                                    interval=monitor['interval'],
                                    timeout=monitor['timeout'])
                        except F5CcclError as e:
                            log.debug("GTM: Error while creating https Health Monitor: %s", e)
                            raise e
                    if monitor['type'] == "tcp":
                        try:
                            gtm.monitor.tcps.tcp.create(
                                name=monitor['name'],
                                partition=partition,
                                interval=monitor['interval'],
                                timeout=monitor['timeout'])
                        except F5CcclError as e:
                            log.debug("GTM: Error while creating tcp Health Monitor: %s", e)
                            raise e
                else:
                    try:
                        if monitor['type'] == "http":
                            obj = gtm.monitor.https.http.load(
                                name=monitor['name'],
                                partition=partition)
                            obj.send = monitor['send']
                            obj.interval = monitor['interval']
                            obj.timeout = monitor['timeout']
                            obj.update()
                            log.debug("GTM: Updated HTTP monitor {}".format(monitor['name']))
                        if monitor['type'] == "https":
                            obj = gtm.monitor.https_s.https.load(
                                name=monitor['name'],
                                partition=partition)
                            obj.send = monitor['send']
                            obj.interval = monitor['interval']
                            obj.timeout = monitor['timeout']
                            if self.get_bigip_version() >= 16.1:
                                obj.sniServerName = wideIPName
                            obj.update()
                            log.debug("GTM: Updated HTTPS monitor {}".format(monitor['name']))
                        if monitor['type'] == "tcp":
                            obj = gtm.monitor.tcps.tcp.load(
                                name=monitor['name'],
                                partition=partition)
                            obj.interval = monitor['interval']
                            obj.timeout = monitor['timeout']
                            obj.update()
                    except F5CcclError as e:
                        log.debug("GTM: Error while Updating Health Monitor: %s", e)
                        raise e
        except F5CcclError as e:
            log.debug("GTM: Error while creating Health Monitor: %s", e)
            raise e

    # PERF FIX #11: Accept optional pre-loaded pool_obj
    def remove_member_to_gtm_pool(self, gtm, partition, poolName, memberName, pool_obj=None):
        """ Remove member from gtm pool """
        try:
            try:
                parts = memberName.split(":")
                if len(parts) >= 2 and "/" in parts[1]:
                    tenant = parts[1].split("/")[1]
                    if tenant not in self._active_tenants + self._deleted_tenants:
                        log.debug("GTM: Not removing the pool member %s as it may not be created by this CIS instance", memberName)
                        return
                else:
                    log.debug("GTM: Removing member {} (new format, no tenant check)".format(memberName))
            except (IndexError, AttributeError):
                log.debug("GTM: Could not parse tenant from member {}, proceeding with removal".format(memberName))

            # PERF FIX #11: Use pre-loaded pool object if available
            if pool_obj is None:
                exist = gtm.pools.a_s.a.exists(name=poolName, partition=partition)
                if not exist:
                    return
                pool_obj = gtm.pools.a_s.a.load(name=poolName, partition=partition)

            if pool_obj.members_s.member.exists(name=memberName, partition="Common"):
                memObj = pool_obj.members_s.member.load(name=memberName, partition="Common")
                memObj.delete()
                log.info("GTM: Member {} deleted from pool {}".format(memberName, poolName))
            else:
                log.debug("GTM: Member {} not found in pool {} (already deleted)".format(memberName, poolName))
        except Exception as e:
            log.error("GTM: Error while removing pool member {}: {}".format(memberName, str(e)))
            raise e

    def remove_gtm_pool_to_wideip(self, gtm, wideipName, partition, poolName):
        """ Remove gtm pool from the wideip """
        try:
            wideip = gtm.wideips.a_s.a.load(name=wideipName, partition=partition)
            if wideip.lastResortPool == "":
                wideip.lastResortPool = "none"
            if hasattr(wideip, 'pools'):
                for pool in wideip.pools:
                    if pool["name"] == poolName:
                        wideip.pools.remove(pool)
                        wideip.update()
                        log.debug("GTM: Removed pool {} from wideIP".format(poolName))
        except F5CcclError as e:
            log.error("GTM: Error while removing pool: %s", e)
            raise e

    # PERF FIX #7: Avoid deep-copying entire config; load pool once
    def delete_gtm_pool(self, gtm, partition, wideipName, poolName, working_config=None):
        """ Delete gtm pools """
        try:
            # Use working_config if provided, otherwise fall back to self._gtm_config
            config = working_config if working_config is not None else self._gtm_config
            wideips = config.get(partition, {}).get('wideIPs', None)
            if wideips is None:
                return

            for index, wideip in enumerate(wideips):
                if wideipName == wideip['name']:
                    for pool_index, pool in enumerate(wideip['pools']):
                        if pool['name'] == poolName and pool['members'] is not None:
                            members_to_remove = list(pool['members'])
                            pool_dataserver = pool.get('DataServer')

                            # PERF FIX #11: Load pool once for all member removals
                            pool_obj = None
                            if gtm.pools.a_s.a.exists(name=poolName, partition=partition):
                                pool_obj = gtm.pools.a_s.a.load(name=poolName, partition=partition)

                            for member in members_to_remove:
                                member_ref = self._convert_member_to_bigip_reference(
                                    member, pool_dataserver)
                                self.remove_member_to_gtm_pool(
                                    gtm,
                                    partition,
                                    poolName,
                                    member_ref,
                                    pool_obj=pool_obj)
                            config[partition]['wideIPs'][index]["pools"][pool_index]['members'] = None
                            break
                    break

            if gtm.pools.a_s.a.exists(name=poolName, partition=partition):
                obj = gtm.pools.a_s.a.load(name=poolName, partition=partition)
                if len(obj.members_s.get_collection()) == 0:
                    self.remove_gtm_pool_to_wideip(gtm,
                        wideipName, partition, poolName)
                    obj.delete()
                    log.info("GTM: Deleted pool {}".format(poolName))
                    config[partition]['wideIPs'][index]["pools"].pop(pool_index)
            else:
                log.info("GTM: Pool {} already deleted".format(poolName))
        except F5CcclError:
            # Re-raise F5CcclError as-is
            raise
        except Exception as e:
            # Check if permanent or transient error
            if self._is_transient_error(e):
                log.error("GTM: Transient error deleting pool {}: {}".format(poolName, str(e)))
                raise F5CcclError(msg="Transient error deleting pool {}: {}".format(poolName, str(e)))
            else:
                # Permanent error - log but DON'T raise
                log.debug("GTM: Permanent error deleting pool {} (treating as success): {}".format(poolName, str(e)))

    def _remove_wideip_from_config(self, config, partition, wideipName):
        """Helper to remove wideIP from internal config structure.
        
        Args:
            config: Config dict to modify (working_config or self._gtm_config)
            partition: BIG-IP partition name
            wideipName: Name of wideIP to remove
        """
        if config.get(partition, {}).get('wideIPs') is not None:
            for index, wip in enumerate(config[partition]['wideIPs']):
                if wideipName == wip['name']:
                    config[partition]['wideIPs'].pop(index)
                    log.debug("GTM: Removed wideIP {} from internal config".format(wideipName))
                    break

    def delete_gtm_wideip(self, gtm, partition, wideipName, working_config=None):
        """ Delete gtm wideip """
        try:
            log.info("GTM: Attempting to delete wideIP {} in partition {}".format(wideipName, partition))
            # Use working_config if provided, otherwise fall back to self._gtm_config
            config = working_config if working_config is not None else self._gtm_config
            
            # CRITICAL FIX: Check existence FIRST before attempting load
            # For deletes, "not found" means the operation already succeeded
            try:
                if not gtm.wideips.a_s.a.exists(name=wideipName, partition=partition):
                    log.info("GTM: WideIP {} already absent, treating delete as success".format(wideipName))
                    self._remove_wideip_from_config(config, partition, wideipName)
                    return  # SUCCESS - resource already in desired state
            except Exception as e:
                # exists() call failed with transient error
                if self._is_transient_error(e):
                    log.warning("GTM: Transient error checking wideIP {} existence: {}".format(wideipName, str(e)))
                    raise F5CcclError(msg="Transient error checking wideIP existence: {}".format(str(e)))
                else:
                    # Permanent error on exists() - treat as "doesn't exist" (success for delete)
                    log.info("GTM: Permanent error checking wideIP {} existence, treating as absent: {}".format(
                        wideipName, str(e)))
                    self._remove_wideip_from_config(config, partition, wideipName)
                    return
            
            # WideIP exists - proceed with load and delete
            try:
                wideip = gtm.wideips.a_s.a.load(
                    name=wideipName,
                    partition=partition)
            except Exception as e:
                # Load failed - check if it's 404 (race condition - deleted between exists and load)
                error_str = str(e).lower()
                if '404' in error_str or 'not found' in error_str:
                    log.info("GTM: WideIP {} deleted between exists and load (404), treating as success".format(wideipName))
                    self._remove_wideip_from_config(config, partition, wideipName)
                    return
                # For other load errors, check if transient
                if self._is_transient_error(e):
                    log.warning("GTM: Transient error loading wideIP {} for deletion: {}".format(wideipName, str(e)))
                    raise F5CcclError(msg="Transient error loading wideIP {}: {}".format(wideipName, str(e)))
                else:
                    log.error("GTM: Permanent error loading wideIP {} for deletion: {}".format(wideipName, str(e)))
                    raise F5CcclError(msg="Permanent error loading wideIP {}: {}".format(wideipName, str(e)))
            
            log.debug("GTM: Loaded wideIP {} for deletion".format(wideipName))
            if wideip.lastResortPool == "":
                wideip.lastResortPool = "none"
            if hasattr(wideip, 'pools') and len(wideip.pools) > 0:
                log.debug("GTM: Cannot delete wideIP {} - pools still attached".format(wideipName))
            else:
                log.info("GTM: No pools attached to wideIP {}, proceeding with deletion".format(wideipName))
                wideip.delete()
                log.info("GTM: Deleted wideIP {}".format(wideipName))
                self._remove_wideip_from_config(config, partition, wideipName)
        except F5CcclError:
            # Re-raise F5CcclError as-is (for retry trigger)
            raise
        except Exception as e:
            # Check if it's a 404 that slipped through
            error_str = str(e).lower()
            if '404' in error_str or 'not found' in error_str:
                log.info("GTM: WideIP {} not found (404), treating delete as success: {}".format(wideipName, str(e)))
                self._remove_wideip_from_config(config, partition, wideipName)
                return  # SUCCESS
            
            # Check if permanent or transient error
            if self._is_transient_error(e):
                log.error("GTM: Transient error during wideIP deletion {}: {}".format(wideipName, str(e)))
                raise F5CcclError(msg="Transient error deleting wideIP {}: {}".format(wideipName, str(e)))
            else:
                # Permanent error - log but DON'T raise (allows operation to continue)
                # For deletes, permanent errors usually mean resource is already gone (desired state)
                log.warning("GTM: Permanent error during wideIP deletion {} (treating as success): {}".format(wideipName, str(e)))
                self._remove_wideip_from_config(config, partition, wideipName)

    def delete_gtm_hm_helper(self, partition, monitorName, working_config=None):
        """Helper function to find monitor location in config structure.
        
        Args:
            partition: BIG-IP partition name
            monitorName: Name of the health monitor to find
            working_config: Optional working config copy (for retry-safety)
            
        Returns:
            tuple: (wideip_index, pool_index, monitor_type) or None if not found
        """
        config = working_config if working_config is not None else self._gtm_config
        searchConfig = copy.deepcopy(config)
        if searchConfig[partition]['wideIPs'] is not None:
            for index, config_item in enumerate(searchConfig[partition]['wideIPs']):
                for pool_index, pool in enumerate(config_item['pools']):
                    if "monitors" in pool.keys():
                        for monitor in pool['monitors']:
                            if monitorName == monitor['name']:
                                return index, pool_index, monitor['type']

    def delete_gtm_hm(self, gtm, partition, monitorName, working_config=None):
        """ Delete gtm health monitor """
        try:
            config = working_config if working_config is not None else self._gtm_config
            wideip_index, pool_index, type = self.delete_gtm_hm_helper(partition, monitorName, working_config=working_config)
            
            try:
                if type == "http":
                    obj = gtm.monitor.https.http.load(
                        name=monitorName,
                        partition=partition)
                    obj.delete()
                    log.info("GTM: Deleted HTTP monitor {}".format(monitorName))
                elif type == "https":
                    obj = gtm.monitor.https_s.https.load(
                        name=monitorName,
                        partition=partition)
                    obj.delete()
                    log.info("GTM: Deleted HTTPS monitor {}".format(monitorName))
                elif type == "tcp":
                    obj = gtm.monitor.tcps.tcp.load(
                        name=monitorName,
                        partition=partition)
                    obj.delete()
                    log.info("GTM: Deleted TCP monitor {}".format(monitorName))
            except Exception as e:
                error_str = str(e).lower()
                if '404' in error_str or 'not found' in error_str:
                    log.info("GTM: Monitor {} already deleted (404)".format(monitorName))
                    # Still update config even though monitor was already gone
                else:
                    # Re-raise for outer handler
                    raise
            
            config[partition]['wideIPs'][wideip_index]["pools"][pool_index].pop("monitor", None)
        except F5CcclError:
            # Re-raise F5CcclError as-is
            raise
        except Exception as e:
            # Check if permanent or transient error
            if self._is_transient_error(e):
                log.error("GTM: Transient error deleting health monitor {}: {}".format(monitorName, str(e)))
                raise F5CcclError(msg="Transient error deleting monitor {}: {}".format(monitorName, str(e)))
            else:
                # Permanent error - log but DON'T raise  
                log.warning("GTM: Permanent error deleting monitor {} (treating as success): {}".format(monitorName, str(e)))

    # PERF FIX: Optimized cleanup - group by server, batch-fetch VSs
    def cleanup_unused_virtual_servers(self, gtm, partition, oldConfig=None, newConfig=None,
                                       old_parsed=None, new_parsed=None):
        """Clean up virtual servers that CCCL created but are no longer referenced."""
        vs_cleanup_errors = []  # Pre-initialize error collection list at method level
        try:
            log.debug("GTM: Starting cleanup of unused virtual servers")

            if oldConfig is None:
                oldConfig = self._gtm_config
            if newConfig is None:
                newConfig = self._gtm_config

            if old_parsed is not None:
                old_members = old_parsed['all_member_refs']
            else:
                old_parsed_data = self._parse_gtm_config_once(oldConfig, partition)
                old_members = old_parsed_data['all_member_refs']

            if new_parsed is not None:
                new_members = new_parsed['all_member_refs']
            else:
                new_parsed_data = self._parse_gtm_config_once(newConfig, partition)
                new_members = new_parsed_data['all_member_refs']

            members_to_delete = old_members - new_members

            if not members_to_delete:
                log.debug("GTM: No unused virtual servers to clean up")
                return

            log.debug("GTM: Members to delete: {}".format(members_to_delete))

            # Group deletions by server name
            deletions_by_server = {}
            for member_ref in members_to_delete:
                parts = member_ref.split(':')
                if len(parts) != 2:
                    continue
                server_name, vs_name = parts[0], parts[1]
                if server_name not in deletions_by_server:
                    deletions_by_server[server_name] = set()
                deletions_by_server[server_name].add(vs_name)

            # Batch-process each server ONCE
            for server_name, vs_names_to_delete in deletions_by_server.items():
                try:
                    if not gtm.servers.server.exists(name=server_name):
                        log.debug("GTM: Server {} does not exist, skipping".format(server_name))
                        continue

                    server = gtm.servers.server.load(name=server_name)

                    all_vs = server.virtual_servers_s.get_collection()

                    vs_by_name = {vs.name: vs for vs in all_vs}

                    deleted_count = 0
                    for vs_name in vs_names_to_delete:
                        if vs_name in vs_by_name:
                            log.info("GTM: Deleting unused virtual server {} from server {}".format(
                                vs_name, server_name))
                            vs_by_name[vs_name].delete()
                            deleted_count += 1
                        else:
                            log.debug("GTM: VS {} not found on server {}, already gone".format(
                                vs_name, server_name))

                    if deleted_count > 0:
                        log.info("GTM: Deleted {} unused virtual server(s) from server {}".format(
                            deleted_count, server_name))

                except Exception as e:
                    log.error("GTM: Error processing server {} for VS cleanup: {}".format(
                        server_name, str(e)))
                    # Collect error with exception object for transient check
                    vs_cleanup_errors.append((server_name, e))

            log.debug("GTM: Completed cleanup of unused virtual servers")

        except Exception as e:
            log.error("GTM: Error during virtual server cleanup: {}".format(str(e)))
            vs_cleanup_errors.append(("ALL", e))
        
        # After all servers processed, only raise if TRANSIENT errors occurred
        # Permanent errors (404, etc.) are logged but don't trigger retry
        transient_errors = []
        for server_name, error in vs_cleanup_errors:
            if self._is_transient_error(error):
                transient_errors.append((server_name, str(error)))
            else:
                log.warning("GTM: Permanent error during VS cleanup for {} (not retrying): {}".format(
                    server_name, str(error)))
        
        if transient_errors:
            error_summary = "; ".join(["{}: {}".format(srv, err) for srv, err in transient_errors])
            raise F5CcclError(msg="VS cleanup failed with transient errors for {} server(s): {}".format(
                len(transient_errors), error_summary))
        
        # Success - log completion
        log.info("GTM: ✓ Virtual server cleanup completed successfully")

    # PERF FIX + DELETE FIX: Batch-fetch servers; also check servers that lost all VSs
    def cleanup_unused_gslb_servers(self, gtm, datacenter_name=None, oldConfig=None, newConfig=None,
                                    old_parsed=None, new_parsed=None):
        """Clean up GSLB servers that CCCL created but have no virtual servers."""
        try:
            log.debug("GTM: Starting cleanup of unused GSLB servers")

            if oldConfig is None:
                oldConfig = self._gtm_config
            if newConfig is None:
                newConfig = self._gtm_config

            if old_parsed is not None:
                old_servers = old_parsed['all_server_names']
            else:
                old_parsed_data = self._parse_gtm_config_once(
                    oldConfig, list(oldConfig.keys())[0] if oldConfig else "Common")
                old_servers = old_parsed_data['all_server_names']

            if new_parsed is not None:
                new_servers = new_parsed['all_server_names']
            else:
                new_parsed_data = self._parse_gtm_config_once(
                    newConfig, list(newConfig.keys())[0] if newConfig else "Common")
                new_servers = new_parsed_data['all_server_names']

            # DELETE FIX: Check ALL old servers, not just ones missing from new config.
            # After VS cleanup, a server still in new_servers may now have 0 VSs.
            servers_to_check = old_servers.copy()

            if not servers_to_check:
                log.debug("GTM: No GSLB servers to check for cleanup")
                return

            log.debug("GTM: Servers to check for cleanup: {}".format(servers_to_check))

            # Batch-fetch ALL servers in ONE API call
            all_bigip_servers = gtm.servers.get_collection()

            servers_by_name = {s.name: s for s in all_bigip_servers}

            if datacenter_name:
                servers_by_name = {
                    name: srv for name, srv in servers_by_name.items()
                    if getattr(srv, 'datacenter', '').split('/')[-1] == datacenter_name
                }

            deleted_count = 0
            server_cleanup_errors = []
            for server_name in servers_to_check:
                if server_name not in servers_by_name:
                    log.debug("GTM: Server {} not found on BIG-IP, skipping".format(server_name))
                    continue

                server = servers_by_name[server_name]

                try:
                    vs_list = list(server.virtual_servers_s.get_collection())
                    vs_count = len(vs_list)

                    if vs_count == 0:
                        if server_name not in new_servers:
                            # Server removed from config entirely
                            log.info("GTM: Deleting unused GSLB server {} (removed from config)".format(
                                server_name))
                            server.delete()
                            deleted_count += 1
                        else:
                            # DELETE FIX: Still in config but has no VSs left (all were cleaned up)
                            log.info("GTM: Deleting GSLB server {} (no virtual servers remaining)".format(
                                server_name))
                            server.delete()
                            deleted_count += 1
                    else:
                        log.debug("GTM: Server {} has {} VSs, keeping it".format(
                            server_name, vs_count))

                except Exception as e:
                    log.error("GTM: Error checking/deleting server {}: {}".format(
                        server_name, str(e)))
                    # Collect error with exception object for transient check
                    server_cleanup_errors.append((server_name, e))

            if deleted_count > 0:
                log.info("GTM: Deleted {} unused GSLB server(s)".format(deleted_count))
            
            # After all servers processed, only raise if TRANSIENT errors occurred
            # Permanent errors (404, etc.) are logged but don't trigger retry
            transient_errors = []
            for server_name, error in server_cleanup_errors:
                if self._is_transient_error(error):
                    transient_errors.append((server_name, str(error)))
                else:
                    log.warning("GTM: Permanent error during server cleanup for {} (not retrying): {}".format(
                        server_name, str(error)))
            
            if transient_errors:
                error_summary = "; ".join(["{}: {}".format(srv, err) for srv, err in transient_errors])
                raise F5CcclError(msg="GSLB server cleanup failed with transient errors for {} server(s): {}".format(
                    len(transient_errors), error_summary))
            
            # Success - log completion
            log.info("GTM: ✓ GSLB server cleanup completed successfully ✓")

        except F5CcclError:
            # Re-raise F5CcclError as-is (already formatted)
            raise
        except Exception as e:
            # Check if this outer error is transient
            if self._is_transient_error(e):
                log.error("GTM: Transient error during GSLB server cleanup: {}".format(str(e)))
                raise F5CcclError(msg="GSLB server cleanup failed: {}".format(str(e)))
            else:
                log.warning("GTM: Permanent error during GSLB server cleanup (not retrying): {}".format(str(e)))

    def retry_pending_cleanup(self, gtm):
        """Retry cleanup operations that failed in a previous operation.
        
        This method is called on retry when isConfigSame == True but there's
        pending cleanup work from a transient error in the previous attempt.
        """
        if self._pending_cleanup is None:
            log.debug("GTM: No pending cleanup to retry")
            return
        
        log.info("GTM: Retrying pending cleanup operations")
        cleanup_state = self._pending_cleanup
        partition = cleanup_state['partition']
        oldConfig = cleanup_state['oldConfig']
        target_config = cleanup_state['target_config']
        old_parsed = cleanup_state['old_parsed']
        new_parsed = cleanup_state['new_parsed']
        datacenter_name = cleanup_state['datacenter_name']
        
        vs_cleanup_error = None
        server_cleanup_error = None
        
        # Retry VS cleanup
        try:
            log.info("GTM: Retrying VS cleanup")
            self.cleanup_unused_virtual_servers(gtm, partition, oldConfig, target_config,
                                               old_parsed=old_parsed, new_parsed=new_parsed)
        except Exception as e:
            log.error("GTM: VS cleanup retry failed, will still attempt server cleanup: %s", e)
            vs_cleanup_error = e
        
        # Retry GSLB server cleanup
        try:
            log.info("GTM: Retrying GSLB server cleanup")
            self.cleanup_unused_gslb_servers(gtm, datacenter_name, oldConfig, target_config,
                                            old_parsed=old_parsed, new_parsed=new_parsed)
        except Exception as e:
            log.error("GTM: GSLB server cleanup retry failed: %s", e)
            server_cleanup_error = e
        
        # If successful, clear pending state
        if not vs_cleanup_error and not server_cleanup_error:
            self._pending_cleanup = None
            log.info("GTM: ✓✓✓ Pending cleanup retry completed successfully ✓✓✓")
            return
        
        # If still failing, re-raise (will trigger another retry with backoff)
        # pending_cleanup state remains for next retry
        if vs_cleanup_error:
            raise F5CcclError(msg="VS cleanup retry failed: {}".format(str(vs_cleanup_error)))
        if server_cleanup_error:
            raise F5CcclError(msg="GSLB server cleanup retry failed: {}".format(str(server_cleanup_error)))

    # PERF FIX #10: Use dict indexing for O(1) lookups
    def process_config(self, d1, d2):
        """ Process old and new config """

        def _index_by_name(lst):
            return {item["name"]: item for item in lst}

        def _get_value(d, k):
            if d[k] is None:
                return dict()
            return d[k]

        def _get_crud_wide_ips(d1, d2):
            wips1 = _get_value(d1, "wideIPs")
            wips2 = _get_value(d2, "wideIPs")
            wip_set1 = set([v["name"] for v in wips1])
            wip_set2 = set([v["name"] for v in wips2])

            del_wips = list(wip_set1 - wip_set2)
            new_wips = list(wip_set2 - wip_set1)
            cur_wips = wip_set1.intersection(wip_set2)
            update_wips = []

            wip_index1 = _index_by_name(wips1)
            wip_index2 = _index_by_name(wips2)

            for wip_name in cur_wips:
                if wip_index1[wip_name] != wip_index2[wip_name]:
                    update_wips.append(wip_name)

            return new_wips, del_wips, update_wips

        def _get_crud_pools(d1, d2):
            pools1 = []
            pools2 = []
            for wip in _get_value(d1, "wideIPs"):
                pools1 += wip["pools"]
            for wip in _get_value(d2, "wideIPs"):
                pools2 += wip["pools"]

            pool_set1 = set([p["name"] for p in pools1])
            pool_set2 = set([p["name"] for p in pools2])

            new_pools = list(pool_set2 - pool_set1)
            del_pools = list(pool_set1 - pool_set2)
            cur_pools = pool_set1.intersection(pool_set2)
            update_pools = []

            pool_index1 = _index_by_name(pools1)
            pool_index2 = _index_by_name(pools2)

            for pool_name in cur_pools:
                if pool_index1[pool_name] != pool_index2[pool_name]:
                    update_pools.append(pool_name)

            return new_pools, del_pools, update_pools

        def _get_crud_monitors(d1, d2):
            pools1 = []
            pools2 = []
            for wip in _get_value(d1, "wideIPs"):
                pools1 += wip["pools"]
            for wip in _get_value(d2, "wideIPs"):
                pools2 += wip["pools"]

            monitors1, monitors2 = [], []
            for p in pools1:
                if p.get("monitors"):
                    monitors1 += p["monitors"]
            for p in pools2:
                if p.get("monitors"):
                    monitors2 += p["monitors"]

            mon_set1 = set([m["name"] for m in monitors1])
            mon_set2 = set([m["name"] for m in monitors2])

            new_mons = list(mon_set2 - mon_set1)
            del_mons = list(mon_set1 - mon_set2)
            cur_mons = mon_set1.intersection(mon_set2)
            update_mons = []

            mon_index1 = _index_by_name(monitors1)
            mon_index2 = _index_by_name(monitors2)

            for mon_name in cur_mons:
                if mon_index1[mon_name] != mon_index2[mon_name]:
                    update_mons.append(mon_name)

            return new_mons, del_mons, update_mons

        new_wips, del_wips, update_wips = _get_crud_wide_ips(d1, d2)
        new_pools, del_pools, update_pools = _get_crud_pools(d1, d2)
        new_mons, del_mons, update_mons = _get_crud_monitors(d1, d2)

        return {
            "create": {
                "wideIPs": new_wips,
                "pools": new_pools,
                "monitors": new_mons
            },
            "delete": {
                "wideIPs": del_wips,
                "pools": del_pools,
                "monitors": del_mons
            },
            "update": {
                "wideIPs": update_wips,
                "pools": update_pools,
                "monitors": update_mons
            }
        }

    def create_reverse_map(self, d):
        """Create reverse mapping of pools/monitors to their parent wideIPs.
        
        Args:
            d: GTM config dictionary for a partition
            
        Returns:
            dict: Reverse mapping with structure:
                  {'pools': {pool_name: [wideip_names]},
                   'monitors': {monitor_name: pool_name}}
                   
        Note:
            Used during delete operations to find which wideIPs contain
            deleted pools/monitors.
        """
        rev_map = dict()
        rev_map["pools"] = dict()
        rev_map["monitors"] = dict()
        if d["wideIPs"] is None:
            di = dict()
        else:
            di = d["wideIPs"]
        for wip in di:
            wip_name = wip["name"]
            for pool in wip["pools"]:
                pool_name = pool["name"]
                try:
                    rev_map["pools"][pool_name].append(wip_name)
                except:
                    rev_map["pools"][pool_name] = [wip_name]

                try:
                    for monitor in pool["monitors"]:
                        rev_map["monitors"][monitor["name"]] = pool_name
                except:
                    pass
        return rev_map


def _parse_config(config_file):
    def _file_exist_cb(log_success):
        if os.path.exists(config_file):
            if log_success:
                log.info('Config file: {} found'.format(config_file))
            return (True, None)
        else:
            return (False, 'Waiting for config file {}'.format(config_file))
    _retry_backoff(_file_exist_cb)

    with open(config_file, 'r') as config:
        fcntl.lockf(config.fileno(), fcntl.LOCK_SH, 0, 0, 0)
        data = config.read()
        fcntl.lockf(config.fileno(), fcntl.LOCK_UN, 0, 0, 0)
        config_json = json.loads(data)
        log.debug('loaded configuration file successfully')
        return config_json


def _handle_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
            '--config-file',
            type=str,
            required=True,
            help='BigIp configuration file')
    parser.add_argument(
        '--ctlr-prefix',
        type=str,
        required=True,
        help='Controller name prefix'
    )
    args = parser.parse_args()

    basename = os.path.basename(args.config_file)
    if not basename or 0 == len(basename):
        raise ConfigError('must provide a file path')

    args.config_file = os.path.realpath(args.config_file)

    return args


def _handle_global_config(config):
    level = DEFAULT_LOG_LEVEL
    verify_interval = DEFAULT_VERIFY_INTERVAL

    if config and 'global' in config:
        global_cfg = config['global']

        if 'log-level' in global_cfg:
            log_level = global_cfg['log-level']
            try:
                level = logging.getLevelName(log_level.upper())
            except (AttributeError):
                log.warn('The "global:log-level" field in the configuration '
                         'file should be a string')

        if 'verify-interval' in global_cfg:
            try:
                verify_interval = float(global_cfg['verify-interval'])
                if verify_interval < 0:
                    verify_interval = DEFAULT_VERIFY_INTERVAL
                    log.warn('The "global:verify-interval" field in the '
                             'configuration file should be a non-negative '
                             'number')
            except (ValueError):
                log.warn('The "global:verify-interval" field in the '
                         'configuration file should be a number')

        vxlan_partition = global_cfg.get('vxlan-partition')

    try:
        root_logger.setLevel(level)
        if level > logging.DEBUG:
            logging.getLogger('requests.packages.urllib3.'
                              'connectionpool').setLevel(logging.WARNING)
    except:
        level = DEFAULT_LOG_LEVEL
        root_logger.setLevel(level)
        if level > logging.DEBUG:
            logging.getLogger('requests.packages.urllib3.'
                              'connectionpool').setLevel(logging.WARNING)
        log.warn('Undefined value specified for the '
                 '"global:log-level" field in the configuration file')

    return verify_interval, level, vxlan_partition


def get_credentials():
    """
    Unified function to retrieve credentials.
    First tries Unix socket, then falls back to environment variables.
    """
    credentials = get_credentials_from_socket()
    if credentials:
        return credentials

    credential_sources = tuple()
    if not credentials or not credentials.get("bigip_username", ""):
        credential_sources = credential_sources + (('bigip', get_credentials_from_env),)

    if not credentials or not credentials.get("gtm_username", ""):
        credential_sources = credential_sources + (('gtm', get_gtm_credentials_from_env),)

    credentials = {}
    for prefix, fetch_func in credential_sources:
        env_credentials = fetch_func()
        if env_credentials:
            username, password = env_credentials
            credentials[f'{prefix}_username'] = username
            credentials[f'{prefix}_password'] = password

    if not credentials.get("gtm_username", ""):
        credentials["gtm_username"] = credentials["bigip_username"]
    if not credentials.get("gtm_password", ""):
        credentials["gtm_password"] = credentials["bigip_password"]

    return credentials


def get_credentials_from_env():
    log.debug("Checking for credentials in environment variables...")
    username = os.getenv("BIGIP_USERNAME")
    password = os.getenv("BIGIP_PASSWORD")

    if username and password:
        log.info("successfully fetched BIGIP credentials from environment variables.")
        return username, password
    else:
        log.error("Failed to get BIGIP credentials from environment variables.")
        return None


def get_gtm_credentials_from_env():
    log.debug("Checking for GTM credentials in environment variables...")
    username = os.getenv("GTM_BIGIP_USERNAME")
    password = os.getenv("GTM_BIGIP_PASSWORD")

    if username and password:
        log.info("successfully fetched GTM credentials from environment variables.")
        return username, password
    else:
        log.error("Failed to get GTM credentials from environment variables.")
        return None


def get_credentials_from_socket():
    socket_path = "/tmp/secure_cis.sock"
    client = None

    if not os.path.exists(socket_path):
        log.error(f"Socket file not found: {socket_path}")
        return None
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(socket_path)
        log.info("Connected to server.")

        data = client.recv(4096).decode('utf-8')
        credentials = json.loads(data)
        if credentials:
            if credentials.get('bigip_username', '') != "" and credentials.get('bigip_password', '') != "":
                log.info("successfully fetched BIGIP credentials from socket.")
            if credentials.get('gtm_username', '') != "" and credentials.get('gtm_password', '') != "":
                log.info("successfully fetched GTM credentials from socket.")
        return credentials

    except ConnectionError as e:
        log.error(f"Connection failed: {e}")
    finally:
        client.close()


def _handle_bigip_config(config):
    if (not config) or ('bigip' not in config):
        raise ConfigError('Configuration file missing "bigip" section')
    bigip = config['bigip']
    if 'url' not in bigip:
        raise ConfigError('Configuration file missing "bigip:url" section')
    if ('partitions' not in bigip) or (len(bigip['partitions']) == 0):
        raise ConfigError('Configuration file must specify at least one '
                          'partition in the "bigip:partitions" section')

    if 'username' not in config['bigip']:
        raise ConfigError('missing config '
                          '"bigip:username" section')
    if 'password' not in config['bigip']:
        raise ConfigError('missing config '
                          '"bigip:password" section')

    url = urlparse(bigip['url'])
    host = url.hostname
    port = url.port
    if not port:
        port = 443

    return host, port


def _handle_credentials(config):
    credentials = get_credentials()
    if credentials:
        config['bigip']['username'] = credentials.get('bigip_username', '')
        config['bigip']['password'] = credentials.get('bigip_password', '')
        if 'gtm_bigip' in config:
            config['gtm_bigip']['username'] = credentials.get('gtm_username', '')
            config['gtm_bigip']['password'] = credentials.get('gtm_password', '')
    else:
        log.error("Failed to retrieve credentials.")
    return config


def _handle_vxlan_config(config):
    if config and 'vxlan-fdb' in config:
        fdb = config['vxlan-fdb']
        if 'name' not in fdb:
            raise ConfigError('Configuration file missing '
                              '"vxlan-fdb:name" section')
        if 'records' not in fdb:
            raise ConfigError('Configuration file missing '
                              '"vxlan-fdb:records" section')
    if config and 'vxlan-arp' in config:
        arp = config['vxlan-arp']
        if 'arps' not in arp:
            raise ConfigError('Configuration file missing '
                              '"vxlan-arp:arps" section')

    if config and 'static-routes' in config:
        route = config['static-routes']
        if 'routes' not in route:
            raise ConfigError('Configuration file missing '
                              '"static-routes:routes" section')


def _set_user_agent(prefix):
    try:
        with open('/app/vendor/src/f5/VERSION_BUILD.json', 'r') \
                as version_file:
            data = json.load(version_file)
            user_agent = \
                prefix + "-bigip-ctlr-" + data['version'] + '-' + data['build']
    except Exception as e:
        user_agent = prefix + "-bigip-ctlr-VERSION-UNKNOWN"
        log.error("Could not read version file: %s", e)

    return user_agent


def _retry_backoff(cb):
    RETRY_INTERVAL = 1
    log_interval = 0.5
    elapsed = 0.5
    log_success = False
    while 1:
        if log_interval > 0.5:
            log_success = True
        (success, val) = cb(log_success)
        if success:
            return val
        if elapsed == log_interval:
            elapsed = 0
            log_interval *= 2
            log.error("Encountered error: {}. Retrying for {} seconds.".format(
                val, int(log_interval)
            ))
        time.sleep(RETRY_INTERVAL)
        elapsed += RETRY_INTERVAL


def _find_net_schema():
    paths = [path for path in sys.path if 'site-packages' in path]
    for path in paths:
        for root, dirs, files in os.walk(path):
            if NET_SCHEMA_NAME in files:
                return os.path.join(root, NET_SCHEMA_NAME)
    for root, dirs, files in os.walk('/app/src/f5-cccl'):
        if NET_SCHEMA_NAME in files:
            return os.path.join(root, NET_SCHEMA_NAME)
    log.info('Could not find CCCL schema: {}'.format(NET_SCHEMA_NAME))
    return ''


def _is_ltm_disabled(config):
    try:
        return config['global']['disable-ltm']
    except KeyError:
        return False


def _is_arp_disabled(config):
    try:
        return config['global']['disable-arp']
    except KeyError:
        return False


def _is_gtm_config(config):
    try:
        return config['global']['gtm']
    except KeyError:
        return False


def _is_static_routing_enabled(config):
    try:
        return config['global']['static-route-mode']
    except KeyError:
        return False


def _is_cis_secondary(config):
    try:
        return config['global']['multi-cluster-mode'] == "secondary"
    except KeyError:
        return False


def _is_cis_in_arbitrator_mode(config):
    try:
        return config['global']['multi-cluster-mode'] == "arbitrator"
    except KeyError:
        return False


def _is_leader(config):
    try:
        return config['is-leader']
    except KeyError:
        return False


def _is_primary_cluster_status_up(config):
    try:
        return config['primary-cluster-status']
    except KeyError:
        return False


def main():
    try:
        args = _handle_args()

        config = _parse_config(args.config_file)
        verify_interval, _, vxlan_partition = _handle_global_config(config)
        config = _handle_credentials(config)
        host, port = _handle_bigip_config(config)

        # BIG-IP to manage
        def _bigip_connect_cb(log_success):
            try:
                bigip = mgmt_root(
                    host,
                    config['bigip']['username'],
                    config['bigip']['password'],
                    port,
                    "tmos")
                if log_success:
                    log.info('BIG-IP connection established.')
                return (True, bigip)
            except Exception as e:
                return (False, 'BIG-IP connection error: {}'.format(e))
        bigip = _retry_backoff(_bigip_connect_cb)

        user_agent = _set_user_agent(args.ctlr_prefix)

        # GTM BIG-IP to manage
        def _gtmbigip_connect_cb(log_success):
            url = urlparse(config['gtm_bigip']['url'])
            host = url.hostname
            port = url.port
            if not port:
                port = 443
            try:
                bigip = mgmt_root(
                    host,
                    config['gtm_bigip']['username'],
                    config['gtm_bigip']['password'],
                    port,
                    "tmos")
                if log_success:
                    log.info('GTM BIG-IP connection established.')
                return (True, bigip)
            except Exception as e:
                return (False, 'GTM BIG-IP connection error: {}'.format(e))

        managers = []
        if not _is_ltm_disabled(config):
            for partition in config['bigip']['partitions']:
                manager = CloudServiceManager(
                    bigip,
                    partition,
                    user_agent=user_agent)
                managers.append(manager)
        if vxlan_partition:
            manager = CloudServiceManager(
                bigip,
                vxlan_partition,
                user_agent=user_agent,
                prefix=args.ctlr_prefix,
                schema_path=_find_net_schema())
            managers.append(manager)
        if _is_gtm_config(config):
            if "gtm_bigip" in config:
                gtmbigip = _retry_backoff(_gtmbigip_connect_cb)
            else:
                gtmbigip = _retry_backoff(_bigip_connect_cb)
                log.info("GTM: Missing gtm_bigip section on config.")
            for partition in config['bigip']['partitions']:
                manager = CloudServiceManager(
                    gtmbigip,
                    partition,
                    user_agent=user_agent,
                    gtm=True)
                managers.append(manager)

        handler = ConfigHandler(args.config_file,
                                managers,
                                verify_interval)

        if os.path.exists(args.config_file):
            handler.notify_reset()

        watcher = ConfigWatcher(args.config_file, handler.notify_reset)
        watcher.loop()
        handler.stop()
    except (IOError, ValueError, ConfigError) as e:
        log.error(e)
        sys.exit(1)
    except Exception as e:
        log.exception(f'Unexpected error: {str(e)}')
        sys.exit(1)

    return 0


if __name__ == "__main__":
    main()