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
from f5_ctlr_agent.gtm.utils import GTMUtils
from f5_ctlr_agent.gtm.snapshot import GTMSnapshot
from f5_ctlr_agent.gtm.infrastructure import GTMInfrastructure
from f5_ctlr_agent.gtm.wideip import GTMWideIP
from f5_ctlr_agent.gtm.pool import GTMPool
from f5_ctlr_agent.gtm.monitor import GTMMonitor
from f5_ctlr_agent.gtm.cleanup import GTMCleanup

log = logging.getLogger(__name__)
console = logging.StreamHandler()
console.setFormatter(
    logging.Formatter("[%(asctime)s %(name)s %(levelname)s] %(message)s"))
root_logger = logging.getLogger()
root_logger.addHandler(console)

# Set default level BEFORE GTM module imports so early init logs are visible
# _handle_global_config() will override this later with the configured level
DEFAULT_LOG_LEVEL = logging.INFO
root_logger.setLevel(DEFAULT_LOG_LEVEL)


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
                 schema_path=None, gtm=False, local_cluster_name=None):
        """Initialize the CloudServiceManager object."""
        self._mgmt_root = bigip
        self._schema = schema_path
        self._is_gtm = gtm
        if gtm:
            self._gtm = GTMManager(
                bigip,
                partition,
                user_agent=user_agent,
                local_cluster_name=local_cluster_name)
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
                        GTMUtils.pre_process_gtm(newGtmConfig)
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

    def __init__(self, bigip, partition, user_agent=None, local_cluster_name=None):
        """Initialize an instance of the F5 CCCL service manager."""
        log.debug("F5GTMManager initialize")

        if user_agent is not None:
            bigip.icrs.append_user_agent(user_agent)
        self._user_agent = user_agent
        self._mgmt_root = bigip
        self._partition = "Common"  # GTM operates in Common partition only
        self._gtm_config = {}
        self._active_tenants = []
        self._deleted_tenants = []
        self._gtm = bigip.tm.gtm
        self._local_cluster_name = local_cluster_name or ""
        # PERF FIX #9: Cache BIG-IP version once
        self._bigip_version = None
        # RETRY FIX: Track pending cleanup state for isConfigSame retry scenario
        self._pending_cleanup = None
        
        # Initialize GTM component modules for modular architecture
        self._snapshot_helper = GTMSnapshot(
            self._gtm,
            self._partition,
            local_cluster_name=self._local_cluster_name)
        self._infrastructure = GTMInfrastructure(
            self._gtm,
            self._partition,
            local_cluster_name=self._local_cluster_name)
        self._wideip = GTMWideIP(
            self._gtm,
            self._partition,
            local_cluster_name=self._local_cluster_name)
        self._pool = GTMPool(
            self._gtm,
            self._partition,
            self._active_tenants,
            self._deleted_tenants,
            local_cluster_name=self._local_cluster_name)
        self._monitor = GTMMonitor(
            self._gtm,
            self._partition,
            bigip_version_getter=self.get_bigip_version,
            local_cluster_name=self._local_cluster_name)
        self._cleanup = GTMCleanup(
            self._gtm,
            self._partition,
            pool_manager=self._pool,
            local_cluster_name=self._local_cluster_name)

    def get_gtm_config(self):
        """ Return the GTM config object"""
        return self._gtm_config

    def replace_gtm_config(self, config):
        """ Updating the GTM config object"""
        self._active_tenants = config["activeTenants"]
        self._deleted_tenants = []
        self._gtm_config = config["config"]
        
        # Update pool component with new tenant lists
        self._pool._active_tenants = self._active_tenants
        self._pool._deleted_tenants = self._deleted_tenants

    def mgmt_root(self):
        """ Return the BIG-IP ManagementRoot object"""
        return self._mgmt_root

    def gtm(self):
        """Return the GTM object for API operations."""
        return self._gtm

    def get_partition(self):
        """ Return the managed partition."""
        return self._partition
    
    def retry_pending_cleanup(self, gtm):
        """Retry cleanup operations that failed in a previous operation.
        
        This method is called when _pending_cleanup is not None, indicating
        that a previous cleanup operation (VS or GSLB server cleanup) failed.
        
        Args:
            gtm: BIG-IP GTM object (unused, kept for backward compatibility)
        
        Raises:
            F5CcclError: On retry failure
        """
        if self._pending_cleanup is None:
            log.debug("GTM: No pending cleanup to retry")
            return
        
        try:
            self._cleanup.retry_pending_cleanup(self._pending_cleanup)
            # Clear pending state on success
            self._pending_cleanup = None
            log.info("GTM: Pending cleanup retry succeeded")
        except F5CcclError as e:
            log.error("GTM: Pending cleanup retry failed: %s", e)
            raise e

    def delete_update_gtm(self, partition, gtmConfig):
        """ Update GTM object in BIG-IP """
        try:
            oldConfig = self._gtm_config
            mgmt = self.mgmt_root()
            gtm = mgmt.tm.gtm
            if partition in oldConfig and partition in gtmConfig:
                opr_config = GTMUtils.process_config(oldConfig[partition], gtmConfig[partition])
                rev_map = GTMUtils.create_reverse_map(oldConfig[partition])
                
                for opr in opr_config:
                    if opr == "delete":
                        # DELETE FIX: No longer passing incoming_config;
                        # handle_operation_delete builds target config internally
                        self.handle_operation_delete(gtm, partition, opr_config[opr], rev_map)
                        
                        # PENDING CLEANUP FIX: Process any pending cleanup from delete BEFORE create runs
                        # This prevents create operation from overwriting delete's pending cleanup state
                        if self._pending_cleanup is not None:
                            log.info("GTM: Processing pending delete cleanup before create operation")
                            self._cleanup.retry_pending_cleanup(self._pending_cleanup)
                            # Clear pending state on success
                            self._pending_cleanup = None
                    
                    if opr == "create" or opr == "update":
                        self.handle_operation_create(gtm, partition, gtmConfig, opr_config[opr], opr)
        except F5CcclError as e:
            raise e

    # DELETE FIX: Build post-delete target config to correctly identify servers/VSs to remove
    def handle_operation_delete(self, gtm, partition, opr_config, rev_map):
        """ Handle delete operation """
        # RETRY FIX: Work on a deep copy of config; only commit at the end if all steps succeed
        # This prevents partial mutations from making retry think config is already applied
        working_config = copy.deepcopy(self._gtm_config)
        
        try:
            # Save old config before making changes
            oldConfig = self._gtm_config

            # Parse OLD config
            log.debug("GTM: Parsing configs for delete operation cleanup")
            old_parsed = GTMUtils.parse_gtm_config_once(
                oldConfig, partition, local_cluster_name=self._local_cluster_name)

            # DELETE FIX: Build the post-delete target config by removing
            # deleted resources from a copy of the old config.
            # This ensures new_parsed correctly reflects what SHOULD exist
            # after deletions, so cleanup methods can diff properly.
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

            # Parse TARGET config (what should exist AFTER deletions)
            new_parsed = GTMUtils.parse_gtm_config_once(
                target_config, partition, local_cluster_name=self._local_cluster_name)

            # Step 1: Delete monitors
            if len(opr_config["monitors"]) > 0:
                for monitor in opr_config["monitors"]:
                    poolName = rev_map["monitors"][monitor]
                    self._pool.remove_monitor_from_pool(poolName, monitor)
                    # Get monitor type and delete
                    result = GTMUtils.find_monitor_in_config(working_config, partition, monitor)
                    if result:
                        wideip_index, pool_index, monitor_type = result
                        self._monitor.delete_monitor(monitor, monitor_type)
                        working_config[partition]['wideIPs'][wideip_index]["pools"][pool_index].pop("monitor", None)

            # Step 2: Delete pools (this also removes members)
            # Pass working_config so mutations go to the copy, not self._gtm_config
            if len(opr_config["pools"]) > 0:
                for pool in opr_config["pools"]:
                    wideipForPoolDeleted = rev_map["pools"][pool]
                    for wideip in wideipForPoolDeleted:
                        # Delete pool first (removes members internally), then detach from wideIP
                        self._pool.delete_pool(wideip, pool, working_config=working_config)
                        self._wideip.remove_pool_from_wideip(wideip, pool)

            # Step 3: Delete wideIPs
            # Pass working_config so mutations go to the copy, not self._gtm_config
            if len(opr_config["wideIPs"]) > 0:
                for wideip in opr_config["wideIPs"]:
                    result = self._wideip.delete_wideip(wideip, working_config=working_config)
                    if result:
                        self._remove_wideip_from_config(working_config, partition, wideip)

        except F5CcclError as e:
            log.error("GTM: Error while handling delete operation (Steps 1-3): %s", e)
            # Do NOT commit working_config; self._gtm_config remains unchanged for retry
            raise e

        # CRITICAL FIX: Commit BEFORE cleanup phase
        # This ensures successful deletes are recorded even if cleanup fails
        self._gtm_config = working_config
        log.debug("GTM: Committed config changes after successful delete operation")

        # Step 4: Clean up unused virtual servers using target_config
        # RESILIENCE FIX: Separate try block so GSLB server cleanup always runs
        # Errors here trigger retry but the successful delete work is already saved
        vs_cleanup_error = None
        datacenter_name = None
        if partition in target_config:
            datacenter_name = target_config[partition].get('dataCenter', None)
            if datacenter_name and '/' in datacenter_name:
                datacenter_name = datacenter_name.split('/')[-1]
        
        try:
            log.info("GTM: Cleaning up unused virtual servers")
            self._cleanup.cleanup_unused_virtual_servers(oldConfig, target_config,
                                               old_parsed=old_parsed, new_parsed=new_parsed)
        except Exception as e:
            log.error("GTM: VS cleanup failed, will still attempt server cleanup: %s", e)
            vs_cleanup_error = e

        # Step 5: Clean up unused GSLB servers using target_config
        # RESILIENCE FIX: Always attempt, even if VS cleanup failed
        server_cleanup_error = None
        try:
            log.info("GTM: Cleaning up unused GSLB servers")
            self._cleanup.cleanup_unused_gslb_servers(datacenter_name, oldConfig, target_config,
                                            old_parsed=old_parsed, new_parsed=new_parsed)
        except Exception as e:
            log.error("GTM: GSLB server cleanup also failed: %s", e)
            server_cleanup_error = e

        # RETRY FIX: Record pending cleanup state before re-raising
        # This allows retry to work even when isConfigSame == True
        if vs_cleanup_error or server_cleanup_error:
            self._pending_cleanup = {
                'partition': partition,
                'oldConfig': oldConfig,
                'target_config': target_config,
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

    def handle_operation_create(self, gtm, partition, gtmConfig, opr_config, opr):
        """ Handle create operation """
        # RETRY FIX: Work on a deep copy of config; only commit at the end if all steps succeed
        working_config = copy.deepcopy(self._gtm_config)
         # PERF FIX: Use direct reference — oldConfig is read-only, never mutated
        oldConfig = self._gtm_config

        # PERF FIX: Defer parsing until we know there is actual work to do
        old_parsed = None
        orchestration_parsed = None  # For infrastructure orchestration (uses filtered config)
        cleanup_parsed = None  # For cleanup phase (uses full config to avoid mass deletion)
        
        try:
            if len(opr_config["pools"]) > 0 or len(opr_config["monitors"]) > 0 or len(opr_config["wideIPs"]) > 0:
                log.debug("GTM: Parsing configs for create/update operation")
                old_parsed = GTMUtils.parse_gtm_config_once(
                    oldConfig, partition, local_cluster_name=self._local_cluster_name)
                
                # PERF FIX: Calculate which wideIPs changed BEFORE taking snapshot
                wideips_to_process = set()
                filtered_config = gtmConfig  # Default: use full config
                
                if partition in gtmConfig and "wideIPs" in gtmConfig[partition]:
                    if gtmConfig[partition]['wideIPs'] is not None:
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

                        log.info("GTM: [INCREMENTAL] Processing {} changed wideIP(s) out of {} total".format(
                            len(wideips_to_process), len(gtmConfig[partition]['wideIPs'])))
                        
                        if wideips_to_process:
                            filtered_config = {partition: dict(gtmConfig[partition])}
                            filtered_config[partition]['wideIPs'] = [
                                wip for wip in gtmConfig[partition]['wideIPs']
                                if wip['name'] in wideips_to_process
                            ]
                            log.debug("GTM: [INCREMENTAL] Filtered config: {} wideIPs (vs {} total)".format(
                                len(filtered_config[partition]['wideIPs']), 
                                len(gtmConfig[partition]['wideIPs'])))

                log.info("GTM: Ensuring infrastructure for create/update operation")
                # Snapshot with FILTERED config (only changed wideIPs for incremental updates)
                snapshot = self._snapshot_helper.snapshot_bigip_state(filtered_config)
                orchestration_parsed = GTMUtils.parse_gtm_config_once(
                    filtered_config, partition, local_cluster_name=self._local_cluster_name)
                self._infrastructure.orchestrate_with_snapshot(filtered_config, orchestration_parsed, snapshot)
                
                # CRITICAL: Parse FULL config for cleanup phase
                # Must parse from full gtmConfig to get all existing members in cleanup_parsed
                cleanup_parsed = GTMUtils.parse_gtm_config_once(
                    gtmConfig, partition, local_cluster_name=self._local_cluster_name)

                if partition in gtmConfig and "wideIPs" in gtmConfig[partition]:
                    if gtmConfig[partition]['wideIPs'] is not None:

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
                                            self._pool.remove_monitor_from_pool(pool['name'], monitor['name'])
                                            # Get monitor type and delete
                                            result = GTMUtils.find_monitor_in_config(working_config, partition, monitor['name'])
                                            if result:
                                                wideip_index, pool_index, monitor_type = result
                                                self._monitor.delete_monitor(monitor['name'], monitor_type)
                                                working_config[partition]['wideIPs'][wideip_index]["pools"][pool_index].pop("monitor", None)
                                        self._monitor.create_monitor(monitor, config['name'])
                                        monitor_name = GTMUtils.apply_cluster_prefix(
                                            monitor['name'], self._local_cluster_name)
                                        all_monitors += "/" + partition + "/" + monitor_name
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
                                                                if self._pool.gtm.pools.a_s.a.exists(name=oldPool['name'], partition=partition):
                                                                    pool_obj = self._pool.gtm.pools.a_s.a.load(name=oldPool['name'], partition=partition)
                                                                for member in deleteMember:
                                                                    member_ref = GTMUtils.convert_member_to_bigip_reference(
                                                                        member,
                                                                        oldPool.get('DataServer'),
                                                                        local_cluster_name=self._local_cluster_name)
                                                                    log.info("GTM: Deleting member {} (BIG-IP ref: {}) from pool {}".format(
                                                                        member, member_ref, oldPool['name']))
                                                                    self._pool.remove_member(oldPool['name'], member_ref, pool_obj=pool_obj)
                                                            working_config[partition]['wideIPs'][index]["pools"][
                                                                pool_index]['members'] = None
                            try:
                                self._pool.create_pool(config, all_monitors, skip_member_validation=True)
                                self._wideip.create_wideip(config, newPools)
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
        if old_parsed is not None and cleanup_parsed is not None:
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
                self._cleanup.cleanup_unused_virtual_servers(oldConfig, gtmConfig,
                                                old_parsed=old_parsed, new_parsed=cleanup_parsed)
            except Exception as e:
                log.error("GTM: VS cleanup failed during create/update, will still attempt server cleanup: %s", e)
                vs_cleanup_error = e

            server_cleanup_error = None
            try:
                self._cleanup.cleanup_unused_gslb_servers(datacenter_name, oldConfig, gtmConfig,
                                                old_parsed=old_parsed, new_parsed=cleanup_parsed)
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
                    'new_parsed': cleanup_parsed,
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

    def create_gtm(self, partition, gtmConfig):
        """ Create GTM object in BIG-IP — optimized with config-driven snapshot """
        try:
            gtm = self.gtm()

            total_wideips = len(gtmConfig.get(partition, {}).get('wideIPs', []) or [])
            log.info("GTM: ========== Initial sync starting for partition {} ({} wideIPs) ==========".format(
            partition, total_wideips))

            # Step 0: Parse config once
            log.info("GTM: [INIT-SYNC] Step 1/5: Parsing configuration for partition {}...".format(partition))
            parsed = GTMUtils.parse_gtm_config_once(
                gtmConfig, partition, local_cluster_name=self._local_cluster_name)
            
            log.info("GTM: [INIT-SYNC] Step 2/5: Taking BIG-IP state snapshot (for {} wideIPs)...".format(
            total_wideips))
            # Step 0.5: Snapshot BIG-IP state (config-driven, load-only pattern)
            snapshot = self._snapshot_helper.snapshot_bigip_state(gtmConfig)

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
                        if self._snapshot_helper.wideip_fully_exists(config, snapshot):
                            skipped += 1
                        else:
                            all_wideips_exist = False
                            wideips_needing_processing.append(config)
                            processed += 1
                        
                        # Progress log every 100 wideIPs
                        if (skipped + processed) % 100 == 0:
                            log.info("GTM: [INIT-SYNC] Compared {}/{} wideIPs...".format(
                                skipped + processed, total_wideips))

            if all_wideips_exist:
                # ALL wideIPs exist with correct members — skip everything
                log.info("GTM: [SNAPSHOT] All {} wideIPs unchanged — skipping infrastructure and processing".format(
                    skipped))

                # Only run orphan cleanup using snapshot data (zero API calls if no orphans)
                expected_members = parsed['members_by_pool']
                self._cleanup.cleanup_orphaned_members_with_snapshot(expected_members, snapshot)

                self._gtm_config[partition] = gtmConfig[partition]
                log.info("GTM: Initial sync complete for partition {} — {} wideIPs (0 processed, {} skipped)".format(
                    partition, skipped, skipped))
                return

            # Step 2: Some wideIPs need processing — run full infrastructure orchestration
            log.info("GTM: [SNAPSHOT] {} wideIPs need processing, {} unchanged — running infrastructure orchestration".format(
                processed, skipped))

            log.info("GTM: Orchestrating infrastructure for partition {}".format(partition))
            infrastructure = self._infrastructure.orchestrate_with_snapshot(
                gtmConfig, parsed, snapshot)
            log.debug("GTM: Infrastructure ready: {}".format(infrastructure))

            expected_members = parsed['members_by_pool']

            # Step 3: Process ONLY wideIPs that need it (sequential — BIG-IP serializes internally)
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
                            monitor_name = GTMUtils.apply_cluster_prefix(
                                monitor['name'], self._local_cluster_name)
                            all_monitors += "/" + partition + "/" + monitor_name
                            if monitor["name"] != pool["monitors"][-1]["name"]:
                                all_monitors += " and "
                            self._monitor.create_monitor(monitor, config['name'])
                try:
                    self._pool.create_pool(config, all_monitors, skip_member_validation=True)
                    self._wideip.create_wideip(config, newPools)
                except F5CcclError as e:
                    raise e

            log.info("GTM: [SNAPSHOT] Processed {} wideIPs, skipped {} unchanged".format(
                processed, skipped))

            # Step 4: Clean up orphaned pool members using snapshot
            log.debug("GTM: Cleaning up orphaned pool members after create")
            self._cleanup.cleanup_orphaned_members_with_snapshot(expected_members, snapshot)

            # Step 5: Clean up orphaned infrastructure (servers and virtual servers)
            log.debug("GTM: Cleaning up orphaned infrastructure")
            self._gtm_config[partition] = gtmConfig[partition]
            
            # Use infrastructure cleanup for initial sync
            # This properly cleans up orphaned VSs and servers from previous deployments
            expected_members = parsed['members_by_pool']
            try:
                self._infrastructure.cleanup_infrastructure_from_bigip(expected_members)
            except Exception as e:
                log.warning("GTM: Infrastructure cleanup during initial sync failed (non-fatal): %s", e)

            log.info("GTM: Initial sync complete for partition {} — {} wideIPs ({} processed, {} skipped)".format(
                partition, processed + skipped, processed, skipped))

        except F5CcclError as e:
            log.error("GTM: Error while creating gtm: %s", e)
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
    local_cluster_name = None

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
        local_cluster_name = global_cfg.get('local-cluster-name')

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

    return verify_interval, level, vxlan_partition, local_cluster_name


def get_credentials(socket_path=None):
    """
    Unified function to retrieve credentials.
    First tries Unix socket, then falls back to environment variables.

    Args:
        socket_path: Optional custom Unix socket path.
    """
    credentials = get_credentials_from_socket(socket_path) or {}

    if not credentials.get("bigip_username", "") or not credentials.get("bigip_password", ""):
        env_credentials = get_credentials_from_env()
        if env_credentials:
            username, password = env_credentials
            credentials['bigip_username'] = username
            credentials['bigip_password'] = password

    if not credentials.get("gtm_username", "") or not credentials.get("gtm_password", ""):
        gtm_env_credentials = get_gtm_credentials_from_env()
        if gtm_env_credentials:
            username, password = gtm_env_credentials
            credentials['gtm_username'] = username
            credentials['gtm_password'] = password

    if not credentials.get("gtm_username", ""):
        credentials["gtm_username"] = credentials.get("bigip_username", "")
    if not credentials.get("gtm_password", ""):
        credentials["gtm_password"] = credentials.get("bigip_password", "")

    if not credentials.get("bigip_username", "") or not credentials.get("bigip_password", ""):
        log.error("No valid BIGIP credentials could be obtained from socket or environment variables.")
        return None

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


def get_credentials_from_socket(socket_path=None):
    if socket_path is None:
        socket_path = "/tmp/secure_cis.sock"

    client = None
    retry_interval = 0.5
    max_wait_seconds = 10.0

    start_time = time.time()
    waiting_logged = False
    while not os.path.exists(socket_path):
        elapsed = time.time() - start_time
        if elapsed >= max_wait_seconds:
            log.error(
                f"Socket file not found after {max_wait_seconds}s: {socket_path}")
            return None
        if not waiting_logged:
            log.info(f"Waiting for credential socket: {socket_path}")
            waiting_logged = True
        time.sleep(retry_interval)

    last_error = None
    connect_attempts = int(max_wait_seconds / retry_interval)
    for attempt in range(connect_attempts):
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect(socket_path)

            data = client.recv(4096).decode('utf-8')
            credentials = json.loads(data)
            if credentials:
                if credentials.get('bigip_username', '') != "" and credentials.get('bigip_password', '') != "":
                    log.info("successfully fetched BIGIP credentials from socket.")
                if credentials.get('gtm_username', '') != "" and credentials.get('gtm_password', '') != "":
                    log.info("successfully fetched GTM credentials from socket.")
            return credentials

        except (ConnectionRefusedError, FileNotFoundError) as e:
            last_error = e
            log.debug(
                "Credential socket not ready yet on attempt %s/%s: %s",
                attempt + 1,
                connect_attempts,
                e)
            time.sleep(retry_interval)
        except (ConnectionError, OSError, socket.timeout, json.JSONDecodeError, ValueError) as e:
            log.error(f"Connection failed: {e}")
            return None
        finally:
            if client:
                client.close()
                client = None

    log.error(
        f"Could not connect to credential socket after {max_wait_seconds}s: {last_error}")
    return None


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
    credential_socket = config.get('credential_socket', '/tmp/secure_cis.sock')
    credentials = get_credentials(credential_socket)
    if not credentials:
        raise ConfigError('Failed to retrieve valid BIG-IP credentials')

    config['bigip']['username'] = credentials['bigip_username']
    config['bigip']['password'] = credentials['bigip_password']
    if 'gtm_bigip' in config:
        config['gtm_bigip']['username'] = credentials.get(
            'gtm_username', credentials['bigip_username'])
        config['gtm_bigip']['password'] = credentials.get(
            'gtm_password', credentials['bigip_password'])
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


def _is_non_retryable_error(error_message):
    """Return True when an error indicates permanent auth failure."""
    if not error_message:
        return False

    msg = str(error_message).lower()
    if '401' in msg or '403' in msg:
        return True

    # Some platforms return 400 for auth payload/cookie validation errors.
    if '400' in msg:
        auth_markers = (
            'authorization',
            'auth',
            'username and password must not be null',
            'bigipauthcookie'
        )
        return any(marker in msg for marker in auth_markers)

    return False


def _retry_backoff(cb):
    RETRY_INTERVAL = 1
    log_interval = 0.5
    elapsed = 0.5
    log_success = False
    while 1:
        if log_interval > 0.5:
            log_success = True
        cb_result = cb(log_success)
        non_retryable = False
        if len(cb_result) == 2:
            (success, val) = cb_result
        else:
            (success, val, non_retryable) = cb_result

        if success:
            return val
        if non_retryable or _is_non_retryable_error(val):
            raise ConfigError(
                'Encountered non-retryable error: {}'.format(val)
            )
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
        verify_interval, _, vxlan_partition, local_cluster_name = _handle_global_config(config)
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
                error = 'BIG-IP connection error: {}'.format(e)
                return (False, error, _is_non_retryable_error(error))
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
                error = 'GTM BIG-IP connection error: {}'.format(e)
                return (False, error, _is_non_retryable_error(error))

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
                    gtm=True,
                    local_cluster_name=local_cluster_name)
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