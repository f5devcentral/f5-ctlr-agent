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
                 schema_path=None,gtm=False):
        """Initialize the CloudServiceManager object."""
        self._mgmt_root = bigip
        self._schema = schema_path
        self._is_gtm = gtm
        if gtm:
            self._gtm = GTMManager(
                bigip,
                partition,
                user_agent=user_agent)
            self._cccl=None
        else:
            self._cccl = F5CloudServiceManager(
                bigip,
                partition,
                user_agent=user_agent,
                prefix=prefix,
                schema_path=schema_path)
            self._gtm=None

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
                # restart timer, possibly with a new interval
                self.stop()
            self._timer = threading.Timer(self._adjust_interval(), self._run)
            # timers can't be stopped, cancel just prevents the callback from
            # occuring when the timer finally expires.  Make it a daemon allows
            # cancelled timers to exit eventually without a need for join.
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
    """Extract a BIG-IP configuration from the LTM configuration.

    Args:
        config: BigIP config
    """
    ltm = {}
    if 'resources' in config and partition in config['resources']:
        ltm = config['resources'][partition]

    return ltm

def get_gtm_config(config):
    """Extract a BIG-IP configuration from the GTM configuration.

    Args:
        config: BigIP config
    """
    gtm = {}
    if 'gtm' in config:
        gtm = config['gtm']

    return gtm

def create_network_config(config):
    """Extract a BIG-IP Network configuration from the network config.

    Args:
        config: BigIP config which contains vxlan defs
    """
    net = {}
    if ('static-routes' in config and 'routes' in config['static-routes']
            and config['static-routes']['routes'] is not None):
        net['routes'] = config['static-routes']['routes']
        if 'cis-identifier' in config['static-routes']:
            net['cis-identifier'] = config['static-routes']['cis-identifier']
    if 'vxlan-fdb' in config:
        net['userFdbTunnels'] = [config['vxlan-fdb']]
    # Add ARPs only if disable-arp is set to false
    if not _is_arp_disabled(config) and ('vxlan-arp' in config and 'arps' in config['vxlan-arp']
            and config['vxlan-arp']['arps'] is not None):
        net['arps'] = config['vxlan-arp']['arps']
    else:
        #Disabling logging ARP entries.
        log.debug("NET Config: %s", json.dumps(net))
    return net


def _create_custom_profiles(mgmt, partition, custom_profiles):
    incomplete = 0

    # Server profiles may reference a CA cert in another server profile.
    # These need to be loaded first.
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
                try:
                    config = _parse_config(self._config_file)

                    # If LTM is not disabled - CCCL mode and
                    # No 'resources' indicates that the controller is not
                    # yet ready -- it does not mean to apply an empty config
                    if not _is_ltm_disabled(config) and 'resources' not in config:
                        continue

                    # No ARP entries indicate controller is not yet ready
                    # Valid even when there are no resources in cluster mode environment
                    # No FDB entries indicate controller is not yet ready.
                    if not _is_arp_disabled(config) and ('vxlan-arp' not in config or 'vxlan-fdb' not in config):
                        continue

                    # No route entries indicate controller is not yet ready in static route mode.
                    if _is_static_routing_enabled(config) and 'static-routes' not in config:
                        continue

                    # In CIS secondary mode if primary cluster status is up, cccl config
                    # should not be pushed by secondary CIS
                    if _is_cis_secondary(config) and _is_primary_cluster_status_up(config):
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

                gtmIncomplete = 0
                try:
                    config = _parse_config(self._config_file)
                    gtmIncomplete=self._update_gtm(config)
                except ValueError:
                    gtmIncomplete += 1
                    formatted_lines = traceback.format_exc().splitlines()
                    last_line = formatted_lines[-1]
                    log.error('Failed to process the config file {} ({})'
                              .format(self._config_file, last_line))
                except Exception as e:
                    log.exception(f'Unexpected error: {str(e)}')
                    gtmIncomplete = 1

                if incomplete|gtmIncomplete:
                    # Error occurred, perform retries
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
        gtmIncomplete=0
        for mgr in self._managers:
            if mgr.is_gtm():
                oldGtmConfig = mgr._gtm.get_gtm_config()
                # partition = mgr._gtm.get_partition()
                partition="Common"
                try:
                    allConfig=get_gtm_config(config)
                    if bool(allConfig):
                        newGtmConfig = allConfig["config"]
                        self._deleted_tenants = allConfig["deletedTenants"]
                        mgr._gtm.pre_process_gtm(newGtmConfig)
                        isConfigSame = sorted(oldGtmConfig.items())==sorted(newGtmConfig.items())
                        if not isConfigSame and len(oldGtmConfig)==0:
                            # GTM config is not same and for
                            # first time gtm config updates
                            if partition in newGtmConfig:
                                #Remove unused GTM PoolMembers from BIGIP created by CIS <= v2.7.1
                                mgr._gtm.remove_unused_poolmembers(partition, newGtmConfig[partition])
                                mgr._gtm.create_gtm(
                                        partition,
                                        newGtmConfig)
                                # mgr._gtm.delete_update_gtm(
                                #         partition,
                                #         newGtmConfig, newGtmConfig)
                            mgr._gtm.replace_gtm_config(allConfig)
                        elif not isConfigSame:
                            # GTM config is not same
                            log.info("New changes observed in gtm config")
                            if partition in newGtmConfig:
                                mgr._gtm.delete_update_gtm(
                                        partition,
                                        newGtmConfig)
                            mgr._gtm.replace_gtm_config(allConfig)

                except F5CcclError as e:
                    # We created an invalid configuration, raise the
                    # exception and fail
                    log.error("GTM Error.....:%s",e.msg)
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
                # Manually create custom profiles;
                # CCCL doesn't yet do this
                if 'customProfiles' in cfg_ltm and \
                        mgr.get_schema_type() == 'ltm':
                    tmp = 0
                    tmp = _create_custom_profiles(
                        mgr.mgmt_root(),
                        partition,
                        cfg_ltm['customProfiles'])
                    incomplete += tmp

                # Apply the BIG-IP config after creating profiles
                # and before deleting profiles
                if mgr.get_schema_type() == 'net':
                    incomplete += mgr._apply_net_config(cfg_net)
                else:
                    incomplete += mgr._apply_ltm_config(cfg_ltm)

                # Manually delete custom profiles (if needed)
                if mgr.get_schema_type() == 'ltm':
                    _delete_unused_ssl_profiles(
                        mgr,
                        partition,
                        cfg_ltm)

            except F5CcclError as e:
                # We created an invalid configuration, raise the
                # exception and fail
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
        """Initialize an instance of the F5 CCCL service manager.

        :param bigip: BIG-IP management root.
        :param partition: Name of BIG-IP partition to manage.
        :param user_agent: String to append to the User-Agent header for
        iControl REST requests (default: None)
        :param prefix:  The prefix assigned to resources that should be
        managed by this CCCL instance.  This is prepended to the
        resource name (default: None)
        :param schema_path: User defined schema (default: from package)
        """
        log.debug("F5GTMManager initialize")

        # Set user-agent for ICR session
        if user_agent is not None:
            bigip.icrs.append_user_agent(user_agent)
        self._user_agent = user_agent
        self._mgmt_root = bigip
        self._partition = partition
        self._gtm_config = {}
        self._active_tenants = []
        self._deleted_tenants = []
        self._gtm = bigip.tm.gtm

    def get_gtm_config(self):
        """ Return the GTM config object"""
        return self._gtm_config

    def replace_gtm_config(self, config):
        """ Updating the GTM config object"""
        self._active_tenants = config["activeTenants"]
        self._deleted_tenants = []
        self._gtm_config = config["config"]

    def mgmt_root(self):
        """ Return the BIG-IP ManagementRoot object"""
        return self._mgmt_root

    def gtm(self):
        return self._gtm

    def get_partition(self):
        """ Return the managed partition."""
        return self._partition

    @staticmethod
    def pre_process_gtm(gtmConfig):
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

    def delete_update_gtm(self,partition,gtmConfig):
        """ Update GTM object in BIG-IP """
        try:
            oldConfig = self._gtm_config
            mgmt = self.mgmt_root()
            gtm=mgmt.tm.gtm
            if partition in oldConfig and partition in gtmConfig:
                opr_config = self.process_config(oldConfig[partition],gtmConfig[partition])
                rev_map = self.create_reverse_map(oldConfig[partition])
                for opr in opr_config:
                    if opr=="delete":
                        self.handle_operation_delete(gtm,partition,opr_config[opr],rev_map)
                    if opr=="create" or opr=="update":
                        self.handle_operation_create(gtm,partition,gtmConfig,opr_config[opr],opr)
        except F5CcclError as e:
            raise e

    def handle_operation_delete(self,gtm,partition,opr_config,rev_map):
        """ Handle delete operation """
        try:
            if len(opr_config["monitors"]) > 0:
                for monitor in opr_config["monitors"]:
                    poolName = rev_map["monitors"][monitor]
                    self.remove_monitor_from_gtm_pool(gtm, partition, poolName, monitor)
                    self.delete_gtm_hm(gtm, partition, monitor)

            if len(opr_config["pools"]) > 0:
                for pool in opr_config["pools"]:
                    wideipForPoolDeleted = rev_map["pools"][pool]
                    for wideip in wideipForPoolDeleted:
                        self.delete_gtm_pool(gtm, partition, wideip, pool)
            if len(opr_config["wideIPs"]) > 0:
                for wideip in opr_config["wideIPs"]:
                    self.delete_gtm_wideip(gtm, partition, wideip)
        except F5CcclError as e:
            log.error("GTM: Error while handling delete operation: %s", e)
            raise e

    def handle_operation_create(self,gtm,partition,gtmConfig,opr_config,opr):
        """ Handle create operation """
        try:
            oldConfig = copy.deepcopy(self._gtm_config)
            if len(opr_config["pools"]) > 0 or len(opr_config["monitors"]) > 0 or len(opr_config["wideIPs"]) > 0:
                if partition in gtmConfig and "wideIPs" in gtmConfig[partition]:
                    if gtmConfig[partition]['wideIPs'] is not None:
                        for config in gtmConfig[partition]['wideIPs']:
                            monitor = ""
                            newPools = dict()
                            for pool in config['pools']:
                                # Pool object
                                newPools[pool['name']] = {
                                    'name': pool['name'], 'partition': partition, 'ratio': 1, 'order': pool['order']
                                }
                                all_monitors = ""
                                if "monitors" in pool.keys():
                                    # Create Health Monitor
                                    for monitor in pool["monitors"]:
                                        if opr == "update" and monitor['name'] in opr_config["monitors"]:
                                            # Delete Old Health monitors
                                            self.remove_monitor_from_gtm_pool(gtm, partition, pool['name'],
                                                                              monitor['name'])
                                            self.delete_gtm_hm(gtm, partition, monitor['name'])
                                        # Create a new Health Monitor
                                        self.create_HM(gtm, partition, monitor, config['name'])
                                        all_monitors += "/" + partition + "/" + monitor['name']
                                        if monitor["name"] != pool["monitors"][-1]["name"]:
                                            all_monitors += " and "
                                # Delete the old pool members
                                if partition in oldConfig and "wideIPs" in oldConfig[partition]:
                                    if oldConfig[partition]['wideIPs'] is not None:
                                        for index, oldConfig in enumerate(oldConfig[partition]['wideIPs']):
                                            for pool_index, oldPool in enumerate(config['pools']):
                                                if oldPool['name'] == pool['name']:
                                                    if oldPool['members'] is not None and pool['members'] is not None:
                                                        oldPoolMember = set(oldPool['members'])
                                                        newPoolMember = set(pool['members'])
                                                        deleteMember = oldPoolMember - newPoolMember
                                                        for member in deleteMember:
                                                            self.remove_member_to_gtm_pool(
                                                                gtm,
                                                                partition,
                                                                oldPool['name'],
                                                                member)
                                                        self._gtm_config[partition]['wideIPs'][index]["pools"][
                                                            pool_index]['members'] = None
                            try:
                                # Create GTM pool
                                self.create_gtm_pool(gtm, partition, config, all_monitors)
                                # Create Wideip
                                self.create_wideip(gtm, partition, config, newPools)
                            except F5CcclError as e:
                                raise e
        except F5CcclError as e:
            log.error("GTM: Error while handling create operation: %s", e)
            raise e

    def remove_unused_poolmembers(self, partition, gtmConfig):
        """Remove unused GTM PoolMembers from BIGIP created by CIS <= v2.7.1 """
        try:
            def _get_value(d, k):
                if d[k] is None:
                    return dict()
                return d[k]

            def _get_virtualNames_from_member(gtm_members):
                """ Parse GTM Virtuals from memberNames"""
                list_gtm_virtuals = {}
                for poolName in gtm_members:
                    list_gtm_virtuals[poolName] = []
                    for gtm_member in gtm_members[poolName]:
                        list_gtm_virtuals[poolName].append(gtm_member.split('/Shared/')[1])
                return list_gtm_virtuals

            def _find_deleted_members(gtm_members,bigip_members):
                del_gtm_members = {}
                # Parse GTM Virtuals from memberNames
                list_gtm_virtuals = _get_virtualNames_from_member(gtm_members)

                # Find all deleted Members from BIGIP for respective Pool
                for poolName in gtm_members:
                    del_gtm_members[poolName] = []
                    for gtm_member in gtm_members[poolName]:
                        if "ingress_link_" not in gtm_member and poolName in bigip_members:
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
            # Prepare GTM members from activeConfig and bigip_members from BIGIP based on gtm_members
            for p in gtm_pools:
                if p.get("members"):
                    gtm_members[p['name']] = p["members"]
                    exist = gtm.pools.a_s.a.exists(name=p['name'], partition=partition)
                    log.debug("Pool: {}, exists: {}".format(p["name"], exist))
                    if not exist:
                        continue
                    pool = gtm.pools.a_s.a.load(name=p['name'], partition=partition)
                    bigip_members[p['name']] = [gtmMember.name for gtmMember in pool.members_s.get_collection()]

            del_gtm_members = _find_deleted_members(gtm_members,bigip_members)
            try:
                # Remove Members from BIGIP for respective GTM Pool
                for poolName in del_gtm_members:
                    for member in del_gtm_members[poolName]:
                        log.debug("GTM: Removing member:{} from Pool:{}".format(member, poolName))
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

    def create_gtm(self, partition, gtmConfig):
        """ Create GTM object in BIG-IP """
        try:
            gtm = self.gtm()
            if "wideIPs" in gtmConfig[partition]:
                if gtmConfig[partition]['wideIPs'] is not None:
                    for config in gtmConfig[partition]['wideIPs']:
                        newPools = dict()
                        for pool in config['pools']:
                            # Pool object
                            newPools[pool['name']] = {
                                'name': pool['name'], 'partition': partition, 'ratio': 1, 'order': pool['order']
                            }
                            all_monitors = ""
                            if "monitors" in pool.keys():
                                for monitor in pool["monitors"]:
                                    # Create Health Monitor
                                    all_monitors += "/" + partition + "/" + monitor["name"]
                                    if monitor["name"] != pool["monitors"][-1]["name"]:
                                        all_monitors += " and "
                                    self.create_HM(gtm, partition, monitor, config['name'])
                        try:
                            # Create GTM pool
                            self.create_gtm_pool(gtm, partition, config, all_monitors)
                            # Create Wideip
                            self.create_wideip(gtm, partition, config, newPools)
                        except F5CcclError as e:
                            raise e
        except F5CcclError as e:
            log.error("GTM: Error while creating gtm: %s", e)
            raise e

    def create_wideip(self, gtm, partition, config, newPools):
        """ Create wideip and returns the wideip object """
        try:
            exist = gtm.wideips.a_s.a.exists(name=config['name'], partition=partition)
            if not exist:
                log.info('GTM: Creating wideip {}'.format(config['name']))
                gtm.wideips.a_s.a.create(
                    name=config['name'],
                    partition=partition, lastResortPool="none", poolLbMode=config['LoadBalancingMode'])
                # Attach pool to wideip
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


    def create_gtm_pool(self, gtm, partition, config, monitors):
        """ Create gtm pools """
        try:
            for pool in config['pools']:
                exist = gtm.pools.a_s.a.exists(name=pool['name'], partition=partition)
                log.debug("Pool: {}, exists: {}".format(pool["name"], exist))
                if not exist:
                    # Create pool object
                    log.info('GTM: Creating Pool: {}'.format(pool['name']))
                    pl = gtm.pools.a_s.a.create(
                        name=pool['name'],
                        partition=partition,fallbackMode=pool['fallbackMode'],loadBalancingMode=pool['LoadBalancingMode'])
                else:
                    pl = gtm.pools.a_s.a.load(
                        name=pool['name'],
                        partition=partition)
                # Updating the monitors
                if monitors != "":
                    pl.monitor = monitors
                    pl.update()
                    log.info('Updating monitors {} for pool: {}'.format(monitors, pool['name']))
                if pl.fallbackMode !=  pool['fallbackMode']:
                    pl.fallbackMode = pool['fallbackMode']
                    pl.update()
                    log.info('Updating fallbackMode {} for pool: {}'.format(pool['fallbackMode'], pool['name']))
                if pl.loadBalancingMode != pool['LoadBalancingMode']:
                    pl.loadBalancingMode = pool['LoadBalancingMode']
                    pl.update()
                    log.info('Updating loadBalancingMode {} for pool: {}'.format(pool['LoadBalancingMode'], pool['name']))
                if bool(pool['members']):
                    for member in pool['members']:
                        # Add member to pool
                        self.add_member_to_gtm_pool(
                            gtm, pl, pool['name'], member, partition)
        except F5CcclError as e:
            log.error("GTM: Error while creating pool: %s", e)
            raise e

    def attach_gtm_pool_to_wideip(self, gtm, name, partition, poolObj):
        """ Attach gtm pool to the wideip """
        #wideip.raw['pools'] =
        #[{'name': 'api-pool1', 'partition': 'test', 'order': 2, 'ratio': 1}]
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

    def remove_monitor_from_gtm_pool(self,gtm,partition,poolName,monitorName):
        """ Remove monitor from gtm pool """
        try:
            pool = gtm.pools.a_s.a.load(name=poolName,partition=partition)
            if hasattr(pool,'monitor'):
                if f"/{partition}/{monitorName}" in pool.monitor:
                    monitors = pool.monitor.split(" and ")
                    monitors.remove(f"/{partition}/{monitorName}")
                    pool.monitor = " and ".join(monitors)
                    pool.update()
                    log.info("Detached health monitor {} from pool {}".format(monitorName,poolName))
        except F5CcclError as e:
            log.error("Error while removing monitor from pool: %s", e)
            raise e

    def add_member_to_gtm_pool(self, gtm, pool, poolName, memberName, partition):
        """ Add member to gtm pool """
        try:
            if not bool(pool):
                pool = gtm.pools.a_s.a.load(name=poolName,partition=partition)
            exist = pool.members_s.member.exists(
                name=memberName)
            log.debug("Pool Member: {}, exists: {}".format(memberName, exist))
            if not exist:
                s = memberName.split(":")
                server = s[0].split("/")[-1]
                vs_name = s[1]
                serverExist = gtm.servers.server.exists(name=server)
                log.debug("Server: {}, exists: {}".format(server, serverExist))
                if serverExist:
                    sl = gtm.servers.server.load(name=server)
                    vsExist = sl.virtual_servers_s.virtual_server.exists(
                        name=vs_name)
                    log.debug("Virtual Server: {}, exists: {}".format(vs_name, vsExist))
                    if vsExist:
                        pmExist=pool.members_s.member.exists(
                            name=memberName,
                            partition="Common")
                        log.debug("Pool Member: {}, exists: {}".format(memberName, pmExist))
                        if not pmExist:
                            #Add member to gtm pool created
                            log.info('GTM: Adding pool member {} to pool {}'.format(
                                memberName,poolName))
                            pool.members_s.member.create(
                                name = memberName,
                                partition = "Common")
                    else:
                        raise F5CcclError(
                            msg="Virtual Server Resource not Available in BIG-IP")
                else:
                    # Delete pool for invalid server config
                    pool = gtm.pools.a_s.a.load(name=poolName, partition=partition)
                    pool.delete()
                    raise F5CcclError(msg="Server Resource not Available in BIG-IP")
        except (F5CcclError) as e:
            log.debug("GTM: Error while adding member to pool.")
            raise e


    def get_bigip_version(self):
        try:
            mgmt= self.mgmt_root()
            verList = mgmt.tmos_version.split('.')
            return float(verList[0] + '.' + verList[1])
        except F5CcclError as e:
            log.error("GTM: Could not fetch BigipVersion: %s", e)
            raise e

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
                            log.info("HTTP Health monitor {} updated.".format(monitor['name']))
                        if monitor['type'] == "https":
                            log.info(monitor)
                            obj = gtm.monitor.https_s.https.load(
                                name=monitor['name'],
                                partition=partition)
                            obj.send = monitor['send']
                            obj.interval = monitor['interval']
                            obj.timeout = monitor['timeout']
                            if self.get_bigip_version() >= 16.1:
                                obj.sniServerName = wideIPName
                            obj.update()
                            log.info("HTTPS Health monitor {} updated.".format(monitor['name']))
                        if monitor['type'] == "tcp":
                            log.info(monitor)
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


    def remove_member_to_gtm_pool(self,gtm,partition,poolName,memberName):
        """ Remove member to gtm pool """
        try:
            if memberName.split(":")[1].split("/")[1] not in self._active_tenants + self._deleted_tenants:
                log.debug("GTM: Not removing the pool member %s as it may not be created by this CIS instance", memberName)
                return
            exist=gtm.pools.a_s.a.exists(name=poolName, partition=partition)
            if exist:
                pool = gtm.pools.a_s.a.load(name=poolName,partition=partition)
                memObj = pool.members_s.member.load(name=memberName)
                memObj.delete()
                log.info("Member {} deleted.".format(memberName))
        except F5CcclError as e:
            log.error("GTM: Error while removing pool member: %s", e)
            raise e

    def remove_gtm_pool_to_wideip(self, gtm, wideipName, partition, poolName):
        """ Remove gtm pool to the wideip """
        try:
            wideip = gtm.wideips.a_s.a.load(name=wideipName,partition=partition)
            if wideip.lastResortPool == "":
                wideip.lastResortPool = "none"
            if hasattr(wideip,'pools'):
                for pool in wideip.pools:
                    if pool["name"]==poolName:
                        wideip.pools.remove(pool)
                        wideip.update()
                        log.info("Removed the pool: {}".format(poolName))
        except F5CcclError as e:
            log.error("GTM: Error while removing pool: %s", e)
            raise e

    def delete_gtm_pool(self,gtm,partition,wideipName,poolName):
        """ Delete gtm pools """
        try:
            oldConfig = copy.deepcopy(self._gtm_config)
            # Fix this multiple loop 
            if oldConfig[partition]['wideIPs'] is not None:
                for index, wideip in enumerate(oldConfig[partition]['wideIPs']):
                    if wideipName==wideip['name']:
                        for pool_index, pool in enumerate(wideip['pools']):
                            if pool['name']==poolName and pool['members'] is not None:
                                for member in pool['members']:
                                    self.remove_member_to_gtm_pool(
                                        gtm,
                                        partition,
                                        poolName,
                                        member)
                                self._gtm_config[partition]['wideIPs'][index]["pools"][pool_index]['members'] = None
                                break
                        break
                obj = gtm.pools.a_s.a.load(
                    name=poolName,
                    partition=partition)
                # delete the gtm pool and remove the pool from wide ip once there are no pool members attached to it.
                if  len(obj.members_s.get_collection()) == 0:
                    self.remove_gtm_pool_to_wideip(gtm,
                        wideipName,partition,poolName)
                    obj.delete()
                    log.info("Deleted the pool: {}".format(poolName))
                    self._gtm_config[partition]['wideIPs'][index]["pools"].pop(pool_index)
        except F5CcclError as e:
            log.error("GTM: Error while deleting pool: %s", e)
            raise e


    def delete_gtm_wideip(self,gtm,partition,wideipName):
        """ Delete gtm wideip """
        try:
            oldConfig = copy.deepcopy(self._gtm_config)
            # As pool is deleted as part of delete_gtm_pool
            # if oldConfig[partition]['wideIPs'] is not None:
            #     for wideip in oldConfig[partition]['wideIPs']:
            #         if wideipName==wideip['name']:
            #             for pool in wideip['pools']:
            #                 # Fix this multiple loop inside def delete_gtm_pool 
            #                 self.delete_gtm_pool(gtm,partition,oldConfig,wideipName,pool['name'])
            wideip = gtm.wideips.a_s.a.load(
                    name=wideipName,
                    partition=partition)
            if wideip.lastResortPool == "":
                wideip.lastResortPool = "none"
            if hasattr(wideip,'pools'):
                log.info("Could not delete wideip as pool object exist.")
            else:
                wideip.delete()
                log.info("Deleted the wideIP: {}".format(wideipName))
                if oldConfig[partition]['wideIPs'] is not None:
                    for index, wideip in enumerate(oldConfig[partition]['wideIPs']):
                        if wideipName == wideip['name']:
                            self._gtm_config[partition]['wideIPs'].pop(index)
        except F5CcclError as e:
            log.error("Could not delete wideip: %s", e)
            raise e

    def delete_gtm_hm_helper(self, partition, monitorName):
        oldConfig = copy.deepcopy(self._gtm_config)
        if oldConfig[partition]['wideIPs'] is not None:
            for index, config in enumerate(oldConfig[partition]['wideIPs']):
                for pool_index, pool in enumerate(config['pools']):
                    if "monitors" in pool.keys():
                        for monitor in pool['monitors']:
                            if monitorName == monitor['name']:
                                return index, pool_index, monitor['type']

    def delete_gtm_hm(self,gtm,partition,monitorName):
        """ Delete gtm health monitor """
        try:
            wideip_index, pool_index, type = self.delete_gtm_hm_helper(partition, monitorName)
            if type=="http":
                obj = gtm.monitor.https.http.load(
                            name=monitorName,
                            partition=partition)
                obj.delete()
                log.info("Deleted the HTTP Health monitor: {}".format(monitorName))
            elif type=="https":
                obj = gtm.monitor.https_s.https.load(
                            name=monitorName,
                            partition=partition)
                obj.delete()
                log.info("Deleted the HTTPS Health monitor: {}".format(monitorName))
            elif type=="tcp":
                obj = gtm.monitor.tcps.tcp.load(
                            name=monitorName,
                            partition=partition)
                obj.delete()
                log.info("Deleted the TCP Health monitor: {}".format(monitorName))
            self._gtm_config[partition]['wideIPs'][wideip_index]["pools"][pool_index].pop("monitor", None)
        except F5CcclError as e:
            log.error("GTM: Could not delete health monitor: %s", e)
            raise e

    def process_config(self, d1, d2):
        """ Process old and new config """
        def _get_resource_from_list(lst, rsc_name):
            for rsc in lst:
                if rsc["name"] == rsc_name:
                    return rsc

        def _are_wip_equal(wip1, wip2):
            if wip1["recordType"] != wip2["recordType"]:
                return False
            if wip1["loadBalancingMode"] != wip2["loadBalancingMode"]:
                return False

            pool_set1 = set([p["name"] for p in wip1["pools"]])
            pool_set2 = set([p["name"] for p in wip2["pools"]])

            new_pools = pool_set2 - pool_set1
            del_pools = pool_set1 - pool_set2

            if len(new_pools) or len(del_pools):
                return False

            return True

        def _are_pools_equal(pool1, pool2):
            if pool1["recordType"] != pool2["recordType"]:
                return False
            if pool1["loadBalancingMode"] != pool2["loadBalancingMode"]:
                return False

            mem_set1 = set(pool1["members"])
            mem_set2 = set(pool2["members"])

            if len(mem_set1) or len(mem_set2):
                return False

            if pool1["monitor"]["name"] != pool2["monitor"]["name"]:
                return False

            return True

        def _get_crud_wide_ips(d1, d2):
            wip_set1 = set([v["name"] for v in _get_value(d1,"wideIPs")])
            wip_set2 = set([v["name"] for v in _get_value(d2,"wideIPs")])

            del_wips = list(wip_set1 - wip_set2)
            new_wips = list(wip_set2 - wip_set1)
            cur_wips = wip_set1.intersection(wip_set2)
            update_wips = []

            for wip_name in cur_wips:
                wip1 = _get_resource_from_list(_get_value(d1,"wideIPs"), wip_name)
                wip2 = _get_resource_from_list(_get_value(d2,"wideIPs"), wip_name)

                if wip1 != wip2:
                    update_wips.append(wip_name)

            return new_wips, del_wips, update_wips

        def _get_crud_pools(d1, d2):
            pools1 = []
            pools2 = []
            for wip in _get_value(d1,"wideIPs"):
                pools1 += wip["pools"]
            for wip in _get_value(d2,"wideIPs"):
                pools2 += wip["pools"]

            pool_set1 = set([p["name"] for p in pools1])
            pool_set2 = set([p["name"] for p in pools2])

            new_pools = list(pool_set2 - pool_set1)
            del_pools = list(pool_set1 - pool_set2)
            cur_pools = pool_set1.intersection(pool_set2)
            update_pools = []

            for pool_name in cur_pools:
                pool1 = _get_resource_from_list(pools1, pool_name)
                pool2 = _get_resource_from_list(pools2, pool_name)

                if pool1 != pool2:
                    update_pools.append(pool_name)

            return new_pools, del_pools, update_pools

        def _get_value(d,k):
            if d[k] is None:
                return dict()
            return d[k]

        def _get_crud_monitors(d1, d2):
            pools1 = []
            pools2 = []
            for wip in _get_value(d1,"wideIPs"):
                pools1 += wip["pools"]
            for wip in _get_value(d2,"wideIPs"):
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

            for mon_name in cur_mons:
                mon1 = _get_resource_from_list(monitors1, mon_name)
                mon2 = _get_resource_from_list(monitors2, mon_name)

                if mon1 != mon2:
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

    def create_reverse_map(self,d):
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

    # level only is needed for unit tests
    return verify_interval, level, vxlan_partition

def get_credentials():
    """
    Unified function to retrieve credentials.
    First tries Unix socket, then falls back to environment variables.
    Returns:
        dict: {'username': '...', 'password': '...'}
    """
    # First check credentials over Unix Socket
    credentials = get_credentials_from_socket()
    if credentials:
        return credentials

    # Check Environment Variables
    credential_sources = tuple()
    if not credentials or not credentials["bigip_username"]:
        credential_sources = credential_sources + (('bigip', get_credentials_from_env),)

    if not credentials or not credentials["gtm_username"]:
        credential_sources = credential_sources + (('gtm', get_gtm_credentials_from_env),)

    credentials = {}
    for prefix, fetch_func in credential_sources:
        env_credentials = fetch_func()
        if env_credentials:
            username, password = env_credentials
            credentials[f'{prefix}_username'] = username
            credentials[f'{prefix}_password'] = password

    if not credentials["gtm_username"] or credentials["gtm_username"] == "":
        credentials["gtm_username"] = credentials["bigip_username"]
    if not credentials["gtm_password"] or credentials["gtm_password"] == "":
        credentials["gtm_password"] = credentials["bigip_password"]

    return credentials


def get_credentials_from_env():
    """
    Retrieve credentials from environment variables.
    Returns:
        tuple: (username, password) if found, else None.
    """
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
    """
    Retrieve credentials from environment variables.
    Returns:
        tuple: (username, password) if found, else None.
    """
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

        # FIXME (kenr): Big-IP settings are currently static (we ignore any
        #               changes to these fields in subsequent updates). We
        #               may want to make the changes dynamic in the future.

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

        # Read version and build info, set user-agent for ICR session
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
                # Management for the BIG-IP partitions
                manager = CloudServiceManager(
                    bigip,
                    partition,
                    user_agent=user_agent)
                managers.append(manager)
        if vxlan_partition:
            # Management for net resources (VXLAN)
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
                # Management for the BIG-IP partitions
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

