#!/usr/bin/env python

# Copyright (c) 2016-2018, F5 Networks, Inc.
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
import sys
import threading
import time
import traceback

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
        start_time = time.clock()
        try:
            self._cb()
        except Exception:
            log.exception('Unexpected error')
        finally:
            with self._lock:
                stop_time = time.clock()
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

def get_gtm_config(partition, config):
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
    if 'vxlan-fdb' in config:
        net['userFdbTunnels'] = [config['vxlan-fdb']]
    if ('vxlan-arp' in config and 'arps' in config['vxlan-arp']
            and config['vxlan-arp']['arps'] is not None):
        net['arps'] = config['vxlan-arp']['arps']

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
                    # If LTM is not disabled and
                    # No 'resources' indicates that the controller is not
                    # yet ready -- it does not mean to apply an empty config
                    if not _is_ltm_disabled(config) and \
                            'resources' not in config:
                        continue
                    incomplete = self._update_cccl(config)
                except ValueError:
                    formatted_lines = traceback.format_exc().splitlines()
                    last_line = formatted_lines[-1]
                    log.error('Failed to process the config file {} ({})'
                              .format(self._config_file, last_line))
                    incomplete = 1
                except Exception:
                    log.exception('Unexpected error')
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
                except Exception:
                    log.exception('Unexpected error')
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
                    newGtmConfig=get_gtm_config(partition,config)
                    isConfigSame = sorted(oldGtmConfig.items())==sorted(newGtmConfig.items())
                    if isConfigSame:
                        log.info("No change in GMT config.")
                    elif not isConfigSame and len(oldGtmConfig)==0:
                        # GTM config is not same and for
                        # first time gtm config updates
                        if partition in newGtmConfig:
                            mgr._gtm.create_gtm(
                                    partition,
                                    newGtmConfig)
                            # mgr._gtm.delete_update_gtm(
                            #         partition,
                            #         newGtmConfig, newGtmConfig)
                        mgr._gtm.replace_gtm_config(newGtmConfig)
                    elif not isConfigSame:
                        # GTM config is not same
                        log.info("New changes observed in gtm config")
                        if partition in newGtmConfig:
                            mgr._gtm.delete_update_gtm(
                                    partition,
                                    oldGtmConfig,newGtmConfig)
                        mgr._gtm.replace_gtm_config(newGtmConfig)
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

    def get_gtm_config(self):
        """ Return the GTM config object"""
        return self._gtm_config

    def replace_gtm_config(self, config):
        """ Updating the GTM config object"""
        self._gtm_config = config

    def mgmt_root(self):
        """ Return the BIG-IP ManagementRoot object"""
        return self._mgmt_root

    def get_partition(self):
        """ Return the managed partition."""
        return self._partition
    
    def delete_update_gtm(self,partition,oldConfig,gtmConfig):
        """ Update GTM object in BIG-IP """
        mgmt = self.mgmt_root()
        gtm=mgmt.tm.gtm
        if partition in oldConfig and partition in gtmConfig:
            opr_config = self.process_config(oldConfig[partition],gtmConfig[partition])
            rev_map = self.create_reverse_map(oldConfig[partition])
            for opr in opr_config:
                if opr=="delete":
                    self.handle_operation_delete(gtm,partition,oldConfig,opr_config[opr],rev_map)
                if opr=="create" or opr=="update":
                    self.handle_operation_create(gtm,partition,oldConfig,gtmConfig,opr_config[opr])

    def handle_operation_delete(self,gtm,partition,oldConfig,opr_config,rev_map):
        """ Handle delete operation """
        if len(opr_config["pools"])>0:
            for pool in opr_config["pools"]:
                wideipForPoolDeleted=rev_map["pools"][pool]
                for wideip in wideipForPoolDeleted:
                    self.delete_gtm_pool(gtm,partition,oldConfig,wideip,pool)
        if len(opr_config["monitors"])>0:
            for monitor in opr_config["monitors"]:
                poolName=rev_map["monitors"][monitor]
                self.delete_gtm_hm(gtm,partition,poolName,monitor)
        if len(opr_config["wideIPs"])>0:
            for wideip in opr_config["wideIPs"]:
                self.delete_gtm_wideip(gtm,partition,oldConfig,wideip)

    def handle_operation_create(self,gtm,partition,oldConfig,gtmConfig,opr_config):
        """ Handle create operation """
        if len(opr_config["pools"])>0 or len(opr_config["monitors"])>0 or len(opr_config["wideIPs"])>0:
            if partition in gtmConfig and "wideIPs" in gtmConfig[partition]:
                if gtmConfig[partition]['wideIPs'] is not None:
                    for config in gtmConfig[partition]['wideIPs']:
                        monitor = ""
                        newPools = dict()
                        for pool in config['pools']:
                            #Pool object
                            newPools[pool['name']]= {
                                'name': pool['name'], 'partition': partition, 'ratio': 1
                                }
                            if "monitor" in pool.keys():
                                #Create Health Monitor
                                monitor = pool['monitor']['name']
                                self.delete_gtm_hm(gtm,partition,pool['name'],pool['monitor']['name'])
                                self.create_HM(gtm, partition, pool['monitor'])
                            # Delete the old pool members
                            if partition in oldConfig and "wideIPs" in oldConfig[partition]:
                                if oldConfig[partition]['wideIPs'] is not None:
                                    for oldConfig in oldConfig[partition]['wideIPs']:
                                        for oldPool in config['pools']:
                                            if oldPool['name']==pool['name']:
                                                if oldPool['members'] is not None and pool['members'] is not None:
                                                    oldPoolMember=set(oldPool['members'])
                                                    newPoolMember=set(pool['members'])
                                                    deleteMember=oldPoolMember-newPoolMember
                                                    for member in deleteMember:
                                                        self.remove_member_to_gtm_pool(
                                                            gtm,
                                                            partition,
                                                            oldPool['name'],
                                                            member)
                        #Create GTM pool
                        self.create_gtm_pool(gtm, partition, config, monitor)
                        #Create Wideip
                        self.create_wideip(gtm, partition, config,newPools)

    def create_gtm(self, partition, gtmConfig):
        """ Create GTM object in BIG-IP """
        mgmt = self.mgmt_root()
        gtm=mgmt.tm.gtm

        if "wideIPs" in gtmConfig[partition]:
            if gtmConfig[partition]['wideIPs'] is not None:
                for config in gtmConfig[partition]['wideIPs']:
                    monitor = ""
                    newPools = dict()
                    for pool in config['pools']:
                        #Pool object
                        newPools[pool['name']]= {
                            'name': pool['name'], 'partition': partition, 'ratio': 1
                            }
                        if "monitor" in pool.keys():
                            #Create Health Monitor
                            monitor = pool['monitor']['name']
                            self.create_HM(gtm, partition, pool['monitor'])
                    #Create GTM pool
                    self.create_gtm_pool(gtm, partition, config, monitor)
                    #Create Wideip
                    self.create_wideip(gtm, partition, config,newPools)
                    #Attach pool to wideip
                    # self.attach_gtm_pool_to_wideip(
                    # gtm, config['name'], partition, obj)

    def create_wideip(self, gtm, partition, config,newPools):
        """ Create wideip and returns the wideip object """
        exist=gtm.wideips.a_s.a.exists(name=config['name'], partition=partition)
        if not exist:
            log.info('GTM: Creating wideip {}'.format(config['name']))
            gtm.wideips.a_s.a.create(
                name=config['name'],
                partition=partition)
            #Attach pool to wideip
            self.attach_gtm_pool_to_wideip(gtm,config['name'],partition,list(newPools.values()))
        else:
            wideip = gtm.wideips.a_s.a.load(
                name=config['name'],
                partition=partition)
            duplicatePools = []
            if hasattr(wideip,'pools'):
                for p in newPools.keys():
                    if hasattr(wideip.raw['pools'],p):
                        duplicatePools.append(p)
            
            for poolName in duplicatePools:
                del newPools[poolName]

            if len(newPools)>0:
                self.attach_gtm_pool_to_wideip(
                    gtm,
                    config['name'],
                    partition,
                    list(newPools.values()))


    def create_gtm_pool(self, gtm, partition, config, monitorName):
        """ Create gtm pools """
        for pool in config['pools']:
            exist=gtm.pools.a_s.a.exists(name=pool['name'], partition=partition)
            if not exist:
                #Create pool object
                log.info('GTM: Creating Pool: {}'.format(pool['name']))
                if not monitorName:
                    pl=gtm.pools.a_s.a.create(
                    name=pool['name'],
                    partition=partition)
                else:
                    pl=gtm.pools.a_s.a.create(
                        name=pool['name'],
                        partition=partition,
                        monitor="/"+partition+"/"+monitorName)
            else:
                pl=gtm.pools.a_s.a.load(
                    name=pool['name'],
                    partition=partition)
                if monitorName:
                    pl.monitor="/"+partition+"/"+monitorName
                    pl.update()
                    log.info('Updating monitor {} for pool: {}'.format(monitorName,pool['name']))

            if bool(pool['members']):
                for member in pool['members']:
                    #Add member to pool
                    self.adding_member_to_gtm_pool(
                        gtm, pl, pool['name'], member, partition)

    def attach_gtm_pool_to_wideip(self, gtm, name, partition, poolObj):
        """ Attach gtm pool to the wideip """
        #wideip.raw['pools'] =
        #[{'name': 'api-pool1', 'partition': 'test', 'order': 2, 'ratio': 1}]
        wideip = gtm.wideips.a_s.a.load(name=name,partition=partition)
        if hasattr(wideip,'pools'):
            wideip.pools.extend(poolObj)
            log.info('GTM: Attaching Pool: {} to wideip {}'.format(poolObj,name))
            wideip.update()
        else:
            wideip.raw['pools'] = poolObj
            log.info('GTM: Attaching Pool: {} to wideip {}'.format(poolObj,name))
            wideip.update()

    def adding_member_to_gtm_pool(self,gtm,pool,poolName,memberName,partition):
        """ Add member to gtm pool """
        try:
            if not bool(pool):
                pool = gtm.pools.a_s.a.load(name=poolName,partition=partition)
            exist = pool.members_s.member.exists(
                name=memberName)
            if not exist:
                s = memberName.split(":")
                server = s[0].split("/")[-1]
                vs_name = s[1]
                serverExist = gtm.servers.server.exists(name=server)
                if serverExist:
                    sl = gtm.servers.server.load(name=server)
                    vsExist = sl.virtual_servers_s.virtual_server.exists(
                        name=vs_name)
                    if vsExist:
                        pmExist=pool.members_s.member.exists(
                            name=memberName,
                            partition="Common")
                        if not pmExist:
                            #Add member to gtm pool created
                            log.info('GTM: Adding pool member {} to pool {}'.format(
                                memberName,poolName))
                            pool.members_s.member.create(
                                name = memberName,
                                partition = "Common")
        except (AttributeError):
            log.debug("Error while adding member to pool.")

    def create_HM(self, gtm, partition, monitor):
        """ Create Health Monitor """
        if bool(monitor):
            if monitor['type']=="http":
                exist=gtm.monitor.https.http.exists(
                    name=monitor['name'],
                    partition=partition)
            if monitor['type']=="https":
                exist=gtm.monitor.https_s.https.exists(
                    name=monitor['name'],
                    partition=partition)
            if not exist:
                if monitor['type']=="http":
                    gtm.monitor.https.http.create(
                        name=monitor['name'],
                        partition=partition,
                        send=monitor['send'],
                        recv=monitor['recv'],
                        interval=monitor['interval'],
                        timeout=monitor['timeout'])
                if monitor['type']=="https":
                    gtm.monitor.https_s.https.create(
                        name=monitor['name'],
                        partition=partition,
                        send=monitor['send'],
                        recv=monitor['recv'],
                        interval=monitor['interval'],
                        timeout=monitor['timeout'])
            else:
                if monitor['type']=="http":
                    obj=gtm.monitor.https.http.load(
                        name=monitor['name'],
                        partition=partition)
                    obj.send=monitor['send']
                    obj.interval=monitor['interval']
                    obj.timeout=monitor['timeout']
                    obj.update()
                    log.info("Health monitor {} updated.".format(monitor['name']))
                if monitor['type']=="https":
                    log.info(monitor)
                    obj=gtm.monitor.https_s.https.load(
                        name=monitor['name'],
                        partition=partition)
                    obj.send=monitor['send']
                    obj.interval=monitor['interval']
                    obj.timeout=monitor['timeout']
                    obj.update()
                    log.info("Health monitor {} updated.".format(monitor['name']))


    def remove_member_to_gtm_pool(self,gtm,partition,poolName,memberName):
        """ Remove member to gtm pool """
        try:
            exist=gtm.pools.a_s.a.exists(name=poolName, partition=partition)
            if exist:
                pool = gtm.pools.a_s.a.load(name=poolName,partition=partition)
                memObj = pool.members_s.member.load(name=memberName)
                memObj.delete()
                log.info("Member {} deleted.".format(memberName))
        except Exception as e:
            log.error("Could not remove pool member: %s", e)

    def remove_monitor_to_gtm_pool(self,gtm,partition,poolName,monitorName):
        """ Remove monitor from gtm pool """
        try:
            pool = gtm.pools.a_s.a.load(name=poolName,partition=partition)
            if hasattr(pool,'monitor'):
                if pool.monitor=='/'+partition+'/'+monitorName:
                    pool.monitor=""
                    pool.update()
                    log.info("Detached health monitor {} from pool {}".format(monitorName,poolName))
        except Exception as e:
            log.error("Could not remove monitor from pool: %s", e)

    def remove_gtm_pool_to_wideip(self, gtm, wideipName, partition, poolName):
        """ Remove gtm pool to the wideip """
        try:
            wideip = gtm.wideips.a_s.a.load(name=wideipName,partition=partition)
            if hasattr(wideip,'pools'):
                for pool in wideip.pools:
                    if pool["name"]==poolName:
                        wideip.pools.remove(pool)
                        wideip.update()
                        log.info("Removed the pool: {}".format(poolName))
        except Exception as e:
            log.error("Could not remove pool: %s", e)

    def delete_gtm_pool(self,gtm,partition,oldConfig,wideipName,poolName):
        """ Delete gtm pools """
        try:
            # Fix this multiple loop 
            if oldConfig[partition]['wideIPs'] is not None:
                for wideip in oldConfig[partition]['wideIPs']:
                    if wideipName==wideip['name']:
                        for pool in wideip['pools']:
                            if pool['name']==poolName and pool['members'] is not None:
                                for member in pool['members']:
                                    self.remove_member_to_gtm_pool(
                                        gtm,
                                        partition,
                                        poolName,
                                        member)
                            if pool['monitor']['name'] is not None:
                                self.delete_gtm_hm(gtm,partition,pool['name'],pool['monitor']['name'])

                self.remove_gtm_pool_to_wideip(gtm,
                    wideipName,partition,poolName)
                obj = gtm.pools.a_s.a.load(
                    name=poolName,
                    partition=partition)
                obj.delete()
                log.info("Deleted the pool: {}".format(poolName))
        except Exception as e:
            log.error("Could not delete pool: %s", e)

    def delete_gtm_wideip(self,gtm,partition,oldConfig,wideipName):
        """ Delete gtm wideip """
        try:
            if oldConfig[partition]['wideIPs'] is not None:
                for wideip in oldConfig[partition]['wideIPs']:
                    if wideipName==wideip['name']:
                        for pool in wideip['pools']:
                            # Fix this multiple loop inside def delete_gtm_pool 
                            self.delete_gtm_pool(gtm,partition,oldConfig,wideipName,pool['name'])
            obj = gtm.wideips.a_s.a.load(
                    name=wideipName,
                    partition=partition)
            if hasattr(obj,'pools'):
                log.info("Could not delete wideip as pool object exist.")
            else:
                obj.delete()
                log.info("Deleted the wideIP: {}".format(wideipName))
        except Exception as e:
            log.error("Could not delete wideip: %s", e)

    def delete_gtm_hm(self,gtm,partition,poolName,monitorName):
        """ Delete gtm health monitor """
        try:
            self.remove_monitor_to_gtm_pool(gtm,partition,poolName,monitorName)
            obj = gtm.monitor.https_s.https.load(
                            name=monitorName,
                            partition=partition)
            obj.delete()
            obj = gtm.monitor.https.http.load(
                            name=monitorName,
                            partition=partition)
            obj.delete()
            log.info("Deleted the Health monitor: {}".format(monitorName))
        except Exception as e:
            log.error("Could not delete health monitor: %s", e)

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

            monitors1 = [p["monitor"] for p in pools1 if p.get("monitor")]
            monitors2 = [p["monitor"] for p in pools2 if p.get("monitor")]

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
                    mon_name = pool["monitor"]["name"]
                    rev_map["monitors"][mon_name] = pool_name
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


def _handle_bigip_config(config):
    if (not config) or ('bigip' not in config):
        raise ConfigError('Configuration file missing "bigip" section')
    bigip = config['bigip']
    if 'username' not in bigip:
        raise ConfigError('Configuration file missing '
                          '"bigip:username" section')
    if 'password' not in bigip:
        raise ConfigError('Configuration file missing '
                          '"bigip:password" section')
    if 'url' not in bigip:
        raise ConfigError('Configuration file missing "bigip:url" section')
    if ('partitions' not in bigip) or (len(bigip['partitions']) == 0):
        raise ConfigError('Configuration file must specify at least one '
                          'partition in the "bigip:partitions" section')

    url = urlparse(bigip['url'])
    host = url.hostname
    port = url.port
    if not port:
        port = 443

    return host, port


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

def _is_gtm_config(config):
    try:
        return config['global']['gtm']
    except KeyError:
        return False


def main():
    try:
        args = _handle_args()

        config = _parse_config(args.config_file)
        verify_interval, _, vxlan_partition = _handle_global_config(config)
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
    except Exception:
        log.exception('Unexpected error')
        sys.exit(1)

    return 0


if __name__ == "__main__":
    main()

