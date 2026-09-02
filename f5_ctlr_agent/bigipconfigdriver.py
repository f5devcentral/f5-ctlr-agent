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
import re
import signal
import socket
import sys
import threading
import time
import traceback
import copy
import tempfile
import pyinotify

from urllib.parse import urlparse
from f5_cccl.api import F5CloudServiceManager
from f5_cccl.exceptions import F5CcclError, F5CcclResourceNotFoundError
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


# E7: Module-level tracking for temporary certificate files
# Tracks both LTM and GTM temporary cert files for proper cleanup
_temp_cert_files = {}
_cert_file_lock = threading.Lock()
_temp_dir_cache = None  # Cache selected temp directory


def _get_temp_dir():
    """Get the best available temporary directory.
    
    Issue #3: Prefers /dev/shm (memory-based) for security and performance.
    Falls back to /tmp (disk-based) if /dev/shm is unavailable.
    
    Returns:
        Path to temporary directory, or None to use system default
    
    Selection priority:
        1. /dev/shm (if exists and writable) — memory-based, fast, auto-cleanup
        2. /tmp (if writable) — disk-based, universal fallback
        3. None (system default) — tempfile will use platform-specific location
    """
    global _temp_dir_cache
    
    # Return cached result after first check
    if _temp_dir_cache is not None:
        return _temp_dir_cache if _temp_dir_cache != '' else None
    
    preferred_dirs = ['/dev/shm', '/tmp']
    for temp_dir in preferred_dirs:
        try:
            if os.path.exists(temp_dir) and os.access(temp_dir, os.W_OK):
                _temp_dir_cache = temp_dir
                log.debug('Using temporary directory for certificates: %s',
                         temp_dir)
                return temp_dir
        except (OSError, PermissionError) as e:
            log.debug('Cannot use %s for temp files: %s', temp_dir, e)
            continue
    
    # Fallback to system default
    _temp_dir_cache = ''
    log.debug('No preferred temp directories available, using system default')
    return None


def _cleanup_temp_cert_files():
    """Remove temporary certificate files.
    
    E7 FIX: This cleanup is called ONLY at process shutdown to allow multiple
    API operations to reuse the same ManagementRoot connection with stable cert file paths.
    
    Certificate files are deleted in four scenarios:
    1. When TMOSDNSConfig.certSecret is REMOVED (ca.crt deleted) → Immediate cleanup
    2. When TMOSDNSConfig.certSecret CHANGES (ca.crt is updated) → Detected by content comparison
    3. When old cert file is MISSING → Detected by file existence check, new file created
    4. At process termination via finally block → Cleanup remaining files
    
    This design prevents "[SSL: CERTIFICATE_VERIFY_FAILED]" errors on subsequent operations
    while supporting certificate rotation and removal from TMOSDNSConfig updates.
    
    Note: Files are created with 0400 (read-only) permissions for security.
    Before deletion, we restore write permissions so os.remove() succeeds.
    """
    with _cert_file_lock:
        for cert_id, cert_path in list(_temp_cert_files.items()):
            try:
                if cert_path and os.path.exists(cert_path):
                    # Restore write permission before deletion (files created as 0400)
                    os.chmod(cert_path, 0o600)
                    os.remove(cert_path)
                    log.debug('Cleaned up temporary certificate file for %s',
                              cert_id)
            except OSError as e:
                log.warning('Failed to cleanup cert file for %s: %s', cert_id, e)
        _temp_cert_files.clear()


def _create_temp_cert_file(trusted_certs, cert_id='bigip', worker_id=''):
    """Create or update a temporary certificate file.

    Issue #3: Converts PEM certificate content to a temporary file because
    requests/urllib3 verify parameter only accepts file paths.

    Prefers /dev/shm (memory-based) for security and performance, with
    automatic fallback to /tmp (disk-based) if /dev/shm is unavailable.

    E7 FIX: Detects certificate content changes from TMOSDNSConfig certSecret updates.
    - If certificate content CHANGED: Delete old file, create new one
    - If certificate content SAME: Reuse existing file (no deletion)
    - If certSecret REMOVED: Clean up old file, disable TLS verification
    This prevents SSL verification errors while supporting certificate rotation and removal.

    Args:
        trusted_certs: PEM certificate content (string), or empty/None if certSecret removed
        cert_id: Identifier for this cert ('bigip' or 'gtmbigip') for tracking
        worker_id: Optional GTM worker ID from the CIS controller. When provided,
            the temp cert file is named bigip_cert_<worker_id>_<cert_id>_*.pem so
            the Go controller can clean up all PEM files for an endpoint by worker ID.

    Returns:
        Path to temporary cert file, or None if trusted_certs is empty

    Note:
        - Thread-safe with lock protection
        - Uses /dev/shm (memory) when available for security/performance
        - Falls back to /tmp (disk) when /dev/shm unavailable
        - File permissions set to 0400 (read-only) for security
        - Tracks cert content to detect changes from TMOSDNSConfig.certSecret updates
        - Cleans up cert files when certSecret is removed from TMOSDNSConfig
    """
    with _cert_file_lock:
        # E7 FIX: Handle certSecret removal from TMOSDNSConfig
        # If trusted_certs is empty, clean up any existing cert file for this cert_id
        if not trusted_certs:
            if cert_id in _temp_cert_files:
                old_path = _temp_cert_files[cert_id]
                try:
                    if os.path.exists(old_path):
                        os.chmod(old_path, 0o600)  # Restore write permissions
                        os.remove(old_path)
                        log.info('Cleaned up certificate file for %s (certSecret removed)',
                                cert_id)
                except OSError as e:
                    log.warning('Failed to cleanup cert file when removed for %s: %s',
                               cert_id, e)
                finally:
                    # Always remove from tracking dict, even if file deletion failed
                    del _temp_cert_files[cert_id]
            else:
                log.debug('No certificate file to cleanup for %s (certSecret removed)',
                         cert_id)
            
            # Return None to signal no TLS verification needed
            # Caller will use verify=False in mgmt_root()
            return None
        
        # E7 FIX: Detect if certificate content changed from TMOSDNSConfig update
        if cert_id in _temp_cert_files:
            old_path = _temp_cert_files[cert_id]
            
            # Read existing cert file content to compare with new content
            cert_content_changed = False
            try:
                if os.path.exists(old_path):
                    with open(old_path, 'r') as f:
                        old_content = f.read()
                    
                    # Compare certificate content
                    if old_content != trusted_certs:
                        cert_content_changed = True
                        log.info('Certificate content changed for %s; new cert will be used',
                                cert_id)
                    else:
                        # Same certificate, reuse existing file
                        log.debug('Certificate content unchanged for %s. Reusing existing file',
                                 cert_id)
                        return old_path
                else:
                    # File was deleted externally, need to recreate
                    log.warning('Cert file missing for %s. Will recreate.',
                               cert_id)
                    cert_content_changed = True
            except OSError as e:
                log.warning('Failed to read existing cert file for %s: %s. Will recreate.',
                           cert_id, e)
                cert_content_changed = True
            
            # Delete old cert file if content changed or file is missing
            if cert_content_changed:
                try:
                    if os.path.exists(old_path):
                        os.chmod(old_path, 0o600)  # Restore write permissions
                        os.remove(old_path)
                        log.info('Deleted old certificate file for %s',
                                cert_id)
                except OSError as e:
                    log.warning('Failed to delete old cert file for %s: %s',
                               cert_id, e)
        
        # Create new temporary file in best available directory.
        # Include the worker ID in the prefix so the Go controller can remove
        # all PEM files belonging to a specific endpoint by globbing
        # bigip_cert_<worker_id>_*.pem when that endpoint is deleted.
        try:
            temp_dir = _get_temp_dir()
            if worker_id:
                prefix = 'bigip_cert_{}_{}_'.format(worker_id, cert_id)
            else:
                prefix = 'bigip_cert_{}_'.format(cert_id)
            temp_cert_file = tempfile.NamedTemporaryFile(
                mode='w', suffix='.pem', delete=False, prefix=prefix,
                dir=temp_dir  # ← Uses /dev/shm if available, /tmp fallback
            )
            temp_cert_file.write(trusted_certs)
            temp_cert_file.flush()
            temp_cert_file.close()

            cert_path = temp_cert_file.name

            # Set restrictive permissions (read-only for owner)
            # ManagementRoot runs in same process/user, so can still read it
            os.chmod(cert_path, 0o400)

            _temp_cert_files[cert_id] = cert_path
            log.debug('Created temporary certificate file for %s (perms=0400)',
                      cert_id)
            return cert_path
        except IOError as e:
            log.error('Failed to create temporary certificate file: %s', e)
            return None


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
                 schema_path=None, gtm=False, local_cluster_name=None,
                 cluster_digital_asset_id=None):
        """Initialize the CloudServiceManager object."""
        self._mgmt_root = bigip
        self._schema = schema_path
        self._is_gtm = gtm
        if gtm:
            self._gtm = GTMManager(
                bigip,
                partition,
                user_agent=user_agent,
                local_cluster_name=local_cluster_name,
                cluster_digital_asset_id=cluster_digital_asset_id)
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

                log.info('updating tasks finished, took %s seconds',
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
                        disabled_zones = allConfig.get("disabledAvailabilityZones", [])

                        # Keep gtm.clusterIdentifier and gtm.digitalAssetID as distinct fields.
                        # Go always writes both keys (even as "") so the Python driver can
                        # clear stale values when identifiers are removed.
                        cluster_id = allConfig.get("clusterIdentifier")
                        digital_asset_id = allConfig.get("digitalAssetID")

                        # Propagate clusterIdentifier to all GTM submodules when it changes.
                        # Guard allows empty string to clear a previously-set identifier.
                        if cluster_id is not None and cluster_id != mgr._gtm._local_cluster_name:
                            log.info("GTM: Updating cluster identifier to: %r", cluster_id)
                            mgr._gtm._local_cluster_name = cluster_id
                            mgr._gtm._infrastructure._local_cluster_name = cluster_id
                            mgr._gtm._wideip._local_cluster_name = cluster_id
                            mgr._gtm._pool._local_cluster_name = cluster_id
                            mgr._gtm._monitor._local_cluster_name = cluster_id
                            mgr._gtm._snapshot_helper._local_cluster_name = cluster_id
                            mgr._gtm._cleanup._local_cluster_name = cluster_id

                        # Propagate digitalAssetID to all GTM submodules when it changes.
                        if digital_asset_id is not None and digital_asset_id != mgr._gtm._cluster_digital_asset_id:
                            log.info("GTM: Updating digital asset id to: %r", digital_asset_id)
                            mgr._gtm._cluster_digital_asset_id = digital_asset_id
                            mgr._gtm._infrastructure._cluster_digital_asset_id = digital_asset_id
                            mgr._gtm._wideip._cluster_digital_asset_id = digital_asset_id
                            mgr._gtm._pool._cluster_digital_asset_id = digital_asset_id
                            mgr._gtm._snapshot_helper._cluster_digital_asset_id = digital_asset_id
                            mgr._gtm._cleanup._cluster_digital_asset_id = digital_asset_id

                        prev_enable_data_server_monitor = getattr(
                            mgr._gtm._infrastructure, "_enable_data_server_monitor", False)

                        # enableDataServerMonitor controls GSLB server health monitor attachment
                        new_enable_data_server_monitor = GTMUtils.as_bool(
                            allConfig.get("enableDataServerMonitor", False),
                            default=False)
                        mgr._gtm._infrastructure._enable_data_server_monitor = new_enable_data_server_monitor

                        data_server_monitor_changed = (prev_enable_data_server_monitor != new_enable_data_server_monitor)
                        monitor_settings_changed = data_server_monitor_changed

                        GTMUtils.pre_process_gtm(newGtmConfig, disabled_availability_zones=disabled_zones)
                        isConfigSame = sorted(oldGtmConfig.items()) == sorted(newGtmConfig.items())
                        _bip = mgr._gtm._bigip_host
                        _wip_count = len(newGtmConfig.get(partition, {}).get('wideIPs', []) or [])
                        if (not isConfigSame or monitor_settings_changed) and len(oldGtmConfig) == 0:
                            if partition in newGtmConfig:
                                mgr._gtm.create_gtm(
                                    partition,
                                    newGtmConfig)
                            mgr._gtm.replace_gtm_config(allConfig)
                            log.info("GTM: Initial push/sync on restart completed successfully ({} wideIPs), bigip: {}".format(
                                _wip_count, _bip))
                        elif not isConfigSame or monitor_settings_changed:
                            if monitor_settings_changed and isConfigSame:
                                # WideIP config is unchanged; server monitor toggle is outside gtm.config.
                                # delete_update_gtm would compute empty CRUD and become a no-op.
                                log.info("GTM: Monitor settings changed (enableDataServerMonitor=%s), "
                                         "running monitor-only reconciliation, bigip: %s",
                                         new_enable_data_server_monitor, _bip)
                                if partition in newGtmConfig:
                                    mgr._gtm.apply_monitor_settings(
                                        partition,
                                        newGtmConfig,
                                        reconcile_pool=False,
                                        reconcile_server=data_server_monitor_changed,
                                    )
                            else:
                                log.info("New changes observed in gtm config, bigip: %s", _bip)
                                if partition in newGtmConfig:
                                    mgr._gtm.delete_update_gtm(
                                        partition,
                                        newGtmConfig)
                                    # Even when GTM config changed, still reconcile server monitor
                                    # toggle explicitly because it lives outside gtm.config diffing.
                                    if data_server_monitor_changed:
                                        log.info(
                                            "GTM: Post-diff monitor reconcile triggered "
                                            "(reason=data_server_monitor_toggle, "
                                            "enableDataServerMonitor=%s, partition=%s, bigip=%s)",
                                            new_enable_data_server_monitor,
                                            partition,
                                            _bip,
                                        )
                                        mgr._gtm.apply_monitor_settings(
                                            partition,
                                            newGtmConfig,
                                            reconcile_pool=False,
                                            reconcile_server=True,
                                        )
                            mgr._gtm.replace_gtm_config(allConfig)
                            log.info("GTM: Config sync completed successfully ({} wideIPs), bigip: {}".format(
                                _wip_count, _bip))

                except F5CcclError as e:
                    _bip = mgr._gtm._bigip_host if hasattr(mgr, '_gtm') and mgr._gtm else 'unknown'
                    _code = _extract_http_code(str(e))
                    log.error("GTM Error.....:%s, bigip: %s, error_code: %s", e.msg, _bip, _code)
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

    def __init__(self, bigip, partition, user_agent=None, local_cluster_name=None,
                 cluster_digital_asset_id=None):
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
        self._cluster_digital_asset_id = cluster_digital_asset_id or ""
        try:
            self._bigip_host = bigip._meta_data.get('hostname', 'unknown')
        except Exception:
            self._bigip_host = 'unknown'
        if not self._local_cluster_name and not self._cluster_digital_asset_id:
            log.info("GTM: Running in legacy unscoped mode — all GTM objects will be "
                     "treated as owned by this CIS instance as cluster identifier and digital asset ID are not set. ")
        # PERF FIX #9: Cache BIG-IP version once
        self._bigip_version = None
        # RETRY FIX: Track pending cleanup state for isConfigSame retry scenario
        self._pending_cleanup = None
        
        # Initialize GTM component modules for modular architecture
        self._snapshot_helper = GTMSnapshot(
            self._gtm,
            self._partition,
            local_cluster_name=self._local_cluster_name,
            cluster_digital_asset_id=self._cluster_digital_asset_id)
        self._infrastructure = GTMInfrastructure(
            self._gtm,
            self._partition,
            local_cluster_name=self._local_cluster_name,
            cluster_digital_asset_id=self._cluster_digital_asset_id)
        self._wideip = GTMWideIP(
            self._gtm,
            self._partition,
            local_cluster_name=self._local_cluster_name,
            cluster_digital_asset_id=self._cluster_digital_asset_id)
        self._pool = GTMPool(
            self._gtm,
            self._partition,
            self._active_tenants,
            self._deleted_tenants,
            local_cluster_name=self._local_cluster_name,
            cluster_digital_asset_id=self._cluster_digital_asset_id)
        self._monitor = GTMMonitor(
            self._gtm,
            self._partition,
            bigip_version_getter=self.get_bigip_version,
            local_cluster_name=self._local_cluster_name)
        self._cleanup = GTMCleanup(
            self._gtm,
            self._partition,
            pool_manager=self._pool,
            local_cluster_name=self._local_cluster_name,
            cluster_digital_asset_id=self._cluster_digital_asset_id)

    def get_gtm_config(self):
        """ Return the GTM config object"""
        return self._gtm_config

    def replace_gtm_config(self, config):
        """ Updating the GTM config object"""
        self._active_tenants = config["activeTenants"]
        self._deleted_tenants = []
        # Deep copy so that subsequent working_config mutations (e.g. members=None
        # set by delete_pool) never alias into the authoritative cached config.
        self._gtm_config = copy.deepcopy(config["config"])
        
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

    def _build_effective_pool_monitor(self, pool):
        """Build desired BIG-IP pool monitor string for one pool config."""
        monitor_refs = []
        for monitor in pool.get("monitors", []) or []:
            monitor_name = GTMUtils.apply_cluster_prefix(
                monitor.get('name'), self._local_cluster_name)
            if monitor_name:
                monitor_refs.append("/{}/{}".format(self._partition, monitor_name))

        pool_monitor_ref = pool.get('poolMonitorRef')
        if pool_monitor_ref and pool_monitor_ref not in monitor_refs:
            monitor_refs.append(pool_monitor_ref)

        return " and ".join(monitor_refs)

    def _is_not_found_error(self, exception):
        """Return True when the client exception represents a missing BIG-IP resource."""
        if isinstance(exception, F5CcclResourceNotFoundError):
            return True

        if hasattr(exception, 'response') and exception.response is not None:
            try:
                return exception.response.status_code == 404
            except (AttributeError, TypeError):
                pass

        if hasattr(exception, 'args'):
            for arg in exception.args:
                if isinstance(arg, BaseException) and self._is_not_found_error(arg):
                    return True

        return False

    def _load_bigip_resource_or_none(self, load_fn, resource_kind, resource_name, **kwargs):
        """Load a BIG-IP resource, returning None when it does not exist."""
        try:
            return load_fn(name=resource_name, **kwargs)
        except Exception as e:
            if self._is_not_found_error(e):
                log.debug("GTM: %s %s not found on BIG-IP, skipping", resource_kind, resource_name)
                return None
            raise

    def apply_monitor_settings(self, partition, gtmConfig, reconcile_pool=True, reconcile_server=True,
                               reconcile_fallback=False):
        """Reconcile pool/server runtime attributes without relying on GTM CRUD diff."""
        pools_updated = 0
        servers_updated = 0

        try:
            if partition not in gtmConfig:
                log.debug("GTM: [MONITOR-RECONCILE] Partition %s not present in config", partition)
                return

            # Pool monitor/fallback reconciliation.
            if reconcile_pool or reconcile_fallback:
                for wip in gtmConfig[partition].get('wideIPs', []) or []:
                    for pool in wip.get('pools', []) or []:
                        pool_name = GTMUtils.format_pool_name(
                            pool.get('name'), self._local_cluster_name,
                            self._cluster_digital_asset_id)
                        if not pool_name:
                            continue

                        try:
                            pl = self._load_bigip_resource_or_none(
                                self._pool.gtm.pools.a_s.a.load,
                                'Pool',
                                pool_name,
                                partition=self._partition,
                            )
                            if pl is None:
                                continue
                            effective_monitors = self._build_effective_pool_monitor(pool)
                            current_monitor = getattr(pl, 'monitor', '') or ''
                            pool_needs_update = False

                            if effective_monitors and current_monitor != effective_monitors:
                                log.info("GTM: [MONITOR-RECONCILE] Pool %s: monitor %r -> %r",
                                         pool_name, current_monitor, effective_monitors)
                                pl.monitor = effective_monitors
                                pool_needs_update = True
                            elif not effective_monitors and current_monitor:
                                log.info("GTM: [MONITOR-RECONCILE] Pool %s: clearing monitor (was %r)",
                                         pool_name, current_monitor)
                                pl.monitor = ""
                                pool_needs_update = True

                            if reconcile_fallback:
                                desired_fallback_mode = pool.get('fallbackMode') or 'return-to-dns'
                                desired_fallback_ip = pool.get('fallbackIp') or pool.get('fallback-ip', '')
                                fallback_needs_update = False

                                if getattr(pl, 'fallbackMode', None) != desired_fallback_mode:
                                    pl.fallbackMode = desired_fallback_mode
                                    fallback_needs_update = True

                                if desired_fallback_mode == 'fallback-ip' and desired_fallback_ip:
                                    if getattr(pl, 'fallbackIp', '') != desired_fallback_ip:
                                        pl.fallbackIp = desired_fallback_ip
                                        fallback_needs_update = True
                                elif desired_fallback_mode != 'fallback-ip':
                                    current_fallback_ip = getattr(pl, 'fallbackIp', 'any')
                                    if current_fallback_ip not in ('any', '', None):
                                        pl.fallbackIp = 'any'
                                        fallback_needs_update = True

                                if fallback_needs_update:
                                    log.info("GTM: [FALLBACK-RECONCILE] Pool %s: mode=%r fallbackIp=%r",
                                             pool_name, getattr(pl, 'fallbackMode', None), getattr(pl, 'fallbackIp', ''))
                                    pool_needs_update = True

                            if pool_needs_update:
                                pl.update()
                                pools_updated += 1
                        except Exception as e:
                            log.error("GTM: [MONITOR-RECONCILE] Error updating pool %s: %s", pool_name, e)
                            if self._is_not_found_error(e):
                                continue
                            if GTMUtils.is_transient_error(e):
                                raise F5CcclError(
                                    msg="Monitor reconcile failed for pool {}: {}".format(pool_name, e))
                            raise F5CcclError(
                                msg="Monitor reconcile failed for pool {}: {}".format(pool_name, e))

            # Data server monitor reconciliation.
            if reconcile_server:
                parsed = GTMUtils.parse_gtm_config_once(
                    gtmConfig, partition,
                    local_cluster_name=self._local_cluster_name,
                    digital_asset_id=self._cluster_digital_asset_id)
                desired_server_monitor = GTMUtils.default_data_server_monitor() if self._infrastructure._enable_data_server_monitor else ''

                for dataserver_ip in parsed.get('dataservers', set()):
                    server_name = GTMUtils.format_server_name(
                        dataserver_ip, self._local_cluster_name,
                        self._cluster_digital_asset_id)
                    try:
                        server_obj = self._load_bigip_resource_or_none(
                            self._infrastructure._gtm.servers.server.load,
                            'Server',
                            server_name,
                        )
                        if server_obj is None:
                            continue
                        current_monitor = getattr(server_obj, 'monitor', None)

                        if desired_server_monitor and current_monitor != desired_server_monitor:
                            log.info("GTM: [MONITOR-RECONCILE] Server %s: attaching monitor %s (was %r)",
                                     server_name, desired_server_monitor, current_monitor)
                            server_obj.monitor = desired_server_monitor
                            server_obj.update()
                            servers_updated += 1
                        elif not desired_server_monitor and current_monitor:
                            log.info("GTM: [MONITOR-RECONCILE] Server %s: removing monitor (was %r)",
                                     server_name, current_monitor)
                            server_obj.monitor = ''
                            server_obj.update()
                            servers_updated += 1
                    except Exception as e:
                        log.error("GTM: [MONITOR-RECONCILE] Error updating server %s: %s", server_name, e)
                        if self._is_not_found_error(e):
                            continue
                        if GTMUtils.is_transient_error(e):
                            raise F5CcclError(
                                msg="Monitor reconcile failed for server {}: {}".format(server_name, e))
                        raise F5CcclError(
                            msg="Monitor reconcile failed for server {}: {}".format(server_name, e))

            log.info("GTM: [MONITOR-RECONCILE] Complete - %d pool(s), %d server(s) updated",
                     pools_updated, servers_updated)
        except F5CcclError:
            raise
        except Exception as e:
            log.error("GTM: [MONITOR-RECONCILE] Unexpected error: %s", e)
            raise F5CcclError(msg="Monitor reconciliation failed: {}".format(e))

    def delete_update_gtm(self, partition, gtmConfig):
        """ Update GTM object in BIG-IP """
        try:
            oldConfig = self._gtm_config
            if partition not in oldConfig or partition not in gtmConfig:
                return
            opr_config = GTMUtils.process_config(oldConfig[partition], gtmConfig[partition])
            rev_map = GTMUtils.create_reverse_map(oldConfig[partition])
            # Resolve BIG-IP handle once, inside the partition guard.
            gtm = self.mgmt_root().tm.gtm

            # Process delete ALWAYS before create/update — enforced explicitly
            # rather than relying on dict iteration order.
            if opr_config.get("delete"):
                # Pass incoming gtmConfig so delete cleanup preserves
                # infrastructure still needed by the new config, and so
                # the commit step can restore surviving pool member lists
                # (preventing members=None from propagating to _gtm_config).
                self.handle_operation_delete(gtm, partition, opr_config["delete"], rev_map,
                                             incoming_config=gtmConfig)

                # Process any pending cleanup from delete BEFORE create runs
                # to prevent create from overwriting delete's pending cleanup state.
                if self._pending_cleanup is not None:
                    log.info("GTM: Processing pending delete cleanup before create operation")
                    self._cleanup.retry_pending_cleanup(self._pending_cleanup)
                    self._pending_cleanup = None

            for opr in ("create", "update"):
                if opr_config.get(opr):
                    self.handle_operation_create(gtm, partition, gtmConfig, opr_config[opr], opr)
        except F5CcclError as e:
            raise e

    # DELETE FIX: Build post-delete target config to correctly identify servers/VSs to remove
    def handle_operation_delete(self, gtm, partition, opr_config, rev_map, incoming_config=None):
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
                        oldConfig, partition, local_cluster_name=self._local_cluster_name,
                        digital_asset_id=self._cluster_digital_asset_id)
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
                        target_config, partition, local_cluster_name=self._local_cluster_name,
                        digital_asset_id=self._cluster_digital_asset_id)
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

            # Step 3: Delete wideIPs.
            # delete_wideip handles pool detachment internally (removes our pools by UID,
            # leaves other cluster pools untouched, only deletes wideip when no pools remain).
            if len(opr_config["wideIPs"]) > 0:
                for wideip_name in opr_config["wideIPs"]:
                    # Ownership check FIRST — if the WideIP is not ours, skip entirely.
                    # Our create was rejected earlier so it was never added to _gtm_config.
                    if not self._wideip.is_wideip_owned_by_this_cluster(wideip_name):
                        log.info("GTM: WideIP %s not owned by us — skipping delete.", wideip_name)
                        continue

                    self._wideip.delete_wideip(wideip_name, working_config=working_config)
                    # Always remove from internal config — Go already deleted its desired state.
                    self._remove_wideip_from_config(working_config, partition, wideip_name)

        except F5CcclError as e:
            code = _extract_http_code(str(e))
            log.error("GTM: Error while handling delete operation (Steps 1-3): %s, bigip: %s, error_code: %s",
                      e, self._bigip_host, code)
            raise e

        # CRITICAL FIX: Commit BEFORE cleanup phase
        # This ensures successful deletes are recorded even if cleanup fails.
        # Restore surviving pool member lists from incoming_config so that
        # _gtm_config never stores None for pools that weren't deleted.
        # delete_pool() sets members=None in working_config as a retry-safety
        # sentinel, but that sentinel must not propagate to the cached config
        # or subsequent delta computations (old_parsed) will produce empty sets,
        # breaking VS/server cleanup for all future cycles (AZ disable parity).
        if incoming_config and partition in working_config and partition in incoming_config:
            wc_wideips = working_config[partition].get('wideIPs') or []
            ic_wideip_index = {
                wip['name']: wip
                for wip in (incoming_config[partition].get('wideIPs') or [])
            }
            for wip in wc_wideips:
                ic_wip = ic_wideip_index.get(wip['name'])
                if ic_wip is None:
                    continue  # This wideIP was deleted — keep as-is
                ic_pool_index = {p['name']: p for p in ic_wip.get('pools') or []}
                for pool in wip.get('pools') or []:
                    ic_pool = ic_pool_index.get(pool['name'])
                    if ic_pool is not None and pool.get('members') is None:
                        pool['members'] = ic_pool.get('members')
        self._gtm_config = working_config
        log.debug("GTM: Committed config changes after successful delete operation")

        # Step 4: Clean up unused virtual servers
        # RENAME FIX: When incoming_config is provided (rename scenario), use it as
        # the cleanup target instead of target_config. This preserves infrastructure
        # (servers/VSs) that the new WideIP still needs.
        cleanup_config = incoming_config if incoming_config else target_config
        if incoming_config:
            cleanup_new_parsed = GTMUtils.parse_gtm_config_once(
                incoming_config, partition, local_cluster_name=self._local_cluster_name,
                digital_asset_id=self._cluster_digital_asset_id)
        else:
            cleanup_new_parsed = new_parsed

        # RESILIENCE FIX: Separate try block so GSLB server cleanup always runs
        # Errors here trigger retry but the successful delete work is already saved
        vs_cleanup_error = None
        datacenter_name = None
        if partition in cleanup_config:
            datacenter_name = cleanup_config[partition].get('dataCenter', None)
            if datacenter_name and '/' in datacenter_name:
                datacenter_name = datacenter_name.split('/')[-1]
        
        try:
            log.info("GTM: Cleaning up unused virtual servers")
            self._cleanup.cleanup_unused_virtual_servers(oldConfig, cleanup_config,
                                               old_parsed=old_parsed, new_parsed=cleanup_new_parsed)
        except Exception as e:
            log.error("GTM: VS cleanup failed, will still attempt server cleanup: %s", e)
            vs_cleanup_error = e

        # Step 5: Clean up unused GSLB servers using cleanup_config
        # RESILIENCE FIX: Always attempt, even if VS cleanup failed
        server_cleanup_error = None
        try:
            log.info("GTM: Cleaning up unused GSLB servers")
            self._cleanup.cleanup_unused_gslb_servers(datacenter_name, oldConfig, cleanup_config,
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
        # PERF: Defer the expensive deepcopy until we know there is actual work to do.
        # oldConfig is a direct reference — read-only, never mutated.
        oldConfig = self._gtm_config
        working_config = None

        old_parsed = None
        orchestration_parsed = None  # For infrastructure orchestration (uses filtered config)
        cleanup_parsed = None  # For cleanup phase (uses full configs — same as old single-GTM algorithm)

        try:
            if len(opr_config["pools"]) > 0 or len(opr_config["monitors"]) > 0 or len(opr_config["wideIPs"]) > 0:
                # Deep copy only when there is real work — avoids the cost on no-op calls.
                working_config = copy.deepcopy(self._gtm_config)
                log.debug("GTM: Parsing configs for create/update operation")
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
                    filtered_config, partition, local_cluster_name=self._local_cluster_name,
                    digital_asset_id=self._cluster_digital_asset_id)
                self._infrastructure.orchestrate_with_snapshot(filtered_config, orchestration_parsed, snapshot)

                # Parse FULL configs for cleanup diff — same algorithm as old single-GTM code.
                # Both sides must use the complete unmodified configs so that member refs are
                # consistent and only truly removed members are cleaned up.
                old_parsed = GTMUtils.parse_gtm_config_once(
                    oldConfig, partition, local_cluster_name=self._local_cluster_name,
                    digital_asset_id=self._cluster_digital_asset_id)
                cleanup_parsed = GTMUtils.parse_gtm_config_once(
                    gtmConfig, partition, local_cluster_name=self._local_cluster_name,
                    digital_asset_id=self._cluster_digital_asset_id)

                if partition in gtmConfig and "wideIPs" in gtmConfig[partition]:
                    if gtmConfig[partition]['wideIPs'] is not None:
                        # Pre-build index of oldConfig wideIPs → pool-name → pool dict
                        # so member delta lookup is O(1) per pool instead of O(W) per pool.
                        _old_wideip_pool_index = {}
                        if partition in oldConfig and oldConfig[partition].get('wideIPs'):
                            for _owip in oldConfig[partition]['wideIPs']:
                                _old_wideip_pool_index[_owip['name']] = {
                                    p['name']: p for p in _owip.get('pools', [])
                                }

                        for config in gtmConfig[partition]['wideIPs']:
                            # SKIP wideIPs that haven't changed
                            if config['name'] not in wideips_to_process:
                                continue

                            # Ownership check at the top — skip all BIG-IP ops if owned by another cluster
                            if not self._wideip.is_wideip_owned_by_this_cluster(config['name']):
                                log.warning("GTM: Skipping pool and wideip creation for %s — owned by another cluster", config['name'])
                                continue

                            # Pool-name → pool dict for this wideIP in oldConfig.
                            _old_pool_index = _old_wideip_pool_index.get(config['name'], {})

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
                                        monitor_ref = "/" + partition + "/" + monitor_name
                                        all_monitors += monitor_ref
                                        if monitor["name"] != pool["monitors"][-1]["name"]:
                                            all_monitors += " and "

                                # Delete removed members from BIG-IP pool.
                                # Compare old members (from stored config) against new members
                                # (from incoming gtmConfig) and remove only the delta.
                                # oldWideIP_pool_index is built once per wideIP outside the pool
                                # loop (see below) to avoid O(W) linear scan per pool.
                                oldPool = _old_pool_index.get(pool['name'])
                                if oldPool is not None and (oldPool['members'] is not None or pool['members'] is not None):
                                    oldPoolMember = set(oldPool['members'] or [])
                                    newPoolMember = set(pool['members'] or [])
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
                                                local_cluster_name=self._local_cluster_name,
                                                digital_asset_id=self._cluster_digital_asset_id)
                                            log.info("GTM: Deleting member {} (BIG-IP ref: {}) from pool {}".format(
                                                member, member_ref, oldPool['name']))
                                            self._pool.remove_member(oldPool['name'], member_ref, pool_obj=pool_obj)
                            try:
                                self._pool.create_pool(config, all_monitors, skip_member_validation=True)
                                self._wideip.create_wideip(config, newPools)
                            except F5CcclError as e:
                                raise e

        except F5CcclError as e:
            code = _extract_http_code(str(e))
            log.error("GTM: Error while handling create operation: %s, bigip: %s, error_code: %s",
                      e, self._bigip_host, code)
            raise e

        # Commit BEFORE cleanup phase — ensures successful creates are recorded
        # even if cleanup fails. Use gtmConfig as the authoritative post-operation
        # state (not working_config which only tracked monitor mutations on old structs).
        # This also prevents parse_gtm_config_once from seeing stale/None members on
        # the next cycle and incorrectly marking VSs as orphans for cleanup.
        if working_config is not None:
            if partition in gtmConfig:
                working_config[partition] = gtmConfig[partition]
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

            # Snapshot-based orphan member cleanup: catches the first-disable-after-startup
            # edge case where oldPool['members'] is None (no delta baseline) but BIG-IP
            # still holds stale members from a prior sync. The snapshot was taken before
            # create_pool ran, so pool_members reflects pre-operation BIG-IP state.
            # Scope to only the pools belonging to changed wideIPs to avoid unnecessary
            # API calls on unrelated pools.
            try:
                # Reuse cleanup_parsed['members_by_pool'] (already formatted pool names)
                # filtered to pools whose parent wideIP is in wideips_to_process.
                # This avoids rebuilding pool names from scratch.
                wideip_to_pools = {}
                for wip in gtmConfig.get(partition, {}).get('wideIPs', []) or []:
                    if wip['name'] in wideips_to_process:
                        wideip_to_pools[wip['name']] = {
                            GTMUtils.format_pool_name(
                                p['name'], self._local_cluster_name,
                                self._cluster_digital_asset_id)
                            for p in wip.get('pools', [])
                        }
                changed_pool_names = set().union(*wideip_to_pools.values()) if wideip_to_pools else set()
                scoped_expected = {
                    pool_name: members
                    for pool_name, members in cleanup_parsed['members_by_pool'].items()
                    if pool_name in changed_pool_names
                }
                scoped_snapshot = {
                    'pool_members': {
                        pool_name: actual
                        for pool_name, actual in snapshot['pool_members'].items()
                        if pool_name in changed_pool_names
                    }
                }
                log.info("GTM: Running snapshot-based orphan member cleanup for {} changed pool(s)".format(
                    len(changed_pool_names)))
                self._cleanup.cleanup_orphaned_members_with_snapshot(scoped_expected, scoped_snapshot)
            except Exception as e:
                log.error("GTM: Snapshot-based orphan member cleanup failed (non-fatal): %s", e)

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
                gtmConfig, partition, local_cluster_name=self._local_cluster_name,
                digital_asset_id=self._cluster_digital_asset_id)

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
                        if self._snapshot_helper.wideip_fully_exists(
                                config,
                                snapshot,
                                enable_data_server_monitor=self._infrastructure._enable_data_server_monitor):
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
                log.info("GTM: [INIT-SYNC] All {} wideIPs fully match snapshot — skipping infrastructure and processing".format(
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
                            self._monitor.create_monitor(monitor, config['name'])
                            monitor_name = GTMUtils.apply_cluster_prefix(
                                monitor['name'], self._local_cluster_name)
                            monitor_ref = "/" + partition + "/" + monitor_name
                            all_monitors += monitor_ref
                            if monitor["name"] != pool["monitors"][-1]["name"]:
                                all_monitors += " and "
                # PRE-CHECK: Skip entire wideip entry if owned by another cluster
                if not self._wideip.is_wideip_owned_by_this_cluster(config['name']):
                    log.warning("GTM: [INIT-SYNC] Skipping pool and wideip creation for %s — owned by another cluster", config['name'])
                    continue
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
            code = _extract_http_code(str(e))
            log.error("GTM: Error while creating gtm: %s, bigip: %s, error_code: %s",
                      e, self._bigip_host, code)
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
    cluster_digital_asset_id = None
    namespace = None

    if config and 'global' in config:
        global_cfg = config['global']

        # Support both camelCase (new spec) and kebab-case (legacy)
        log_level = global_cfg.get('logLevel') or global_cfg.get('log-level')
        if log_level:
            try:
                level = logging.getLevelName(log_level.upper())
            except (AttributeError):
                log.warn('The "global:log-level" field in the configuration '
                         'file should be a string')

        _vi_raw = (
            global_cfg.get('verifyInterval')
            if 'verifyInterval' in global_cfg
            else global_cfg.get('verify-interval')
        )
        if _vi_raw is not None:
            try:
                verify_interval = float(_vi_raw)
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
        cluster_digital_asset_id = global_cfg.get('cluster-digital-asset-id')
        namespace = global_cfg.get('namespace')
        # cluster-identifier is written by Go's globalSection for the legacy single-GTM path.
        # Takes precedence over local-cluster-name when set, matching main() line 1810 logic.
        cluster_identifier = global_cfg.get('cluster-identifier')
        if cluster_identifier:
            local_cluster_name = cluster_identifier

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

    return verify_interval, level, vxlan_partition, local_cluster_name, cluster_digital_asset_id, namespace


def get_credentials(socket_path=None):
    """
    Unified function to retrieve credentials.
    Priority order:
      1. Unix socket (path from config's 'credential_socket' key, or default)
      2. Environment variables (BIGIP_USERNAME/BIGIP_PASSWORD, GTM_BIGIP_USERNAME/GTM_BIGIP_PASSWORD)
      3. Copy BIGIP creds → GTM creds when no dedicated GTM creds are available

    For the multi-GTM worker path the socket always contains both bigip_ and gtm_
    fields set to the same endpoint creds.  For the single-GTM path the socket may
    return empty gtm_ fields, in which case we fall back to BIGIP creds (step 3).

    Args:
        socket_path: Optional custom Unix socket path.
    """
    credentials = get_credentials_from_socket(socket_path) or {}

    # Fill BIGIP creds from env if socket did not supply them
    if not credentials.get("bigip_username") or not credentials.get("bigip_password"):
        env_credentials = get_credentials_from_env()
        if env_credentials:
            username, password = env_credentials
            credentials['bigip_username'] = username
            credentials['bigip_password'] = password

    # Fill GTM creds from env ONLY if socket did not supply them AND env vars are set.
    # Skip the env lookup entirely when the socket returned empty GTM fields — in that
    # case the single-GTM fallback below (copy from BIGIP) is the correct behaviour and
    # avoids a spurious DEBUG lookup + misleading log lines.
    socket_had_gtm = bool(credentials.get("gtm_username")) or bool(credentials.get("gtm_password"))
    if not socket_had_gtm:
        gtm_env_credentials = get_gtm_credentials_from_env()
        if gtm_env_credentials:
            username, password = gtm_env_credentials
            credentials['gtm_username'] = username
            credentials['gtm_password'] = password

    # Single-GTM fallback: no dedicated GTM creds → reuse BIGIP creds
    if not credentials.get("gtm_username"):
        credentials["gtm_username"] = credentials.get("bigip_username", "")
    if not credentials.get("gtm_password"):
        credentials["gtm_password"] = credentials.get("bigip_password", "")

    if not credentials.get("bigip_username") or not credentials.get("bigip_password"):
        log.error("No valid BIGIP credentials could be obtained from socket or environment variables.")
        return None

    return credentials


def get_credentials_from_env():
    log.debug("Checking for credentials in environment variables...")
    username = os.getenv("BIGIP_USERNAME")
    password = os.getenv("BIGIP_PASSWORD")

    if username and password:
        log.info("Successfully fetched BIGIP credentials from environment variables.")
        return username, password
    else:
        # Not an error — env vars are optional when the socket path is the credential source.
        log.debug("BIGIP_USERNAME/BIGIP_PASSWORD env vars not set (socket-based auth in use).")
        return None


def get_gtm_credentials_from_env():
    log.debug("Checking for GTM credentials in environment variables...")
    username = os.getenv("GTM_BIGIP_USERNAME")
    password = os.getenv("GTM_BIGIP_PASSWORD")

    if username and password:
        log.info("Successfully fetched GTM credentials from environment variables.")
        return username, password
    else:
        # Not an error — GTM env vars are optional; GTM creds may come from the socket
        # or fall back to BIGIP creds (single-GTM case).
        log.debug("GTM_BIGIP_USERNAME/GTM_BIGIP_PASSWORD env vars not set.")
        return None


def get_credentials_from_socket(socket_path=None):
    if socket_path is None:
        socket_path = "/tmp/secure_ebc.sock"

    client = None
    retry_interval = 0.5
    # max_wait_seconds is used for EACH of the two phases below:
    #   Phase 1: wait up to max_wait_seconds for the socket file to appear
    #   Phase 2: up to connect_attempts × retry_interval to successfully connect
    # Total worst-case wait = 2 × max_wait_seconds.
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
                    log.info("Successfully fetched BIGIP credentials from socket.")
                if credentials.get('gtm_username', '') != "" and credentials.get('gtm_password', '') != "":
                    log.info("Successfully fetched GTM credentials from socket.")
                # E7: Retrieve optional trusted certs (TLS CA certificate) for each endpoint
                if credentials.get('cert_data', '') != "":
                    log.info("Successfully fetched trusted certificate from socket.")
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
    credential_socket = config.get('credential_socket', '/tmp/secure_ebc.sock')
    credentials = get_credentials(credential_socket)
    if not credentials:
        raise ConfigError('Failed to retrieve valid BIG-IP credentials')

    config['bigip']['username'] = credentials['bigip_username']
    config['bigip']['password'] = credentials['bigip_password']
    # E7: Optional trusted certs from socket — stored at bigip level for all partition managers
    config['bigip']['trusted_certs'] = credentials.get('cert_data', '')
    if 'gtm_bigip' in config:
        config['gtm_bigip']['username'] = credentials.get(
            'gtm_username', credentials['bigip_username'])
        config['gtm_bigip']['password'] = credentials.get(
            'gtm_password', credentials['bigip_password'])
        # E7: GTM also gets the trusted certs from socket
        config['gtm_bigip']['trusted_certs'] = credentials.get('cert_data', '')
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


def _extract_http_code(error_msg):
    """Extract HTTP status code from an error string, defaulting to 500."""
    m = re.search(r'\b([45]\d{2})\b', str(error_msg))
    return m.group(1) if m else '500'


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
    # Support both camelCase (new spec) and kebab-case (legacy)
    try:
        global_cfg = config['global']
        return global_cfg.get('disableLTM', global_cfg.get('disable-ltm', False))
    except KeyError:
        return False


def _is_arp_disabled(config):
    # Support both camelCase (new spec) and kebab-case (legacy)
    try:
        global_cfg = config['global']
        return global_cfg.get('disableARP', global_cfg.get('disable-arp', False))
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
        verify_interval, _, vxlan_partition, local_cluster_name, cluster_digital_asset_id, namespace = _handle_global_config(config)
        # Keep gtm.clusterIdentifier, gtm.digitalAssetID, and gtm.namespace independent from global defaults.
        local_cluster_name = config.get('gtm', {}).get('clusterIdentifier') or local_cluster_name
        cluster_digital_asset_id = config.get('gtm', {}).get('digitalAssetID') or cluster_digital_asset_id
        namespace = config.get('gtm', {}).get('namespace') or namespace
        config = _handle_credentials(config)
        host, port = _handle_bigip_config(config)

        # E7: Prepare temporary cert file(s) for TLS verification.
        # In GTM-only mode the BIG-IP and GTM endpoints resolve to the same
        # GTM VE and use the same CA cert from certSecret.  Share one temp
        # file between the two ManagementRoot sessions so only one PEM is
        # created per GTM endpoint.
        worker_id = config.get('worker_id', '')
        bigip_trusted_certs = config['bigip'].get('trusted_certs', '')
        gtm_trusted_certs = config['gtm_bigip'].get('trusted_certs', '') \
            if 'gtm_bigip' in config else ''
        if bigip_trusted_certs and bigip_trusted_certs == gtm_trusted_certs:
            shared_ca_certs_path = _create_temp_cert_file(
                bigip_trusted_certs, 'bigip', worker_id)
            bigip_ca_certs_path = shared_ca_certs_path
            gtm_ca_certs_path = shared_ca_certs_path
            log.debug('Using shared temporary certificate file for bigip and gtm_bigip')
        else:
            bigip_ca_certs_path = _create_temp_cert_file(
                bigip_trusted_certs, 'bigip', worker_id) if bigip_trusted_certs else None
            gtm_ca_certs_path = _create_temp_cert_file(
                gtm_trusted_certs, 'gtmbigip', worker_id) if gtm_trusted_certs else None

        # BIG-IP to manage
        def _bigip_connect_cb(log_success):
            try:
                bigip = mgmt_root(
                    host,
                    config['bigip']['username'],
                    config['bigip']['password'],
                    port,
                    "tmos",
                    ca_certs=bigip_ca_certs_path)
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
                    "tmos",
                    ca_certs=gtm_ca_certs_path)
                if log_success:
                    log.info('GTM BIG-IP connection established, bigip: %s', host)
                return (True, bigip)
            except Exception as e:
                code = _extract_http_code(str(e))
                error = 'GTM BIG-IP connection error: {}, bigip: {}, error_code: {}'.format(e, host, code)
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
                    local_cluster_name=local_cluster_name,
                    cluster_digital_asset_id=cluster_digital_asset_id)
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
    finally:
        # E7: Cleanup temporary certificate files on shutdown
        # Ensures no orphaned cert files remain after process terminates
        _cleanup_temp_cert_files()
    
    return 0


if __name__ == "__main__":
    main()
