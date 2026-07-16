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

"""
GTM snapshot functionality for capturing BIG-IP state.

This module handles efficient state capture of existing GTM resources
on the BIG-IP to avoid redundant operations.
"""

import logging
import time
from f5_cccl.exceptions import F5CcclError
from f5_ctlr_agent.gtm.utils import GTMUtils

log = logging.getLogger(__name__)


class GTMSnapshot:
    """Captures and manages BIG-IP GTM state snapshots."""
    
    def __init__(self, gtm, partition, local_cluster_name=None, cluster_digital_asset_id=None):
        """Initialize GTMSnapshot.
        
        Args:
            gtm: BIG-IP GTM object from management root
            partition (str): Partition to snapshot
            local_cluster_name (str, optional): Cluster identifier
            cluster_digital_asset_id (str, optional): Cluster digital asset ID
        """
        self._gtm = gtm
        self._partition = partition
        self._local_cluster_name = local_cluster_name
        self._cluster_digital_asset_id = cluster_digital_asset_id
    
    def snapshot_bigip_state(self, gtmConfig):
        """Optimized config-driven BIG-IP state snapshot.
        
        Skips VS fetching — VS existence is inferred from pool member existence.
        If all pool members match, VSs are guaranteed to exist (VSs are prerequisites for members).
        If some wideIPs need processing, VS names are fetched lazily in orchestration.
        
        Args:
            gtmConfig (dict): GTM configuration to snapshot against
            
        Returns:
            dict: Snapshot with keys:
                  - servers: set of server names
                  - server_vs: dict {server_name: set(vs_names)} 
                  - pools: set of pool names
                  - pool_members: dict {pool_name: set(member_refs)}
                  - wideips: set of wideip names
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
        #    If needed, VSs loaded lazily during orchestration
        # ---------------------------------------------------------------
        all_servers = self._gtm.servers.get_collection()
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
        if self._partition not in gtmConfig or 'wideIPs' not in gtmConfig[self._partition]:
            total_time = time.time() - start_time
            log.info("GTM: [SNAPSHOT] Complete in {:.1f}s — no wideIPs in config".format(total_time))
            return snapshot

        wideips = gtmConfig[self._partition].get('wideIPs', []) or []

        pools_to_check = set()
        for wip in wideips:
            for pool in wip.get('pools', []):
                pools_to_check.add(
                    GTMUtils.format_pool_name(
                        pool['name'], self._local_cluster_name,
                        self._cluster_digital_asset_id))

        pool_start = time.time()
        pools_found = 0
        pools_missing = 0

        for pool_name in pools_to_check:
            try:
                pool_obj = self._gtm.pools.a_s.a.load(name=pool_name, partition=self._partition)
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
                if self._gtm.wideips.a_s.a.exists(name=wip_name, partition=self._partition):
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
    
    def wideip_fully_exists(self, config, snapshot):
        """Check if wideIP fully exists with correct members.
        
        Zero API calls — pure in-memory comparison.
        
        Args:
            config (dict): WideIP configuration to check
            snapshot (dict): State snapshot from snapshot_bigip_state()
            
        Returns:
            bool: True if wideIP exists with all correct pool members
        """
        wideip_name = config['name']
        
        # Check wideIP exists
        if wideip_name not in snapshot['wideips']:
            return False
        
        # Check all pools exist with correct members
        for pool in config.get('pools', []):
            pool_name = GTMUtils.format_pool_name(
                pool['name'], self._local_cluster_name,
                self._cluster_digital_asset_id)
            
            # Pool must exist
            if pool_name not in snapshot['pools']:
                return False
            
            # Get expected members from config
            expected_members = set()
            pool_dataserver = pool.get('DataServer')
            pool_namespace = pool.get('namespace')
            
            for member_spec in pool.get('members', []):
                member_ref = GTMUtils.convert_member_to_bigip_reference(
                    member_spec,
                    pool_dataserver,
                    local_cluster_name=self._local_cluster_name,
                    digital_asset_id=self._cluster_digital_asset_id,
                    namespace=pool_namespace)
                expected_members.add(member_ref)
            
            # Get actual members from snapshot
            actual_members = snapshot['pool_members'].get(pool_name, set())
            
            # Members must match exactly
            if expected_members != actual_members:
                return False
        
        return True
