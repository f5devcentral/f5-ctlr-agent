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
GTM WideIP operations module.

This module handles all WideIP-related operations including creation,
updates, deletion, and pool attachment.
"""

import logging
from f5_cccl.exceptions import F5CcclError
from f5_ctlr_agent.gtm.utils import GTMUtils

log = logging.getLogger(__name__)


class GTMWideIP:
    """Manages GTM WideIP resources."""
    
    def __init__(self, gtm, partition, local_cluster_name=None, cluster_digital_asset_id=None):
        """Initialize WideIP manager.

        Args:
            gtm: BIG-IP GTM object
            partition (str): Partition to manage
            local_cluster_name (str, optional): Cluster identifier
            cluster_digital_asset_id (str, optional): Cluster digital asset ID for ownership tagging
        """
        self._gtm = gtm
        self._partition = partition
        self._local_cluster_name = local_cluster_name
        self._cluster_digital_asset_id = cluster_digital_asset_id

    def _prefixed_pool_name(self, pool_name):
        return GTMUtils.format_pool_name(
            pool_name,
            self._local_cluster_name,
            self._cluster_digital_asset_id)

    def _normalize_pool_map(self, newPools):
        normalized = {}
        for pool in newPools.values():
            prefixed_name = self._prefixed_pool_name(pool['name'])
            normalized[prefixed_name] = {
                'name': prefixed_name,
                'partition': pool['partition'],
                'ratio': pool['ratio'],
                'order': pool['order']
            }
        return normalized
    
    def create_wideip(self, config, newPools):
        """Create wideip and returns the wideip object.

        Args:
            config (dict): WideIP configuration with keys:
                          - name: WideIP name
                          - Load BalancingMode: Load balancing mode
                          - aliases (optional): list of DNS aliases
                          - domain-name / domain-suffix (optional): used by pre_process_gtm
            newPools (dict): Pools to attach to WideIP

        Returns:
            WideIP object or None
        """
        try:
            newPools = self._normalize_pool_map(newPools)

            # Enhancement 4: Build ownership description for multi-cluster scoping
            description = None
            if self._cluster_digital_asset_id or self._local_cluster_name:
                parts = []
                if self._local_cluster_name:
                    parts.append(self._local_cluster_name)
                if self._cluster_digital_asset_id:
                    parts.append(self._cluster_digital_asset_id)
                cluster_part = "-".join(parts)
                description = "managed-by: ebc | cluster: {}".format(cluster_part)

            # Enhancement 2: Alias support
            aliases = config.get('aliases') or []

            exist = self._gtm.wideips.a_s.a.exists(name=config['name'], partition=self._partition)
            if not exist:
                log.info('GTM: Creating wideip {}'.format(config['name']))
                create_kwargs = {
                    'name': config['name'],
                    'partition': self._partition,
                    'lastResortPool': "none",
                    'poolLbMode': config['LoadBalancingMode'],
                }
                if description:
                    create_kwargs['description'] = description
                if aliases:
                    create_kwargs['aliases'] = aliases
                self._gtm.wideips.a_s.a.create(**create_kwargs)
                self.attach_pool_to_wideip(config['name'], list(newPools.values()))
            else:
                wideip = self._gtm.wideips.a_s.a.load(
                    name=config['name'],
                    partition=self._partition)
                needs_update = False
                if wideip.poolLbMode != config['LoadBalancingMode']:
                    wideip.poolLbMode = config['LoadBalancingMode']
                    needs_update = True
                if description and getattr(wideip, 'description', None) != description:
                    wideip.description = description
                    needs_update = True
                current_aliases = sorted(getattr(wideip, 'aliases', None) or [])
                if sorted(aliases) != current_aliases:
                    wideip.aliases = aliases
                    needs_update = True
                if needs_update:
                    wideip.update()
                duplicatePools = []
                if hasattr(wideip, 'pools'):
                    for p in newPools.keys():
                        if hasattr(wideip.raw['pools'], p):
                            duplicatePools.append(p)

                for poolName in duplicatePools:
                    del newPools[poolName]

                if len(newPools) > 0:
                    self.attach_pool_to_wideip(
                        config['name'],
                        list(newPools.values()))
        except F5CcclError as e:
            log.error("GTM: Error while creating wideip: %s", e)
            raise e
    
    def attach_pool_to_wideip(self, name, poolObj):
        """Attach gtm pool to the wideip.
        
        Args:
            name (str): WideIP name
            poolObj (list): List of pool objects to attach
        """
        try:
            wideip = self._gtm.wideips.a_s.a.load(name=name, partition=self._partition)
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
    
    def remove_pool_from_wideip(self, wideipName, poolName):
        """Remove gtm pool from the wideip.
        
        Args:
            wideipName (str): Name of the WideIP
            poolName (str): Name of the pool to remove
        """
        try:
            prefixed_pool_name = self._prefixed_pool_name(poolName)
            # CRITICAL FIX: Check existence FIRST before attempting load
            try:
                if not self._gtm.wideips.a_s.a.exists(name=wideipName, partition=self._partition):
                    log.info("GTM: WideIP {} already absent, treating pool removal as success".format(wideipName))
                    return  # SUCCESS - wideIP doesn't exist, so pool is already removed
            except Exception as e:
                # exists() call failed with transient error
                if GTMUtils.is_transient_error(e):
                    log.warning("GTM: Transient error checking wideIP {} existence: {}".format(wideipName, str(e)))
                    raise F5CcclError(msg="Transient error checking wideIP existence: {}".format(str(e)))
                else:
                    # Permanent error on exists() - treat as "doesn't exist" (success for pool removal)
                    log.info("GTM: Permanent error checking wideIP {} existence, treating as absent: {}".format(
                        wideipName, str(e)))
                    return
            
            # WideIP exists - proceed with load
            try:
                wideip = self._gtm.wideips.a_s.a.load(name=wideipName, partition=self._partition)
            except Exception as e:
                # Load failed - check if it's 404 (race condition)
                error_str = str(e).lower()
                if '404' in error_str or 'not found' in error_str:
                    log.info("GTM: WideIP {} deleted between exists and load, treating as success".format(wideipName))
                    return
                if GTMUtils.is_transient_error(e):
                    log.warning("GTM: Transient error loading wideIP {}: {}".format(wideipName, str(e)))
                    raise F5CcclError(msg="Transient error loading wideIP {}: {}".format(wideipName, str(e)))
                else:
                    log.error("GTM: Permanent error loading wideIP {}: {}".format(wideipName, str(e)))
                    raise F5CcclError(msg="Permanent error loading wideIP {}: {}".format(wideipName, str(e)))
            
            # WideIP loaded successfully - remove pool
            if wideip.lastResortPool == "":
                wideip.lastResortPool = "none"
            if hasattr(wideip, 'pools'):
                for pool in wideip.pools:
                    if pool["name"] == prefixed_pool_name:
                        wideip.pools.remove(pool)
                        wideip.update()
                        log.info("GTM: Removed pool {} from wideIP {}".format(prefixed_pool_name, wideipName))
                        return
                log.debug("GTM: Pool {} not found in wideIP {} pools (already removed)".format(prefixed_pool_name, wideipName))
            else:
                log.debug("GTM: WideIP {} has no pools attribute".format(wideipName))
        except F5CcclError:
            raise
        except Exception as e:
            error_str = str(e).lower()
            if '404' in error_str or 'not found' in error_str:
                log.info("GTM: WideIP {} not found (404), treating pool removal as success: {}".format(wideipName, str(e)))
                return
            if GTMUtils.is_transient_error(e):
                log.error("GTM: Transient error during pool removal: {}".format(str(e)))
                raise F5CcclError(msg="Transient error removing pool: {}".format(str(e)))
            else:
                log.warning("GTM: Permanent error during pool removal (treating as success): {}".format(str(e)))
    
    def delete_wideip(self, wideipName, working_config=None):
        """Delete gtm wideip.
        
        Args:
            wideipName (str): Name of the WideIP to delete
            working_config (dict, optional): Working config to update
            
        Returns:
            bool: True if deleted or already absent
        """
        try:
            log.info("GTM: Attempting to delete wideIP {} in partition {}".format(wideipName, self._partition))
            
            # Check existence FIRST
            try:
                if not self._gtm.wideips.a_s.a.exists(name=wideipName, partition=self._partition):
                    log.info("GTM: WideIP {} already absent, treating delete as success".format(wideipName))
                    return True
            except Exception as e:
                if GTMUtils.is_transient_error(e):
                    log.warning("GTM: Transient error checking wideIP existence: {}".format(str(e)))
                    raise F5CcclError(msg="Transient error checking wideIP existence: {}".format(str(e)))
                else:
                    log.info("GTM: Permanent error checking wideIP existence, treating as absent: {}".format(str(e)))
                    return True
            
            # WideIP exists - proceed with delete
            try:
                wideip = self._gtm.wideips.a_s.a.load(name=wideipName, partition=self._partition)

                # Ownership-scoped delete: skip deletion when the WideIP's description
                # indicates it is owned by a different CIS cluster.
                #
                # Description format written by create_wideip():
                #   "managed-by: cis | cluster: <cluster_part>"
                # where cluster_part = "-".join(filter(None, [local_cluster_name, digital_asset_id]))
                #
                # The gate mirrors create_wideip: check activates when EITHER
                # local_cluster_name OR cluster_digital_asset_id is set, because BNK
                # mode uses digital_asset_id alone (no cluster-name) to stamp ownership.
                #
                # We skip deletion when ALL of these are true:
                #   1. This CIS instance has at least one ownership identifier set
                #   2. The WideIP has a non-empty description containing "cluster: "
                #   3. The cluster_part in the description does NOT match our composite
                our_name = self._local_cluster_name or ''
                our_asset = self._cluster_digital_asset_id or ''
                # Rebuild composite exactly as create_wideip does
                our_parts = [p for p in [our_name, our_asset] if p]
                our_composite = '-'.join(our_parts)  # "" when both empty

                if our_composite:
                    existing_description = getattr(wideip, 'description', '') or ''
                    if existing_description and 'cluster: ' in existing_description:
                        marker = 'cluster: '
                        marker_start = existing_description.index(marker) + len(marker)
                        cluster_value = existing_description[marker_start:].strip()
                        if cluster_value != our_composite:
                            log.warning(
                                "GTM: Skipping delete of WideIP %s — owned by another cluster "
                                "(description: %r, our composite: %r)",
                                wideipName, existing_description, our_composite)
                            return False

                # Fix lastResortPool if empty (BIG-IP API guard)
                if wideip.lastResortPool == "":
                    wideip.lastResortPool = "none"
                    wideip.update()
                
                # Check if pools are still attached
                if hasattr(wideip, 'pools') and len(wideip.pools) > 0:
                    log.debug("GTM: Cannot delete wideIP {} - pools still attached".format(wideipName))
                    return False
                    
                wideip.delete()
                log.info("GTM: Deleted wideIP {}".format(wideipName))
                return True
            except Exception as e:
                error_str = str(e).lower()
                if '404' in error_str or 'not found' in error_str:
                    log.info("GTM: WideIP {} already deleted (404): {}".format(wideipName, str(e)))
                    return True
                if GTMUtils.is_transient_error(e):
                    log.error("GTM: Transient error deleting wideIP {}: {}".format(wideipName, str(e)))
                    raise F5CcclError(msg="Transient error deleting wideIP: {}".format(str(e)))
                else:
                    log.debug("GTM: Permanent error deleting wideIP {} (treating as success): {}".format(wideipName, str(e)))
                    return True
                    
        except F5CcclError:
            raise
        except Exception as e:
            log.error("GTM: Unexpected error deleting wideIP {}: {}".format(wideipName, str(e)))
            raise F5CcclError(msg="Error deleting wideIP: {}".format(str(e)))
