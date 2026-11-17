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
    
    def _get_our_composite(self):
        """Build the composite cluster identifier used in WideIP description.

        Returns:
            str: Composite cluster identifier, or empty string in legacy mode.
        """
        our_name = self._local_cluster_name or ''
        our_asset = self._cluster_digital_asset_id or ''
        our_parts = [p for p in [our_name, our_asset] if p]
        return '-'.join(our_parts)

    def build_description(self):
        """Return the ownership description for new WideIPs, or None when unscoped."""
        if not (self._cluster_digital_asset_id or self._local_cluster_name):
            return None
        parts = []
        if self._local_cluster_name:
            parts.append(self._local_cluster_name)
        if self._cluster_digital_asset_id:
            parts.append(self._cluster_digital_asset_id)
        return "managed-by: ebc | cluster: {}".format("-".join(parts))

    def is_wideip_owned_by_this_cluster(self, wideip_name, wideip=None):
        """Return True when this cluster owns the WideIP or legacy mode allows it.

        Args:
            wideip_name (str): Name of the WideIP (used for BIG-IP lookup and logging).
            wideip (optional): Already-loaded BIG-IP WideIP object. When provided the
                               BIG-IP exists/load calls are skipped entirely.

        Returns:
            bool: True if this cluster owns the WideIP (or legacy mode allows it).
        """
        if wideip is None:
            try:
                if not self._gtm.wideips.a_s.a.exists(name=wideip_name, partition=self._partition):
                    # WideIP doesn't exist yet — safe to create.
                    log.debug(
                        "GTM: is_wideip_owned_by_this_cluster: %s does not exist yet; allowing create",
                        wideip_name)
                    return True
                wideip = self._gtm.wideips.a_s.a.load(name=wideip_name, partition=self._partition)
            except Exception as e:
                # On error, be conservative — allow creation so we don't silently drop configs.
                log.warning(
                    "GTM: Error checking wideip %s ownership (allowing creation): %s",
                    wideip_name, str(e))
                return True

        uid = self._cluster_digital_asset_id
        existing_description = getattr(wideip, 'description', '') or ''

        if not uid:
            if not existing_description:
                log.debug(
                    "GTM: WideIP %s has no description in legacy mode; treating as owned",
                    wideip_name)
                return True
            log.debug(
                "GTM: WideIP %s has description %r in legacy mode; treating as not owned",
                wideip_name, existing_description)
            return False

        if not existing_description:
            log.debug("GTM: WideIP %s has no description — not owned by us", wideip_name)
            return False

        if uid in existing_description:
            return True

        log.debug(
            "GTM: WideIP %s description %r does not contain our UID %r — not ours",
            wideip_name, existing_description, uid)
        return False

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

        Note:
            If a WideIP with the same name already exists on BIG-IP but is owned
            by a *different* cluster (determined by the description field), this
            method logs a warning and skips creation/update entirely.  This
            prevents one cluster from silently hijacking another cluster's WideIP.
        """
        try:
            newPools = self._normalize_pool_map(newPools)

            # Enhancement 4: Build ownership description for multi-cluster scoping
            description = self.build_description()

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

                # CROSS-CLUSTER GUARD: Reject creation/update if the WideIP is
                # owned by a different cluster.  This is the primary defense against
                # "same WideIP created across clusters" creating conflicting state.
                if not self.is_wideip_owned_by_this_cluster(config['name'], wideip=wideip):
                    existing_description = getattr(wideip, 'description', '') or ''
                    our_composite = self._get_our_composite()
                    log.warning(
                        "GTM: REJECTED create/update of WideIP %s — already owned by "
                        "another cluster (description: %r, our composite: %r). "
                        "Skipping pool attachment to prevent cross-cluster conflict.",
                        config['name'], existing_description, our_composite)
                    return  # Do NOT attach pools or modify the wideip

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
                removed = False
                for pool in list(wideip.pools):
                    pool_name_on_bigip = pool["name"] if isinstance(pool, dict) else getattr(pool, 'name', '')
                    if pool_name_on_bigip == prefixed_pool_name:
                        wideip.pools.remove(pool)
                        wideip.update()
                        log.info("GTM: Removed pool {} from wideIP {}".format(pool_name_on_bigip, wideipName))
                        removed = True
                        break
                if not removed:
                    log.debug("GTM: Pool {} not found in wideIP {} pools "
                              "(already removed)".format(prefixed_pool_name, wideipName))
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

        Multi-cluster aware deletion logic:
        1. If we don't own the WideIP (description belongs to another cluster) → skip entirely.
        2. If we own it, first detach only our cluster's pools from the WideIP.
        3. After removing our pools, if no pools remain → delete the WideIP.
        4. If other clusters' pools remain → leave the WideIP in place but return True so the
           caller can remove it from the internal config (we are done with it from our side).

        Args:
            wideipName (str): Name of the WideIP to delete
            working_config (dict, optional): Working config to update (unused, kept for compat)

        Returns:
            bool: True if this cluster's ownership/interest is fully resolved
                  (either deleted, already absent, or our pools removed from a shared WideIP).
                  False only when the WideIP is owned by a different cluster entirely.
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

            # WideIP exists - proceed with load
            try:
                wideip = self._gtm.wideips.a_s.a.load(name=wideipName, partition=self._partition)
            except Exception as e:
                error_str = str(e).lower()
                if '404' in error_str or 'not found' in error_str:
                    log.info("GTM: WideIP {} already deleted (404): {}".format(wideipName, str(e)))
                    return True
                if GTMUtils.is_transient_error(e):
                    log.error("GTM: Transient error loading wideIP {}: {}".format(wideipName, str(e)))
                    raise F5CcclError(msg="Transient error loading wideIP: {}".format(str(e)))
                else:
                    log.debug("GTM: Permanent error loading wideIP {} (treating as success): {}".format(wideipName, str(e)))
                    return True

            # ----------------------------------------------------------------
            # Ownership check: skip entirely if owned by a different cluster.
            # UID in description = we own it; no description or different UID = not ours.
            # ----------------------------------------------------------------
            if not self.is_wideip_owned_by_this_cluster(wideipName, wideip=wideip):
                existing_description = getattr(wideip, 'description', '') or ''
                our_composite = self._get_our_composite()
                log.warning(
                    "GTM: Skipping delete of WideIP %s — owned by another cluster "
                    "(description: %r, our composite: %r)",
                    wideipName, existing_description, our_composite)
                return False

            # Fix lastResortPool if empty (BIG-IP API guard)
            if wideip.lastResortPool == "":
                wideip.lastResortPool = "none"
                wideip.update()

            # Remove only pools belonging to this cluster (UID in pool name).
            # If other cluster pools remain, don't delete the WideIP — just return True.
            uid = self._cluster_digital_asset_id
            if hasattr(wideip, 'pools') and wideip.pools:
                wideip = self._gtm.wideips.a_s.a.load(name=wideipName, partition=self._partition)
                if wideip.lastResortPool == "":
                    wideip.lastResortPool = "none"

                pools_after_removal = []
                our_pools_removed = []

                for pool_entry in (wideip.pools or []):
                    pool_entry_name = pool_entry.get('name', '') if isinstance(pool_entry, dict) else getattr(pool_entry, 'name', '')
                    # Pool name format: pool-<uid>-<cluster>-<domain>
                    # Use startswith to match precisely at the uid position (pool-<uid>-).
                    # UID is assumed to always be present — skip deletion if uid is empty.
                    if uid and (pool_entry_name.startswith("pool-" + uid + "-") or pool_entry_name == "pool-" + uid):
                        our_pools_removed.append(pool_entry_name)
                    else:
                        # uid empty OR pool belongs to another cluster → leave it
                        pools_after_removal.append(pool_entry)

                if our_pools_removed:
                    log.info("GTM: Removing our pools {} from wideIP {} before deletion".format(
                        our_pools_removed, wideipName))
                    wideip.pools = pools_after_removal
                    try:
                        wideip.update()
                        log.info("GTM: Removed {} pool(s) from wideIP {}".format(
                            len(our_pools_removed), wideipName))
                    except Exception as update_err:
                        log.error("GTM: Error updating wideIP {} after pool removal: {}".format(
                            wideipName, str(update_err)))
                        raise F5CcclError(msg="Error removing pools from wideIP: {}".format(str(update_err)))

                if len(pools_after_removal) > 0:
                    log.info("GTM: WideIP {} still has {} pool(s) from other cluster(s) — not deleting.".format(
                        wideipName, len(pools_after_removal)))
                    return True
            else:
                log.debug("GTM: WideIP {} has no pools attached".format(wideipName))

            # No remaining pools — safe to delete the WideIP
            try:
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
