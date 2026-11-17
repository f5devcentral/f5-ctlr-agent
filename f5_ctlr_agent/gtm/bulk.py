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

"""GTM bulk operations for large syncs.

Replaces thousands of per-object REST calls with a few bulk reads and
transactional batch writes. Everything here is an optimization: a failed batch
is handed back to the caller, which creates those objects through the regular
per-object path (which is idempotent and enforces cluster ownership).

Set GTM_BULK_SYNC_DISABLED=1 to turn the whole module off.
"""

import logging
import os
from concurrent.futures import ThreadPoolExecutor

from f5_ctlr_agent.gtm.utils import GTMUtils

log = logging.getLogger(__name__)

DISABLE_ENV = 'GTM_BULK_SYNC_DISABLED'


class GTMBulk(object):
    """Bulk snapshot and transactional creation of GTM objects."""

    # Below this many items the per-object path is just as fast.
    MIN_ITEMS = 20
    WIDEIP_BATCH_SIZE = 40  # wideIPs (each with its pools) per transaction
    VS_BATCH_SIZE = 250  # virtual servers per transaction
    QUEUE_WORKERS = 10  # parallel requests queued into one transaction

    def __init__(self, mgmt_root, partition, local_cluster_name=None,
                 cluster_digital_asset_id=None, description_builder=None):
        """Initialize the bulk helper.

        Args:
            mgmt_root: f5-sdk ManagementRoot (token auth; its session is shared by threads)
            partition (str): Partition to manage
            local_cluster_name (str, optional): Cluster identifier
            cluster_digital_asset_id (str, optional): Cluster digital asset ID
            description_builder (callable, optional): Returns the wideIP ownership
                description (GTMWideIP.build_description)
        """
        self._root = mgmt_root
        self._partition = partition
        self._local_cluster_name = local_cluster_name
        self._cluster_digital_asset_id = cluster_digital_asset_id
        self._description_builder = description_builder

    def enabled(self, item_count):
        """True when a bulk path is worthwhile for item_count objects."""
        if GTMUtils.as_bool(os.environ.get(DISABLE_ENV), default=False):
            return False
        return item_count >= self.MIN_ITEMS

    # ------------------------------------------------------------------
    # transport
    # ------------------------------------------------------------------
    def _url(self, path):
        return '{}tm/{}'.format(self._root._meta_data['uri'], path)

    def _items(self, path, params=None):
        resp = self._root.icrs.get(self._url(path), params=params)
        return resp.json().get('items', []) or []

    def _run_transaction(self, groups):
        """Queue every group, then commit once.

        Each group is a list of (path, body) POSTs queued in order by a single
        worker, so a pool is always queued before the wideIP that references it.
        Raises on any failure, after discarding the transaction.
        """
        icrs = self._root.icrs
        tx_id = str(icrs.post(self._url('transaction'), json={}).json()['transId'])
        headers = {'X-F5-REST-Coordination-Id': tx_id}

        def queue(group):
            for path, body in group:
                icrs.post(self._url(path), json=body, headers=headers)

        try:
            with ThreadPoolExecutor(max_workers=self.QUEUE_WORKERS) as executor:
                list(executor.map(queue, groups))
            icrs.patch(self._url('transaction/{}'.format(tx_id)),
                       json={'state': 'VALIDATING'})
        except Exception:
            try:
                icrs.delete(self._url('transaction/{}'.format(tx_id)))
            except Exception as e:
                log.debug("GTM: [BULK] Could not discard transaction %s: %s", tx_id, e)
            raise

    # ------------------------------------------------------------------
    # bulk read
    # ------------------------------------------------------------------
    def snapshot_bigip_state(self, gtmConfig):
        """Build the same snapshot as GTMSnapshot.snapshot_bigip_state with 3 GETs.

        Raises on any error; the caller falls back to the per-object snapshot.
        """
        snapshot = {
            'servers': set(),
            'server_vs': {},
            'server_monitors': {},
            'pools': set(),
            'pool_members': {},
            'pool_monitors': {},
            'pool_fallback_mode': {},
            'pool_fallback_ip': {},
            'wideips': set(),
            'wideip_attrs': {},
        }

        for srv in self._items('gtm/server'):
            name = srv['name']
            snapshot['servers'].add(name)
            snapshot['server_vs'][name] = set()
            snapshot['server_monitors'][name] = srv.get('monitor', '') or ''

        wideips = gtmConfig.get(self._partition, {}).get('wideIPs', []) or []
        wanted_wideips = set()
        wanted_pools = set()
        for wip in wideips:
            wanted_wideips.add(wip['name'])
            for pool in wip.get('pools', []) or []:
                wanted_pools.add(GTMUtils.format_pool_name(
                    pool['name'], self._local_cluster_name,
                    self._cluster_digital_asset_id))

        for item in self._items('gtm/pool/a', params={'expandSubcollections': 'true'}):
            name = item['name']
            if name not in wanted_pools or item.get('partition', self._partition) != self._partition:
                continue
            snapshot['pools'].add(name)
            snapshot['pool_monitors'][name] = item.get('monitor', '') or ''
            snapshot['pool_fallback_mode'][name] = item.get('fallbackMode', '') or ''
            snapshot['pool_fallback_ip'][name] = item.get('fallbackIp', '') or ''
            members = (item.get('membersReference') or {}).get('items', []) or []
            snapshot['pool_members'][name] = {m['name'] for m in members}

        for item in self._items('gtm/wideip/a'):
            name = item['name']
            if name not in wanted_wideips or item.get('partition', self._partition) != self._partition:
                continue
            snapshot['wideips'].add(name)
            snapshot['wideip_attrs'][name] = {
                'aliases': list(item.get('aliases') or []),
                'poolLbMode': item.get('poolLbMode', '') or '',
            }

        log.info("GTM: [BULK] Snapshot: %d servers, %d pools, %d wideips",
                 len(snapshot['servers']), len(snapshot['pools']), len(snapshot['wideips']))
        return snapshot

    # ------------------------------------------------------------------
    # transactional writes
    # ------------------------------------------------------------------
    def create_virtual_servers(self, server_name, vs_items):
        """Create virtual servers on an existing GSLB server in transaction batches.

        Args:
            server_name (str): GSLB server name
            vs_items (list): (member_ip, vs_name, destination) tuples to create

        Returns:
            list: items that were NOT created (failed batches), for the per-object path
        """
        path = 'gtm/server/~{}~{}/virtual-servers'.format(self._partition, server_name)
        remaining = []
        created = 0
        for i in range(0, len(vs_items), self.VS_BATCH_SIZE):
            batch = vs_items[i:i + self.VS_BATCH_SIZE]
            groups = [[(path, {'name': vs_name, 'destination': destination, 'enabled': True})]
                      for _, vs_name, destination in batch]
            try:
                self._run_transaction(groups)
                created += len(batch)
            except Exception as e:
                log.warning("GTM: [BULK] Virtual server batch of %d on %s failed, "
                            "using per-object path: %s", len(batch), server_name, e)
                remaining.extend(batch)
        log.info("GTM: [BULK] Created %d virtual servers on %s in batches, %d left for per-object path",
                 created, server_name, len(remaining))
        return remaining

    def _build_wideip_requests(self, config, snapshot):
        """Return [(path, body), ...] creating the wideIP and its pools, or None.

        None means the wideIP must go through the per-object path: it (or one of its
        pools) already exists, needs custom monitors, or has unparsable members.
        """
        try:
            name = config['name']
            pools = config['pools']
            if not pools or name in snapshot['wideips']:
                return None

            requests = []
            attach = []
            for pool in pools:
                if pool.get('monitors'):
                    return None
                pool_name = GTMUtils.format_pool_name(
                    pool['name'], self._local_cluster_name, self._cluster_digital_asset_id)
                if pool_name in snapshot['pools']:
                    return None

                members = []
                for spec in pool.get('members') or []:
                    dataserver, _, _, destination = GTMUtils.parse_member_spec(
                        spec, pool.get('DataServer'))
                    if dataserver is None:
                        return None
                    members.append({
                        'name': '{}:{}'.format(
                            GTMUtils.format_server_name(
                                dataserver, self._local_cluster_name,
                                self._cluster_digital_asset_id),
                            GTMUtils.format_vs_name(destination, self._local_cluster_name)),
                        'partition': self._partition,
                    })

                fallback_mode = pool.get('fallbackMode') or 'return-to-dns'
                body = {
                    'name': pool_name,
                    'partition': self._partition,
                    'fallbackMode': fallback_mode,
                    'loadBalancingMode': pool['LoadBalancingMode'],
                }
                fallback_ip = pool.get('fallbackIp') or pool.get('fallback-ip', '')
                if fallback_ip and fallback_mode == 'fallback-ip':
                    body['fallbackIp'] = fallback_ip
                if pool.get('poolMonitorRef'):
                    body['monitor'] = pool['poolMonitorRef']
                if members:
                    body['members'] = members
                requests.append(('gtm/pool/a', body))
                attach.append({'name': pool_name, 'partition': self._partition,
                               'ratio': 1, 'order': pool['order']})

            wideip_body = {
                'name': name,
                'partition': self._partition,
                'lastResortPool': 'none',
                'poolLbMode': config['LoadBalancingMode'],
                'pools': attach,
            }
            description = self._description_builder() if self._description_builder else None
            if description:
                wideip_body['description'] = description
            if config.get('aliases'):
                wideip_body['aliases'] = config['aliases']
            requests.append(('gtm/wideip/a', wideip_body))
            return requests
        except KeyError as e:
            log.debug("GTM: [BULK] wideIP config missing %s, using per-object path", e)
            return None

    def create_wideips(self, configs, snapshot):
        """Create wideIPs (with their pools) that are absent from the snapshot, in batches.

        Args:
            configs (list): wideIP configs that need processing
            snapshot (dict): BIG-IP state snapshot

        Returns:
            list: configs that were NOT created, for the per-object path
        """
        fresh = []
        leftover = []
        for config in configs:
            requests = self._build_wideip_requests(config, snapshot)
            if requests is None:
                leftover.append(config)
            else:
                fresh.append((config, requests))

        if not self.enabled(len(fresh)):
            return list(configs)

        created = 0
        for i in range(0, len(fresh), self.WIDEIP_BATCH_SIZE):
            batch = fresh[i:i + self.WIDEIP_BATCH_SIZE]
            try:
                self._run_transaction([requests for _, requests in batch])
                created += len(batch)
            except Exception as e:
                log.warning("GTM: [BULK] wideIP batch of %d failed, using per-object path: %s",
                            len(batch), e)
                leftover.extend(config for config, _ in batch)
            if created and (created % 200 == 0):
                log.info("GTM: [BULK] Created %d/%d wideIPs", created, len(fresh))

        log.info("GTM: [BULK] Created %d wideIPs in batches, %d left for per-object path",
                 created, len(leftover))
        return leftover
