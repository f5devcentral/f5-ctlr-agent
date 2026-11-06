#!/usr/bin/env python

# Copyright (c) 2018-2026 F5 Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import pytest
from mock import Mock, MagicMock, patch

from f5_ctlr_agent.bigipconfigdriver import GTMManager


def create_mock_gtm_bigip():
    """Create a mock BIG-IP management root with GTM objects."""
    bigip = MagicMock()
    gtm = MagicMock()
    bigip.tm.gtm = gtm

    # Mock pools
    mock_pool = MagicMock()
    mock_pool.members_s.get_collection.return_value = []
    mock_pool.members_s.member.exists.return_value = False
    gtm.pools.a_s.a.load.return_value = mock_pool
    gtm.pools.a_s.a.exists.return_value = True

    # Mock wideIPs
    mock_wideip = MagicMock()
    mock_wideip.lastResortPool = ""
    mock_wideip.pools = []
    mock_wideip.raw = {'pools': {}}
    mock_wideip.poolLbMode = "round-robin"
    gtm.wideips.a_s.a.load.return_value = mock_wideip
    gtm.wideips.a_s.a.exists.return_value = True

    # Mock servers
    mock_server = MagicMock()
    mock_server.virtual_servers_s.virtual_server.exists.return_value = True
    gtm.servers.server.load.return_value = mock_server
    gtm.servers.server.exists.return_value = True

    # Mock monitors
    mock_hm = MagicMock()
    gtm.monitor.https.http.load.return_value = mock_hm
    gtm.monitor.https.http.exists.return_value = True
    gtm.monitor.https_s.https.load.return_value = mock_hm
    gtm.monitor.https_s.https.exists.return_value = True
    gtm.monitor.tcps.tcp.load.return_value = mock_hm
    gtm.monitor.tcps.tcp.exists.return_value = True

    return bigip


def test_gtm_manager_init():
    bigip = create_mock_gtm_bigip()
    mgr = GTMManager(bigip, "Common")
    assert mgr.get_partition() == "Common"
    assert mgr.get_gtm_config() == {}


def test_gtm_pool_deletion_last_pool_no_index_error():
    """Test deleting the last/only pool from a wideIP and ensuring subsequent create/update does not crash."""
    bigip = create_mock_gtm_bigip()
    mgr = GTMManager(bigip, "Common")

    initial_config = {
        "activeTenants": ["edns-repro"],
        "deletedTenants": [],
        "config": {
            "Common": {
                "wideIPs": [
                    {
                        "name": "app-a.lab.example.com",
                        "recordType": "A",
                        "LoadBalancingMode": "round-robin",
                        "loadBalancingMode": "round-robin",
                        "pools": [
                            {
                                "name": "app-a.lab.example.com_10_168_3_20_k8s_gtm",
                                "order": 0,
                                "ratio": 1,
                                "recordType": "A",
                                "fallbackMode": "return-to-dns",
                                "LoadBalancingMode": "round-robin",
                                "loadBalancingMode": "round-robin",
                                "members": ["/Common/LTM-LAB:/edns-repro/Shared/vs-app-a"],
                                "monitors": [
                                    {
                                        "name": "app-a.lab.example.com_10_168_3_20_k8s_gtm_monitor",
                                        "type": "http",
                                        "send": "GET / HTTP/1.1\\r\\nHost: app-a.lab.example.com\\r\\n",
                                        "recv": "",
                                        "interval": 30,
                                        "timeout": 91
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "name": "app-b.lab.example.com",
                        "recordType": "A",
                        "LoadBalancingMode": "round-robin",
                        "loadBalancingMode": "round-robin",
                        "pools": [
                            {
                                "name": "app-b.lab.example.com_10_168_3_20_k8s_gtm",
                                "order": 0,
                                "ratio": 1,
                                "recordType": "A",
                                "fallbackMode": "return-to-dns",
                                "LoadBalancingMode": "round-robin",
                                "loadBalancingMode": "round-robin",
                                "members": ["/Common/LTM-LAB:/edns-repro/Shared/vs-app-b"],
                                "monitors": [
                                    {
                                        "name": "app-b.lab.example.com_10_168_3_20_k8s_gtm_monitor",
                                        "type": "http",
                                        "send": "GET / HTTP/1.1\\r\\nHost: app-b.lab.example.com\\r\\n",
                                        "recv": "",
                                        "interval": 30,
                                        "timeout": 91
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        }
    }

    # Step 1: Set initial config in cache
    mgr.replace_gtm_config(initial_config)

    # Step 2: Remove the only pool from app-b (spec.pools is now [])
    updated_config = {
        "Common": {
            "wideIPs": [
                copy.deepcopy(initial_config["config"]["Common"]["wideIPs"][0]),
                {
                    "name": "app-b.lab.example.com",
                    "recordType": "A",
                    "LoadBalancingMode": "round-robin",
                    "loadBalancingMode": "round-robin",
                    "pools": []
                }
            ]
        }
    }

    # Execute delete_update_gtm - MUST NOT raise IndexError: list index out of range
    mgr.delete_update_gtm("Common", updated_config)

    # Verify that app-b pool was removed from cache
    cached_wips = mgr.get_gtm_config()["Common"]["wideIPs"]
    for wip in cached_wips:
        if wip["name"] == "app-b.lab.example.com":
            assert len(wip["pools"]) == 0

    # Step 3: Now add app-c while app-b has empty pools in cache
    app_c_config = {
        "Common": {
            "wideIPs": [
                copy.deepcopy(initial_config["config"]["Common"]["wideIPs"][0]),
                {
                    "name": "app-b.lab.example.com",
                    "recordType": "A",
                    "LoadBalancingMode": "round-robin",
                    "loadBalancingMode": "round-robin",
                    "pools": []
                },
                {
                    "name": "app-c.lab.example.com",
                    "recordType": "A",
                    "LoadBalancingMode": "round-robin",
                    "loadBalancingMode": "round-robin",
                    "pools": [
                        {
                            "name": "app-c.lab.example.com_10_168_3_20_k8s_gtm",
                            "order": 0,
                            "ratio": 1,
                            "recordType": "A",
                            "fallbackMode": "return-to-dns",
                            "LoadBalancingMode": "round-robin",
                            "loadBalancingMode": "round-robin",
                            "members": ["/Common/LTM-LAB:/edns-repro/Shared/vs-app-c"],
                            "monitors": []
                        }
                    ]
                }
            ]
        }
    }

    # Execute delete_update_gtm with new wideIP app-c - MUST NOT raise IndexError
    mgr.delete_update_gtm("Common", app_c_config)


def test_gtm_member_deletion_difference():
    """Test that removing a member from a pool correctly invokes remove_member_to_gtm_pool."""
    bigip = create_mock_gtm_bigip()
    mgr = GTMManager(bigip, "Common")

    initial_config = {
        "activeTenants": ["edns-repro"],
        "deletedTenants": [],
        "config": {
            "Common": {
                "wideIPs": [
                    {
                        "name": "app-a.lab.example.com",
                        "recordType": "A",
                        "LoadBalancingMode": "round-robin",
                        "loadBalancingMode": "round-robin",
                        "pools": [
                            {
                                "name": "app-a.lab.example.com_pool",
                                "order": 0,
                                "ratio": 1,
                                "recordType": "A",
                                "fallbackMode": "return-to-dns",
                                "LoadBalancingMode": "round-robin",
                                "loadBalancingMode": "round-robin",
                                "members": [
                                    "/Common/LTM-LAB:/edns-repro/Shared/vs-app-a1",
                                    "/Common/LTM-LAB:/edns-repro/Shared/vs-app-a2"
                                ],
                                "monitors": []
                            }
                        ]
                    }
                ]
            }
        }
    }

    mgr.replace_gtm_config(initial_config)

    # Updated config with only vs-app-a1 (vs-app-a2 removed)
    updated_config = {
        "Common": {
            "wideIPs": [
                {
                    "name": "app-a.lab.example.com",
                    "recordType": "A",
                    "LoadBalancingMode": "round-robin",
                    "loadBalancingMode": "round-robin",
                    "pools": [
                        {
                            "name": "app-a.lab.example.com_pool",
                            "order": 0,
                            "ratio": 1,
                            "recordType": "A",
                            "fallbackMode": "return-to-dns",
                            "LoadBalancingMode": "round-robin",
                            "loadBalancingMode": "round-robin",
                            "members": [
                                "/Common/LTM-LAB:/edns-repro/Shared/vs-app-a1"
                            ],
                            "monitors": []
                        }
                    ]
                }
            ]
        }
    }

    with patch.object(mgr, 'remove_member_to_gtm_pool') as mock_remove_member:
        mgr.delete_update_gtm("Common", updated_config)
        mock_remove_member.assert_called_with(
            bigip.tm.gtm,
            "Common",
            "app-a.lab.example.com_pool",
            "/Common/LTM-LAB:/edns-repro/Shared/vs-app-a2"
        )


def test_delete_gtm_wideip_and_hm():
    """Test delete_gtm_wideip and delete_gtm_hm cleanly update cache and call BIG-IP."""
    bigip = create_mock_gtm_bigip()
    mgr = GTMManager(bigip, "Common")

    initial_config = {
        "activeTenants": ["test"],
        "deletedTenants": [],
        "config": {
            "Common": {
                "wideIPs": [
                    {
                        "name": "wip-1",
                        "pools": [
                            {
                                "name": "pool-1",
                                "monitors": [
                                    {"name": "mon-1", "type": "http"}
                                ]
                            }
                        ]
                    }
                ]
            }
        }
    }
    mgr.replace_gtm_config(initial_config)

    # Delete HM
    mgr.delete_gtm_hm(bigip.tm.gtm, "Common", "mon-1")
    assert len(mgr.get_gtm_config()["Common"]["wideIPs"][0]["pools"][0]["monitors"]) == 0

    # Delete wideIP (without pools)
    mgr.get_gtm_config()["Common"]["wideIPs"][0]["pools"] = []
    mgr.delete_gtm_wideip(bigip.tm.gtm, "Common", "wip-1")
    assert len(mgr.get_gtm_config()["Common"]["wideIPs"]) == 0


def test_gtm_empty_pools_reconciliation():
    """Test reconciliation when an ExternalDNS wideIP has all pools removed (spec.pools: [])."""
    bigip = create_mock_gtm_bigip()
    mgr = GTMManager(bigip, "Common")

    initial_config = {
        "activeTenants": ["test"],
        "deletedTenants": [],
        "config": {
            "Common": {
                "wideIPs": [
                    {
                        "name": "foo.com",
                        "recordType": "A",
                        "LoadBalancingMode": "round-robin",
                        "loadBalancingMode": "round-robin",
                        "pools": [
                            {
                                "name": "foo_pool",
                                "order": 0,
                                "ratio": 1,
                                "recordType": "A",
                                "fallbackMode": "return-to-dns",
                                "LoadBalancingMode": "round-robin",
                                "loadBalancingMode": "round-robin",
                                "members": ["/Common/LTM:/test/Shared/vs-foo"],
                                "monitors": [{"name": "foo_mon", "type": "http"}]
                            }
                        ]
                    },
                    {
                        "name": "bar.com",
                        "recordType": "A",
                        "LoadBalancingMode": "round-robin",
                        "loadBalancingMode": "round-robin",
                        "pools": [
                            {
                                "name": "bar_pool",
                                "order": 0,
                                "ratio": 1,
                                "recordType": "A",
                                "fallbackMode": "return-to-dns",
                                "LoadBalancingMode": "round-robin",
                                "loadBalancingMode": "round-robin",
                                "members": ["/Common/LTM:/test/Shared/vs-bar"],
                                "monitors": [{"name": "bar_mon", "type": "http"}]
                            }
                        ]
                    }
                ]
            }
        }
    }
    mgr.replace_gtm_config(initial_config)

    # bar.com has its pools drained (pools: [])
    updated_config = {
        "Common": {
            "wideIPs": [
                {
                    "name": "foo.com",
                    "recordType": "A",
                    "LoadBalancingMode": "round-robin",
                    "loadBalancingMode": "round-robin",
                    "pools": [
                        {
                            "name": "foo_pool",
                            "order": 0,
                            "ratio": 1,
                            "recordType": "A",
                            "fallbackMode": "return-to-dns",
                            "LoadBalancingMode": "round-robin",
                            "loadBalancingMode": "round-robin",
                            "members": ["/Common/LTM:/test/Shared/vs-foo"],
                            "monitors": [{"name": "foo_mon", "type": "http"}]
                        }
                    ]
                },
                {
                    "name": "bar.com",
                    "recordType": "A",
                    "LoadBalancingMode": "round-robin",
                    "loadBalancingMode": "round-robin",
                    "pools": []
                }
            ]
        }
    }

    # Must execute without UnboundLocalError: 'all_monitors' or IndexError
    mgr.delete_update_gtm("Common", updated_config)

    # create_gtm must also handle empty pools safely
    mgr.create_gtm("Common", updated_config)

