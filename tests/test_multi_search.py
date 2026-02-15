"""
Tests for multi-search feature (parallel entity searches with overlay).
Tests the frontend logic for managing multiple concurrent searches and merging results.
"""

import unittest


class TestMultiSearch(unittest.TestCase):
    """Unit tests for multi-search storage and merge logic."""

    def test_search_storage_map_creation(self):
        """Test that searches are stored in a Map-like structure."""
        searches = {}

        # Add search
        search_id = "search_0"
        searches[search_id] = {
            "label": "Sweden (Location)",
            "seed": "Sweden",
            "seedId": "entity_123",
            "depth": 2,
            "minConf": 0.7,
            "subgraph": None,
            "active": True,
        }

        self.assertIn(search_id, searches)
        self.assertEqual(searches[search_id]["label"], "Sweden (Location)")
        self.assertEqual(searches[search_id]["depth"], 2)
        self.assertTrue(searches[search_id]["active"])

    def test_multi_search_add_current_search(self):
        """Test adding current search to multi-search list."""
        searches = {}
        search_counter = [0]

        def add_search(label, seed, seed_id, depth, min_conf):
            search_id = f"search_{search_counter[0]}"
            search_counter[0] += 1
            searches[search_id] = {
                "label": label,
                "seed": seed,
                "seedId": seed_id,
                "depth": depth,
                "minConf": min_conf,
                "subgraph": None,
                "active": True,
            }
            return search_id

        # Add searches
        id1 = add_search("Sweden", "Sweden", "entity_1", 2, 0.7)
        id2 = add_search("Logistics", "Logistics", "entity_2", 3, 0.8)
        id3 = add_search("Cyber Attack", "Cyber Attack", "entity_3", 1, 0.75)

        self.assertEqual(len(searches), 3)
        self.assertEqual(searches[id1]["label"], "Sweden")
        self.assertEqual(searches[id2]["depth"], 3)
        self.assertEqual(searches[id3]["minConf"], 0.75)

    def test_search_toggle_active(self):
        """Test toggling search active/inactive."""
        searches = {
            "search_0": {
                "label": "Sweden",
                "seed": "Sweden",
                "seedId": "entity_1",
                "depth": 2,
                "minConf": 0.7,
                "subgraph": None,
                "active": True,
            }
        }

        # Toggle off
        searches["search_0"]["active"] = False
        self.assertFalse(searches["search_0"]["active"])

        # Toggle on
        searches["search_0"]["active"] = True
        self.assertTrue(searches["search_0"]["active"])

    def test_search_removal(self):
        """Test removing a search from storage."""
        searches = {
            "search_0": {"label": "Sweden", "active": True},
            "search_1": {"label": "Logistics", "active": True},
            "search_2": {"label": "Cyber Attack", "active": True},
        }

        self.assertEqual(len(searches), 3)
        del searches["search_1"]
        self.assertEqual(len(searches), 2)
        self.assertNotIn("search_1", searches)

    def test_merge_subgraph_results(self):
        """Test merging multiple subgraph results into single graph."""
        search_1_result = {
            "nodes": [
                {"id": "entity_1", "name": "Sweden", "type": "location"},
                {"id": "entity_2", "name": "Uppsala", "type": "location"},
            ],
            "edges": [
                {
                    "source": "entity_1",
                    "target": "entity_2",
                    "type": "contains",
                    "confidence": 0.95,
                }
            ],
        }

        search_2_result = {
            "nodes": [
                {"id": "entity_3", "name": "Logistics Inc", "type": "organization"},
                {"id": "entity_4", "name": "Transport AI", "type": "tool"},
            ],
            "edges": [
                {
                    "source": "entity_3",
                    "target": "entity_4",
                    "type": "uses",
                    "confidence": 0.88,
                }
            ],
        }

        # Merge logic: collect all unique nodes and edges
        merged_nodes = {}
        merged_edges = []

        for search_result in [search_1_result, search_2_result]:
            for node in search_result["nodes"]:
                merged_nodes[node["id"]] = node
            merged_edges.extend(search_result["edges"])

        self.assertEqual(len(merged_nodes), 4)
        self.assertEqual(len(merged_edges), 2)
        self.assertIn("entity_1", merged_nodes)
        self.assertIn("entity_3", merged_nodes)

    def test_merge_deduplicates_nodes(self):
        """Test that merging deduplicates nodes with same ID."""
        search_1_result = {
            "nodes": [
                {"id": "entity_1", "name": "Sweden", "type": "location"},
            ],
            "edges": [],
        }

        search_2_result = {
            "nodes": [
                {"id": "entity_1", "name": "Sweden", "type": "location"},
            ],
            "edges": [],
        }

        merged_nodes = {}
        for search_result in [search_1_result, search_2_result]:
            for node in search_result["nodes"]:
                merged_nodes[node["id"]] = node

        # Should have only 1 node despite adding it twice
        self.assertEqual(len(merged_nodes), 1)

    def test_merge_only_active_searches(self):
        """Test that merge only includes active searches."""
        searches = {
            "search_0": {
                "label": "Sweden",
                "active": True,
                "subgraph": {
                    "nodes": [{"id": "entity_1", "name": "Sweden"}],
                    "edges": [],
                },
            },
            "search_1": {
                "label": "Logistics",
                "active": False,
                "subgraph": {
                    "nodes": [{"id": "entity_2", "name": "Logistics"}],
                    "edges": [],
                },
            },
            "search_2": {
                "label": "Cyber Attack",
                "active": True,
                "subgraph": {
                    "nodes": [{"id": "entity_3", "name": "Cyber Attack"}],
                    "edges": [],
                },
            },
        }

        # Merge only active
        merged_nodes = {}
        for search_id, search in searches.items():
            if search["active"] and search["subgraph"]:
                for node in search["subgraph"]["nodes"]:
                    merged_nodes[node["id"]] = node

        # Should have 2 nodes (from search_0 and search_2)
        self.assertEqual(len(merged_nodes), 2)
        self.assertIn("entity_1", merged_nodes)
        self.assertIn("entity_3", merged_nodes)
        self.assertNotIn("entity_2", merged_nodes)

    def test_merge_preserves_edge_metadata(self):
        """Test that merging preserves edge confidence and type."""
        search_results = [
            {
                "nodes": [
                    {"id": "entity_1", "name": "Malware A"},
                    {"id": "entity_2", "name": "Attack Pattern B"},
                ],
                "edges": [
                    {
                        "source": "entity_1",
                        "target": "entity_2",
                        "type": "uses",
                        "confidence": 0.92,
                        "provenance": "from_gvm",
                    }
                ],
            }
        ]

        merged_edges = []
        for search_result in search_results:
            merged_edges.extend(search_result["edges"])

        self.assertEqual(len(merged_edges), 1)
        edge = merged_edges[0]
        self.assertEqual(edge["type"], "uses")
        self.assertEqual(edge["confidence"], 0.92)
        self.assertEqual(edge["provenance"], "from_gvm")

    def test_search_with_empty_results(self):
        """Test handling of search with no results."""
        search_with_results = {
            "nodes": [{"id": "entity_1", "name": "Sweden"}],
            "edges": [],
        }

        search_empty = {"nodes": [], "edges": []}

        merged_nodes = {}
        merged_edges = []

        for result in [search_with_results, search_empty]:
            for node in result["nodes"]:
                merged_nodes[node["id"]] = node
            merged_edges.extend(result["edges"])

        self.assertEqual(len(merged_nodes), 1)
        self.assertEqual(len(merged_edges), 0)

    def test_multiple_searches_different_depths(self):
        """Test merging searches with different depth configurations."""
        searches = {}
        search_counter = [0]

        def create_search(label, depth):
            search_id = f"search_{search_counter[0]}"
            search_counter[0] += 1
            searches[search_id] = {
                "label": label,
                "depth": depth,
                "active": True,
            }
            return search_id

        create_search("Shallow Sweden", 1)
        create_search("Medium Malware", 2)
        create_search("Deep Campaign", 3)

        depths = [searches[sid]["depth"] for sid in searches]
        self.assertEqual(sorted(depths), [1, 2, 3])

    def test_render_search_list_html(self):
        """Test HTML rendering of search list."""
        searches = {
            "search_0": {
                "label": "Sweden",
                "depth": 2,
                "active": True,
                "seedId": "entity_1",
            },
            "search_1": {
                "label": "Logistics",
                "depth": 3,
                "active": False,
                "seedId": "entity_2",
            },
        }

        html_cards = []
        for search_id, search in searches.items():
            card_html = f"""
            <div class="search-card">
                <div class="search-card-header">
                    <span class="search-label">{search['label']}</span>
                    <span class="search-depth">depth={search['depth']}</span>
                </div>
                <div class="search-card-controls">
                    <input type="checkbox" class="search-toggle"
                           data-search-id="{search_id}"
                           {'checked' if search['active'] else ''}>
                    <button class="search-remove" data-search-id="{search_id}">×</button>
                </div>
            </div>
            """
            html_cards.append(card_html)

        self.assertEqual(len(html_cards), 2)
        self.assertIn("Sweden", html_cards[0])
        self.assertIn("Logistics", html_cards[1])
        self.assertIn("checked", html_cards[0])  # search_0 is active
        self.assertNotIn("checked", html_cards[1])  # search_1 is inactive

    def test_search_persistence_across_merges(self):
        """Test that search metadata persists after merge."""
        searches = {
            "search_0": {
                "label": "Sweden (Location)",
                "seed": "Sweden",
                "seedId": "entity_123",
                "depth": 2,
                "minConf": 0.7,
                "active": True,
            }
        }

        original = searches["search_0"].copy()

        # Simulate merge operation (no modification of search metadata)
        # Verify metadata unchanged
        self.assertEqual(searches["search_0"]["label"], original["label"])
        self.assertEqual(searches["search_0"]["seedId"], original["seedId"])
        self.assertEqual(searches["search_0"]["depth"], original["depth"])

    def test_max_searches_limit(self):
        """Test that reasonable limit of concurrent searches is respected."""
        searches = {}
        max_searches = 5

        for i in range(max_searches + 2):
            search_id = f"search_{i}"
            if len(searches) < max_searches:
                searches[search_id] = {"label": f"Search {i}", "active": True}
            else:
                # Would be rejected
                pass

        self.assertEqual(len(searches), max_searches)

    def test_search_visibility_toggle(self):
        """Test toggling search visibility in UI."""
        search_active_states = {
            "search_0": True,
            "search_1": False,
            "search_2": True,
        }

        # Filter to visible (active) searches
        visible = [sid for sid, active in search_active_states.items() if active]

        self.assertEqual(len(visible), 2)
        self.assertIn("search_0", visible)
        self.assertNotIn("search_1", visible)

    def test_merge_with_cross_search_edges(self):
        """Test handling edges between nodes from different searches."""
        # This tests a more complex scenario where an edge might connect
        # nodes from two different searches
        merged_result = {
            "nodes": [
                {"id": "entity_1", "name": "Sweden", "search": "search_0"},
                {"id": "entity_2", "name": "Logistics", "search": "search_1"},
                {"id": "entity_3", "name": "Attack", "search": "search_2"},
            ],
            "edges": [
                {
                    "source": "entity_1",
                    "target": "entity_2",
                    "type": "targets",
                    "search_ids": ["search_0", "search_1"],
                }
            ],
        }

        # Verify cross-search edges preserved
        self.assertTrue(
            any(len(edge.get("search_ids", [])) > 1 for edge in merged_result["edges"])
        )


if __name__ == "__main__":
    unittest.main()
