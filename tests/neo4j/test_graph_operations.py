"""Neo4j-specific tests for graph database operations.

Implements Task Group 3 patterns for Neo4j testing with real database connections.
"""

import time

import pytest


@pytest.mark.neo4j
@pytest.mark.asyncio
class TestNeo4jConnection:
    """Test Neo4j database connectivity and basic operations."""

    async def test_database_connection(self, neo4j_driver):
        """Test that Neo4j database connection is working."""
        # Verify driver is connected
        neo4j_driver.verify_connectivity()

        # Test basic query
        with neo4j_driver.session() as session:
            result = session.run("RETURN 1 as test")
            record = result.single()
            assert record["test"] == 1

    async def test_database_version(self, neo4j_driver):
        """Test database version compatibility."""
        with neo4j_driver.session() as session:
            result = session.run("CALL dbms.components() YIELD versions")
            record = result.single()
            version = record["versions"][0]

            # Should be Neo4j 5.x for compatibility
            assert version.startswith("5."), f"Expected Neo4j 5.x, got {version}"

    async def test_database_permissions(self, neo4j_session):
        """Test that test user has required permissions."""
        # Test CREATE permission
        result = neo4j_session.run(
            "CREATE (n:TestNode {id: 'permission_test'}) RETURN n"
        )
        assert result.single() is not None

        # Test DELETE permission
        neo4j_session.run("MATCH (n:TestNode {id: 'permission_test'}) DELETE n")


@pytest.mark.neo4j
@pytest.mark.asyncio
class TestKnowledgeGraphSchema:
    """Test knowledge graph schema creation and constraints."""

    async def test_create_constraints(self, neo4j_session, knowledge_graph_schema):
        """Test creating constraints for knowledge graph."""
        # Create constraints
        for constraint in knowledge_graph_schema["constraints"]:
            result = neo4j_session.run(constraint)
            assert result is not None

        # Verify constraints exist
        result = neo4j_session.run("SHOW CONSTRAINTS")
        constraints = [record["name"] for record in result]
        assert len(constraints) >= 2

    async def test_create_indexes(self, neo4j_session, knowledge_graph_schema):
        """Test creating indexes for performance."""
        # Create indexes
        for index in knowledge_graph_schema["indexes"]:
            result = neo4j_session.run(index)
            assert result is not None

        # Verify indexes exist
        result = neo4j_session.run("SHOW INDEXES")
        indexes = [record["name"] for record in result]
        assert len(indexes) >= 2

    async def test_constraint_enforcement(self, neo4j_session, knowledge_graph_schema):
        """Test that constraints are properly enforced."""
        # Create constraint
        neo4j_session.run(knowledge_graph_schema["constraints"][0])

        # Create first term
        neo4j_session.run(
            "CREATE (n:MedicalTerm {id: 'unique_test', name: 'Test Term'})"
        )

        # Try to create duplicate - should fail
        with pytest.raises(Exception):
            neo4j_session.run(
                "CREATE (n:MedicalTerm {id: 'unique_test', name: 'Duplicate Term'})"
            )


@pytest.mark.neo4j
@pytest.mark.asyncio
class TestMedicalTerminologyOperations:
    """Test medical terminology CRUD operations."""

    async def test_create_medical_term(self, setup_knowledge_graph):
        """Test creating medical terms in Neo4j."""
        # Term should already exist from setup
        result = setup_knowledge_graph.run(
            "MATCH (n:MedicalTerm {id: 'term_1'}) RETURN n.name as name"
        )
        record = result.single()
        assert record["name"] == "Hypertension"

    async def test_update_medical_term(self, setup_knowledge_graph):
        """Test updating medical term properties."""
        # Update term
        setup_knowledge_graph.run(
            "MATCH (n:MedicalTerm {id: 'term_1'}) "
            "SET n.description = 'High blood pressure condition', n.updated_at = datetime()"
        )

        # Verify update
        result = setup_knowledge_graph.run(
            "MATCH (n:MedicalTerm {id: 'term_1'}) "
            "RETURN n.description as description, n.updated_at as updated"
        )
        record = result.single()
        assert record["description"] == "High blood pressure condition"
        assert record["updated"] is not None

    async def test_delete_medical_term(self, setup_knowledge_graph):
        """Test deleting medical terms."""
        # Create term to delete
        setup_knowledge_graph.run(
            "CREATE (n:MedicalTerm {id: 'delete_test', name: 'Delete Me'})"
        )

        # Verify creation
        result = setup_knowledge_graph.run(
            "MATCH (n:MedicalTerm {id: 'delete_test'}) RETURN count(n) as count"
        )
        assert result.single()["count"] == 1

        # Delete term
        setup_knowledge_graph.run(
            "MATCH (n:MedicalTerm {id: 'delete_test'}) DETACH DELETE n"
        )

        # Verify deletion
        result = setup_knowledge_graph.run(
            "MATCH (n:MedicalTerm {id: 'delete_test'}) RETURN count(n) as count"
        )
        assert result.single()["count"] == 0

    async def test_search_medical_terms(self, setup_knowledge_graph):
        """Test searching medical terms by various criteria."""
        # Search by name
        result = setup_knowledge_graph.run(
            "MATCH (n:MedicalTerm) WHERE n.name CONTAINS 'tension' RETURN n.name as name"
        )
        names = [record["name"] for record in result]
        assert "Hypertension" in names

        # Search by category
        result = setup_knowledge_graph.run(
            "MATCH (n:MedicalTerm {category: 'cardiovascular'}) RETURN count(n) as count"
        )
        assert result.single()["count"] >= 1


@pytest.mark.neo4j
@pytest.mark.asyncio
class TestRelationshipOperations:
    """Test relationship operations between medical terms."""

    async def test_create_relationships(self, setup_knowledge_graph):
        """Test creating relationships between terms."""
        # Relationship should exist from setup
        result = setup_knowledge_graph.run(
            "MATCH (a:MedicalTerm {id: 'term_1'})-[r:COMORBID_WITH]->(b:MedicalTerm {id: 'term_2'}) "
            "RETURN type(r) as rel_type"
        )
        record = result.single()
        assert record["rel_type"] == "COMORBID_WITH"

    async def test_update_relationship_properties(self, setup_knowledge_graph):
        """Test updating relationship properties."""
        # Add properties to relationship
        setup_knowledge_graph.run(
            "MATCH (a:MedicalTerm {id: 'term_1'})-[r:COMORBID_WITH]->(b:MedicalTerm {id: 'term_2'}) "
            "SET r.strength = 0.85, r.evidence_level = 'high'"
        )

        # Verify properties
        result = setup_knowledge_graph.run(
            "MATCH (a:MedicalTerm {id: 'term_1'})-[r:COMORBID_WITH]->(b:MedicalTerm {id: 'term_2'}) "
            "RETURN r.strength as strength, r.evidence_level as evidence"
        )
        record = result.single()
        assert record["strength"] == 0.85
        assert record["evidence"] == "high"

    async def test_delete_relationships(self, setup_knowledge_graph):
        """Test deleting relationships."""
        # Create test relationship
        setup_knowledge_graph.run(
            "MATCH (a:MedicalTerm {id: 'term_1'}), (b:MedicalTerm {id: 'term_3'}) "
            "CREATE (a)-[r:TEST_RELATIONSHIP]->(b)"
        )

        # Verify creation
        result = setup_knowledge_graph.run(
            "MATCH (a:MedicalTerm {id: 'term_1'})-[r:TEST_RELATIONSHIP]->(b:MedicalTerm {id: 'term_3'}) "
            "RETURN count(r) as count"
        )
        assert result.single()["count"] == 1

        # Delete relationship
        setup_knowledge_graph.run(
            "MATCH (a:MedicalTerm {id: 'term_1'})-[r:TEST_RELATIONSHIP]->(b:MedicalTerm {id: 'term_3'}) "
            "DELETE r"
        )

        # Verify deletion
        result = setup_knowledge_graph.run(
            "MATCH (a:MedicalTerm {id: 'term_1'})-[r:TEST_RELATIONSHIP]->(b:MedicalTerm {id: 'term_3'}) "
            "RETURN count(r) as count"
        )
        assert result.single()["count"] == 0


@pytest.mark.neo4j
@pytest.mark.asyncio
class TestGraphTraversalOperations:
    """Test complex graph traversal operations."""

    async def test_shortest_path_query(self, setup_knowledge_graph):
        """Test shortest path queries between terms."""
        # Create additional relationship for path testing
        setup_knowledge_graph.run(
            "MATCH (a:MedicalTerm {id: 'term_2'}), (b:MedicalTerm {id: 'term_3'}) "
            "CREATE (a)-[r:RELATED_TO]->(b)"
        )

        # Find shortest path
        result = setup_knowledge_graph.run(
            "MATCH path = shortestPath((a:MedicalTerm {id: 'term_1'})-[*]-(b:MedicalTerm {id: 'term_3'})) "
            "RETURN length(path) as path_length, [node in nodes(path) | node.name] as node_names"
        )
        record = result.single()
        assert record["path_length"] >= 1
        assert "Hypertension" in record["node_names"]
        assert "Pneumonia" in record["node_names"]

    async def test_variable_length_paths(self, setup_knowledge_graph):
        """Test variable length path queries."""
        result = setup_knowledge_graph.run(
            "MATCH (start:MedicalTerm {id: 'term_1'})-[*1..3]-(connected:MedicalTerm) "
            "RETURN DISTINCT connected.name as connected_terms"
        )
        connected_terms = [record["connected_terms"] for record in result]
        assert len(connected_terms) > 0
        assert "Diabetes" in connected_terms  # Should be connected via COMORBID_WITH

    async def test_pattern_matching(self, setup_knowledge_graph):
        """Test complex pattern matching queries."""
        # Find terms with multiple relationships
        result = setup_knowledge_graph.run(
            "MATCH (center:MedicalTerm)-[r1]->(other1:MedicalTerm) "
            "MATCH (center)-[r2]->(other2:MedicalTerm) "
            "WHERE other1 <> other2 "
            "RETURN center.name as center_term, count(*) as relationship_count"
        )

        # Should have at least one term with multiple relationships
        records = list(result)
        assert len(records) > 0


@pytest.mark.neo4j
@pytest.mark.performance
class TestNeo4jPerformance:
    """Performance tests for Neo4j operations."""

    async def test_query_performance(
        self, setup_knowledge_graph, performance_threshold
    ):
        """Test that queries meet performance requirements."""
        start_time = time.time()

        # Execute performance-critical query
        result = setup_knowledge_graph.run(
            "MATCH (n:MedicalTerm) RETURN n.name, n.category ORDER BY n.name LIMIT 100"
        )
        list(result)  # Consume all results

        end_time = time.time()
        query_time = end_time - start_time

        assert query_time < performance_threshold["query_response_time"]

    async def test_bulk_insert_performance(self, neo4j_session, performance_threshold):
        """Test bulk insert operations performance."""
        start_time = time.time()

        # Bulk insert test data
        bulk_data = [
            {"id": f"bulk_{i}", "name": f"Bulk Term {i}", "category": "test"}
            for i in range(100)
        ]

        neo4j_session.run(
            "UNWIND $data AS item "
            "CREATE (n:MedicalTerm {id: item.id, name: item.name, category: item.category})",
            data=bulk_data,
        )

        end_time = time.time()
        bulk_time = end_time - start_time

        assert bulk_time < performance_threshold["bulk_insert_time"]

        # Cleanup
        neo4j_session.run("MATCH (n:MedicalTerm {category: 'test'}) DELETE n")

    async def test_complex_traversal_performance(
        self, setup_knowledge_graph, performance_threshold
    ):
        """Test complex graph traversal performance."""
        start_time = time.time()

        # Execute complex traversal
        result = setup_knowledge_graph.run(
            "MATCH (start:MedicalTerm {id: 'term_1'})-[*1..4]-(connected:MedicalTerm) "
            "RETURN DISTINCT connected.name, connected.category "
            "ORDER BY connected.name"
        )
        list(result)

        end_time = time.time()
        traversal_time = end_time - start_time

        assert traversal_time < performance_threshold["graph_traversal_time"]


@pytest.mark.neo4j
@pytest.mark.integration
class TestDataConsistency:
    """Test data consistency and integrity in Neo4j."""

    async def test_referential_integrity(self, setup_knowledge_graph):
        """Test that relationships maintain referential integrity."""
        # Count total nodes and relationships
        result = setup_knowledge_graph.run("MATCH (n) RETURN count(n) as node_count")
        node_count = result.single()["node_count"]

        result = setup_knowledge_graph.run(
            "MATCH ()-[r]->() RETURN count(r) as rel_count"
        )
        rel_count = result.single()["rel_count"]

        # All relationships should have valid endpoints
        result = setup_knowledge_graph.run(
            "MATCH (a)-[r]->(b) "
            "WHERE a IS NULL OR b IS NULL "
            "RETURN count(r) as invalid_rels"
        )
        invalid_rels = result.single()["invalid_rels"]

        assert node_count > 0
        assert rel_count > 0
        assert invalid_rels == 0

    async def test_duplicate_prevention(self, setup_knowledge_graph):
        """Test that constraints prevent duplicate data."""
        # Try to create duplicate medical term
        with pytest.raises(Exception):
            setup_knowledge_graph.run(
                "CREATE (n:MedicalTerm {id: 'term_1', name: 'Duplicate Hypertension'})"
            )

    async def test_orphaned_node_detection(self, setup_knowledge_graph):
        """Test detection of orphaned nodes."""
        # Create orphaned node
        setup_knowledge_graph.run(
            "CREATE (n:MedicalTerm {id: 'orphan', name: 'Orphaned Term'})"
        )

        # Find orphaned nodes (nodes with no relationships)
        result = setup_knowledge_graph.run(
            "MATCH (n:MedicalTerm) "
            "WHERE NOT (n)-[]-() "
            "RETURN count(n) as orphaned_count, collect(n.id) as orphaned_ids"
        )
        record = result.single()

        assert "orphan" in record["orphaned_ids"]

        # Cleanup
        setup_knowledge_graph.run("MATCH (n:MedicalTerm {id: 'orphan'}) DELETE n")


@pytest.mark.neo4j
@pytest.mark.slow
class TestLargeDatasetOperations:
    """Test operations with larger datasets."""

    async def test_large_graph_traversal(self, neo4j_session):
        """Test traversal performance with larger dataset."""
        # Create larger test dataset
        large_data = [
            {
                "id": f"large_{i}",
                "name": f"Large Term {i}",
                "category": "performance_test",
            }
            for i in range(1000)
        ]

        # Insert data
        neo4j_session.run(
            "UNWIND $data AS item "
            "CREATE (n:MedicalTerm {id: item.id, name: item.name, category: item.category})",
            data=large_data,
        )

        # Create random relationships
        neo4j_session.run(
            "MATCH (a:MedicalTerm {category: 'performance_test'}) "
            "MATCH (b:MedicalTerm {category: 'performance_test'}) "
            "WHERE a <> b AND rand() < 0.01 "  # 1% chance of relationship
            "CREATE (a)-[:PERFORMANCE_TEST_RELATION]->(b)"
        )

        # Test large traversal
        start_time = time.time()
        result = neo4j_session.run(
            "MATCH (n:MedicalTerm {category: 'performance_test'}) "
            "RETURN count(n) as total_count"
        )
        assert result.single()["total_count"] == 1000

        end_time = time.time()
        query_time = end_time - start_time

        # Should complete within reasonable time
        assert query_time < 5.0  # 5 seconds max

        # Cleanup
        neo4j_session.run(
            "MATCH (n:MedicalTerm {category: 'performance_test'}) DETACH DELETE n"
        )


if __name__ == "__main__":
    # Run Neo4j-specific tests
    pytest.main([__file__, "-v", "-m", "neo4j", "--tb=short"])
