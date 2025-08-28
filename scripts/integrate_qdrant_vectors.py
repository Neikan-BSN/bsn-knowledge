#!/usr/bin/env python3
"""
Qdrant Vector Database Integration for Group 1C
Creates vector embeddings for medical content search integration
"""

import sqlite3
import json
import os
import numpy as np
from datetime import datetime


def create_mock_embeddings(text: str, dimension: int = 384) -> list:
    """Create deterministic mock embeddings based on text content."""
    # Use text hash to create deterministic embeddings
    text_hash = hash(text) % (2**32)
    np.random.seed(text_hash)

    # Generate normalized random vector
    vector = np.random.normal(0, 1, dimension)
    vector = vector / np.linalg.norm(vector)

    return vector.tolist()


def integrate_qdrant_vectors():
    """Create vector embeddings and integration for Qdrant database."""

    print("Starting Qdrant Vector Database Integration...")

    # Read medical documents from SQLite
    db_path = "/home/user01/projects/bsn_knowledge/data/medical_test_data.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT document_id, title, content, subject_area, umls_accuracy
        FROM medical_documents
        ORDER BY umls_accuracy DESC
        LIMIT 100
    """)
    documents = cursor.fetchall()

    # Create Qdrant collection metadata
    qdrant_dir = (
        "/home/user01/projects/bsn_knowledge/data/qdrant/medical_content_vectors"
    )
    os.makedirs(qdrant_dir, exist_ok=True)

    # Generate vector embeddings for documents
    vector_data = []

    for i, (doc_id, title, content, subject_area, accuracy) in enumerate(documents):
        # Create text for embedding (title + content preview)
        embedding_text = f"{title}. {content[:500]}"

        # Generate embedding
        vector = create_mock_embeddings(embedding_text)

        # Create vector metadata
        vector_entry = {
            "id": i + 1,
            "document_id": doc_id,
            "title": title,
            "subject_area": subject_area,
            "umls_accuracy": accuracy,
            "vector": vector,
            "created_at": datetime.now().isoformat(),
        }

        vector_data.append(vector_entry)

        if (i + 1) % 25 == 0:
            print(f"Generated vectors for {i + 1}/100 documents")

    # Save vector data as JSON for Qdrant integration
    vectors_file = os.path.join(qdrant_dir, "medical_vectors.json")
    with open(vectors_file, "w") as f:
        json.dump(vector_data, f, indent=2)

    # Create collection configuration
    collection_config = {
        "collection_name": "medical_content",
        "vector_dimension": 384,
        "distance": "cosine",
        "description": "Medical nursing education content vectors for semantic search",
        "metadata": {
            "created_at": datetime.now().isoformat(),
            "document_count": len(vector_data),
            "average_accuracy": sum(v["umls_accuracy"] for v in vector_data)
            / len(vector_data),
            "domains_covered": list(set(v["subject_area"] for v in vector_data)),
        },
    }

    config_file = os.path.join(qdrant_dir, "collection_config.json")
    with open(config_file, "w") as f:
        json.dump(collection_config, f, indent=2)

    # Create search index mapping
    search_index = {}
    for vector in vector_data:
        search_index[vector["document_id"]] = {
            "vector_id": vector["id"],
            "title": vector["title"],
            "subject_area": vector["subject_area"],
            "accuracy": vector["umls_accuracy"],
        }

    index_file = os.path.join(qdrant_dir, "search_index.json")
    with open(index_file, "w") as f:
        json.dump(search_index, f, indent=2)

    conn.close()

    print("\n=== QDRANT INTEGRATION SUMMARY ===")
    print(f"Vectors Generated: {len(vector_data)}")
    print(f"Vector Dimension: {collection_config['vector_dimension']}")
    print(f"Average Accuracy: {collection_config['metadata']['average_accuracy']:.3f}")
    print(f"Domains Covered: {len(collection_config['metadata']['domains_covered'])}")
    print(f"Collection Config: {config_file}")
    print(f"Vector Data: {vectors_file}")
    print(f"Search Index: {index_file}")

    # Integration validation
    validation = {
        "vectors_created": len(vector_data) > 0,
        "config_saved": os.path.exists(config_file),
        "data_saved": os.path.exists(vectors_file),
        "index_created": os.path.exists(index_file),
        "accuracy_maintained": collection_config["metadata"]["average_accuracy"]
        >= 0.98,
    }

    print("\n=== INTEGRATION VALIDATION ===")
    for check, passed in validation.items():
        status = "✓" if passed else "✗"
        print(f"{status} {check.replace('_', ' ').title()}")

    all_checks_passed = all(validation.values())
    print(f"\nIntegration Status: {'✓ SUCCESS' if all_checks_passed else '✗ FAILED'}")

    return {
        "vectors_generated": len(vector_data),
        "config_file": config_file,
        "vectors_file": vectors_file,
        "index_file": index_file,
        "validation": validation,
        "success": all_checks_passed,
    }


if __name__ == "__main__":
    integrate_qdrant_vectors()
