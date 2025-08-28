#!/usr/bin/env python3
"""
Verification script for Group 1C test database
"""

import sqlite3


def verify_database():
    """Verify the medical test database content."""

    db_path = "/home/user01/projects/bsn_knowledge/data/medical_test_data.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Document count
    cursor.execute("SELECT COUNT(*) FROM medical_documents")
    doc_count = cursor.fetchone()[0]

    # Concept count
    cursor.execute("SELECT COUNT(*) FROM medical_concepts")
    concept_count = cursor.fetchone()[0]

    # Average accuracy
    cursor.execute("SELECT AVG(umls_accuracy) FROM medical_documents")
    avg_accuracy = cursor.fetchone()[0]

    # Subject area distribution
    cursor.execute(
        "SELECT subject_area, COUNT(*) FROM medical_documents GROUP BY subject_area"
    )
    domain_distribution = cursor.fetchall()

    # Difficulty distribution
    cursor.execute(
        "SELECT difficulty, COUNT(*) FROM medical_documents GROUP BY difficulty"
    )
    difficulty_distribution = cursor.fetchall()

    # Sample documents
    cursor.execute(
        "SELECT title, subject_area, umls_accuracy FROM medical_documents LIMIT 5"
    )
    sample_docs = cursor.fetchall()

    conn.close()

    print("=== GROUP 1C DATABASE VERIFICATION ===")
    print(f"Documents: {doc_count}")
    print(f"Medical Concepts: {concept_count}")
    print(f"Average UMLS Accuracy: {avg_accuracy:.3f}")
    print(f"Accuracy Threshold Met: {'✓' if avg_accuracy >= 0.98 else '✗'}")

    print("\nDomain Distribution:")
    for domain, count in domain_distribution:
        print(f"  {domain}: {count} documents")

    print("\nDifficulty Distribution:")
    for difficulty, count in difficulty_distribution:
        print(f"  Level {difficulty}: {count} documents")

    print("\nSample Documents:")
    for title, domain, accuracy in sample_docs:
        print(f"  • {title[:50]}... ({domain}, {accuracy:.3f})")

    # Validation summary
    validation = {
        "target_documents_met": doc_count >= 1000,
        "accuracy_threshold_met": avg_accuracy >= 0.98,
        "content_diversity": len(domain_distribution) >= 5,
        "difficulty_range": len(difficulty_distribution) >= 3,
    }

    print("\n=== SUCCESS CRITERIA VALIDATION ===")
    for criterion, met in validation.items():
        status = "✓" if met else "✗"
        print(f"{status} {criterion.replace('_', ' ').title()}")

    all_criteria_met = all(validation.values())
    print(
        f"\nOverall Status: {'✓ SUCCESS' if all_criteria_met else '✗ NEEDS ATTENTION'}"
    )

    return {
        "documents": doc_count,
        "concepts": concept_count,
        "accuracy": avg_accuracy,
        "validation": validation,
        "all_criteria_met": all_criteria_met,
    }


if __name__ == "__main__":
    verify_database()
