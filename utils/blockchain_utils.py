"""
Blockchain utility functions for storing records on Algorand.
Provides a standard interface for creating and storing different types of records.
"""

from algorand.store_hash import store_on_chain


def generate_record_note(record_type, **fields):
    """
    Generate a standardized note format for blockchain storage.
    Format: RECORD_TYPE|field1:value1|field2:value2|...

    Args:
        record_type: Type of record (ATTENDANCE, FEEDBACK, MILESTONE, TASK)
        **fields: Key-value pairs to include in the note

    Returns:
        Formatted note string
    """
    note_parts = [record_type]
    for key, value in fields.items():
        note_parts.append(f"{key}:{value}")
    return "|".join(note_parts)


def record_attendance_on_chain(session_id, user_id, status, marked_by):
    """
    Record attendance on Algorand blockchain.

    Args:
        session_id: ID of attendance session
        user_id: ID of student
        status: 'present' or 'absent'
        marked_by: ID of user who marked (self or instructor)

    Returns:
        Transaction ID from Algorand
    """
    note = generate_record_note(
        'ATTENDANCE',
        session_id=session_id,
        user_id=user_id,
        status=status,
        marked_by=marked_by
    )
    return store_on_chain(note)


def record_feedback_on_chain(form_id, user_id, question_id, response_hash):
    """
    Record verified feedback on Algorand blockchain.
    Anonymous feedback is NOT stored on chain (privacy protection).

    Args:
        form_id: ID of feedback form
        user_id: ID of respondent
        question_id: ID of question
        response_hash: SHA-256 hash of response

    Returns:
        Transaction ID from Algorand
    """
    note = generate_record_note(
        'FEEDBACK',
        form_id=form_id,
        user_id=user_id,
        question_id=question_id,
        hash=response_hash
    )
    return store_on_chain(note)


def record_group_task_on_chain(group_id, task_id, user_id):
    """
    Record task completion on Algorand blockchain.

    Args:
        group_id: ID of group
        task_id: ID of task
        user_id: ID of user who completed it

    Returns:
        Transaction ID from Algorand
    """
    note = generate_record_note(
        'TASK',
        group_id=group_id,
        task_id=task_id,
        user_id=user_id,
        status='completed'
    )
    return store_on_chain(note)


def record_group_milestone_on_chain(group_id, milestone_id, proof_hash, completed_timestamp):
    """
    Record milestone completion on Algorand blockchain.

    Args:
        group_id: ID of group
        milestone_id: ID of milestone
        proof_hash: SHA-256 hash of proof/evidence
        completed_timestamp: ISO format timestamp of completion

    Returns:
        Transaction ID from Algorand
    """
    note = generate_record_note(
        'MILESTONE',
        group_id=group_id,
        milestone_id=milestone_id,
        proof_hash=proof_hash,
        completed_at=completed_timestamp
    )
    return store_on_chain(note)
