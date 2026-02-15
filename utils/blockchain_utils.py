"""
Blockchain utility functions for storing records on Algorand.
Provides a standard interface for creating and storing different types of records.
"""

from algorand.store_hash import store_on_chain, wait_for_confirmation


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


def record_attendance_on_chain(session_id, user_id, status, marked_by, face_hash=None):
    """
    Record attendance on Algorand blockchain.

    Args:
        session_id: ID of attendance session
        user_id: ID of student
        status: 'present' or 'absent'
        marked_by: ID of user who marked (self or instructor)
        face_hash: (Optional) Hash of face image for verification

    Returns:
        Transaction ID from Algorand
    """
    fields = {
        'session_id': session_id,
        'user_id': user_id,
        'status': status,
        'marked_by': marked_by
    }
    
    if face_hash:
        fields['face_hash'] = face_hash
        
    note = generate_record_note('ATTENDANCE', **fields)
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


# Certificate System Logic
# Deployed App ID: 755556381
CERT_APP_ID = 755556381

from algorand.connect import get_client, get_private_key_and_address
from algosdk import transaction, logic
from algosdk.error import AlgodHTTPError
import base64

def store_certificate_hash(file_hash_bytes, metadata_str):
    """
    Store certificate hash and metadata in Algorand Box Storage.
    
    Args:
        file_hash_bytes: SHA-256 hash of the file (bytes)
        metadata_str: Metadata string (e.g. Student Name|Date)
    
    Returns:
        Transaction ID or None on failure
    """
    client = get_client()
    private_key, sender_address = get_private_key_and_address()
    
    box_name = file_hash_bytes
    box_value = metadata_str.encode('utf-8')
    
    # Calculate Box MBR
    # 2500 base + 400 * (len(n) + len(v))
    box_mbr = 2500 + 400 * (len(box_name) + len(box_value))
    
    print(f"Storing cert: Hash={file_hash_bytes.hex()}, MBR={box_mbr}")
    
    params = client.suggested_params()
    
    # 1. Payment transaction to cover MBR (sent to App Account)
    app_address = logic.get_application_address(CERT_APP_ID)
    ptxn = transaction.PaymentTxn(
        sender=sender_address,
        sp=params,
        receiver=app_address,
        amt=box_mbr
    )
    
    # 2. Application Call to add certificate
    app_args = [b"add", box_name, box_value]
    # We must reference the box in the foreign_apps or boxes array
    # define box reference: (app_index, box_name)
    # app_index 0 is current app
    box_ref = (0, box_name)
    
    atxn = transaction.ApplicationNoOpTxn(
        sender=sender_address,
        sp=params,
        index=CERT_APP_ID,
        app_args=app_args,
        boxes=[box_ref]
    )
    
    # Group transactions
    gid = transaction.calculate_group_id([ptxn, atxn])
    ptxn.group = gid
    atxn.group = gid
    
    # Sign
    signed_ptxn = ptxn.sign(private_key)
    signed_atxn = atxn.sign(private_key)
    
    try:
        tx_id = client.send_transactions([signed_ptxn, signed_atxn])
        print(f"Certificate stored. TXID: {tx_id}")
        return tx_id
    except Exception as e:
        print(f"Error storing certificate: {e}")
        raise e

def verify_certificate_on_chain(file_hash_bytes):
    """
    Verify certificate existence by checking Box Storage.
    
    Args:
        file_hash_bytes: SHA-256 hash (bytes)
        
    Returns:
        dict: {'verified': bool, 'metadata': str}
    """
    client = get_client()
    
    # Ensure bytes
    if isinstance(file_hash_bytes, str):
        # Assume hex string if it looks like one (length 64)
        if len(file_hash_bytes) == 64:
             try:
                 file_hash_bytes = bytes.fromhex(file_hash_bytes)
             except ValueError:
                 pass # Not hex?
    
    try:
        box_response = client.application_box_by_name(CERT_APP_ID, file_hash_bytes)
        # box_response['value'] is base64 encoded
        value_b64 = box_response['value']
        value_bytes = base64.b64decode(value_b64)
        metadata = value_bytes.decode('utf-8')
        
        return {
            'verified': True,
            'metadata': metadata
        }
    except AlgodHTTPError:
        # Box not found (404)
        return {
            'verified': False,
            'metadata': None
        }
    except Exception as e:
        print(f"Verification Check Error: {e}")
        return {
            'verified': False,
            'error': str(e)
        }

def delete_certificate_on_chain(file_hash_bytes):
    """
    Delete certificate from Algorand Box Storage.
    
    Args:
        file_hash_bytes: SHA-256 hash of the file (bytes)
        
    Returns:
        Transaction ID or None on failure
    """
    client = get_client()
    private_key, sender_address = get_private_key_and_address()
    
    box_name = file_hash_bytes
    
    print(f"Deleting cert: Hash={file_hash_bytes.hex()}")
    
    params = client.suggested_params()
    
    # Application Call to delete certificate
    app_args = [b"delete", box_name]
    box_ref = (0, box_name)
    
    atxn = transaction.ApplicationNoOpTxn(
        sender=sender_address,
        sp=params,
        index=CERT_APP_ID,
        app_args=app_args,
        boxes=[box_ref]
    )
    
    signed_atxn = atxn.sign(private_key)
    
    try:
        tx_id = client.send_transaction(signed_atxn)
        wait_for_confirmation(client, tx_id)
        print(f"Certificate deleted. TXID: {tx_id}")
        return tx_id
    except Exception as e:
        print(f"Error deleting certificate: {e}")
        return None
