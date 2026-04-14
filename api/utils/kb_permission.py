"""
Knowledge Base Permission Enhancement

Extends RAGFlow's dataset API to support platform-specific fields:
- subject_category: subject classification
- course_code: associated course code
- dept_code: department code
- visibility: private|department|public
- owner_id: owner user ID

Also provides document parsing completion callback to BFF.
"""

import logging
import os

import requests

from api.db.services.knowledgebase_service import KnowledgebaseService

logger = logging.getLogger(__name__)

# BFF callback URL for document parsing completion
BFF_CALLBACK_URL = os.environ.get("BFF_CALLBACK_URL", "")
BFF_WEBHOOK_SECRET = os.environ.get("BFF_WEBHOOK_SECRET", "")


def update_extension_fields(kb_id: str, fields: dict) -> bool:
    """
    Update extension fields on a knowledge base.

    :param kb_id: Knowledge base ID
    :param fields: Dict with extension fields
    :return: True if successful
    """
    allowed_fields = {
        "subject_category", "course_code", "dept_code",
        "visibility", "owner_id",
    }
    update_data = {k: v for k, v in fields.items() if k in allowed_fields}

    if not update_data:
        return True

    return KnowledgebaseService.update_by_id(kb_id, update_data)


def check_visibility(kb_id: str, user_id: str, user_dept_code: str = "") -> bool:
    """
    Check if a user can access a knowledge base based on visibility rules.

    :param kb_id: Knowledge base ID
    :param user_id: User ID
    :param user_dept_code: User's department code
    :return: True if access is allowed
    """
    kbs = KnowledgebaseService.query(id=kb_id)
    if not kbs:
        return False

    kb = kbs[0]
    visibility = getattr(kb, "visibility", "private") or "private"

    # Public: anyone can access
    if visibility == "public":
        return True

    # Department: same department members can access
    if visibility == "department":
        kb_dept = getattr(kb, "dept_code", "") or ""
        if kb_dept and user_dept_code and kb_dept == user_dept_code:
            return True
        # Owner always has access
        owner_id = getattr(kb, "owner_id", "") or ""
        if owner_id == user_id:
            return True
        return False

    # Private: only owner
    owner_id = getattr(kb, "owner_id", "") or ""
    return owner_id == user_id


def notify_document_parse_complete(kb_id: str, doc_id: str, doc_name: str,
                                   status: str, chunk_count: int = 0,
                                   error_message: str = "") -> bool:
    """
    Notify BFF when a document parsing is complete.

    :param kb_id: Knowledge base ID
    :param doc_id: Document ID
    :param doc_name: Document name
    :param status: Parsing status (completed/failed)
    :param chunk_count: Number of chunks created
    :param error_message: Error message if failed
    :return: True if notification was sent successfully
    """
    if not BFF_CALLBACK_URL:
        logger.debug("BFF_CALLBACK_URL not configured, skipping notification")
        return True

    payload = {
        "event": "ragflow_document_parse_complete",
        "kb_id": kb_id,
        "doc_id": doc_id,
        "doc_name": doc_name,
        "status": status,
        "chunk_count": chunk_count,
        "error_message": error_message,
    }

    headers = {
        "Content-Type": "application/json",
    }

    if BFF_WEBHOOK_SECRET:
        headers["X-Webhook-Secret"] = BFF_WEBHOOK_SECRET

    try:
        resp = requests.post(
            BFF_CALLBACK_URL,
            json=payload,
            headers=headers,
            timeout=10,
        )
        if resp.status_code >= 200 and resp.status_code < 300:
            logger.info("Document parse callback sent successfully for %s", doc_id)
            return True
        else:
            logger.warning(
                "Document parse callback failed for %s: status=%d, body=%s",
                doc_id, resp.status_code, resp.text[:200],
            )
            return False
    except Exception as e:
        logger.error("Document parse callback error for %s: %s", doc_id, e)
        return False
