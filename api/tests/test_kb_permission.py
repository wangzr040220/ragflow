"""
Tests for Knowledge Base Permission Module (RAGFlow)

Tests for update_extension_fields, check_visibility,
notify_document_parse_complete
"""

import unittest
from unittest.mock import MagicMock, patch


class TestKBPermission(unittest.TestCase):
    """Test knowledge base permission for RAGFlow"""

    @patch("api.utils.kb_permission.KnowledgebaseService")
    def test_update_extension_fields_with_valid_fields(self, mock_kb_service):
        """Update allowed extension fields on a knowledge base"""
        from api.utils.kb_permission import update_extension_fields

        mock_kb_service.update_by_id.return_value = True

        result = update_extension_fields("kb-123", {
            "subject_category": "Computer Science",
            "course_code": "COMP101",
            "dept_code": "COMP",
            "visibility": "public",
            "owner_id": "user-1",
        })
        self.assertTrue(result)
        mock_kb_service.update_by_id.assert_called_once()

    @patch("api.utils.kb_permission.KnowledgebaseService")
    def test_update_extension_fields_filters_invalid(self, mock_kb_service):
        """Only allowed fields are updated, others are ignored"""
        from api.utils.kb_permission import update_extension_fields

        mock_kb_service.update_by_id.return_value = True

        result = update_extension_fields("kb-123", {
            "subject_category": "CS",
            "invalid_field": "should_be_ignored",
        })
        self.assertTrue(result)
        call_args = mock_kb_service.update_by_id.call_args
        update_data = call_args[0][1]
        self.assertNotIn("invalid_field", update_data)
        self.assertIn("subject_category", update_data)

    def test_update_extension_fields_empty_data(self):
        """Return True when no valid fields to update"""
        from api.utils.kb_permission import update_extension_fields

        result = update_extension_fields("kb-123", {"invalid": "data"})
        self.assertTrue(result)

    def test_update_extension_fields_no_data(self):
        """Return True when no data provided"""
        from api.utils.kb_permission import update_extension_fields

        result = update_extension_fields("kb-123", {})
        self.assertTrue(result)

    @patch("api.utils.kb_permission.KnowledgebaseService")
    def test_check_visibility_public(self, mock_kb_service):
        """Public knowledge bases are accessible by anyone"""
        from api.utils.kb_permission import check_visibility

        mock_kb = MagicMock()
        mock_kb.visibility = "public"
        mock_kb_service.query.return_value = [mock_kb]

        result = check_visibility("kb-1", "any-user", "ANY")
        self.assertTrue(result)

    @patch("api.utils.kb_permission.KnowledgebaseService")
    def test_check_visibility_department_same_dept(self, mock_kb_service):
        """Department KB accessible by same department members"""
        from api.utils.kb_permission import check_visibility

        mock_kb = MagicMock()
        mock_kb.visibility = "department"
        mock_kb.dept_code = "COMP"
        mock_kb.owner_id = "owner-1"
        mock_kb_service.query.return_value = [mock_kb]

        result = check_visibility("kb-1", "user-1", "COMP")
        self.assertTrue(result)

    @patch("api.utils.kb_permission.KnowledgebaseService")
    def test_check_visibility_department_different_dept(self, mock_kb_service):
        """Department KB not accessible by different department"""
        from api.utils.kb_permission import check_visibility

        mock_kb = MagicMock()
        mock_kb.visibility = "department"
        mock_kb.dept_code = "COMP"
        mock_kb.owner_id = "owner-1"
        mock_kb_service.query.return_value = [mock_kb]

        result = check_visibility("kb-1", "user-1", "EIE")
        self.assertFalse(result)

    @patch("api.utils.kb_permission.KnowledgebaseService")
    def test_check_visibility_department_owner_access(self, mock_kb_service):
        """Department KB accessible by owner even from different dept"""
        from api.utils.kb_permission import check_visibility

        mock_kb = MagicMock()
        mock_kb.visibility = "department"
        mock_kb.dept_code = "COMP"
        mock_kb.owner_id = "user-1"
        mock_kb_service.query.return_value = [mock_kb]

        result = check_visibility("kb-1", "user-1", "EIE")
        self.assertTrue(result)

    @patch("api.utils.kb_permission.KnowledgebaseService")
    def test_check_visibility_private_owner(self, mock_kb_service):
        """Private KB accessible by owner"""
        from api.utils.kb_permission import check_visibility

        mock_kb = MagicMock()
        mock_kb.visibility = "private"
        mock_kb.owner_id = "user-1"
        mock_kb_service.query.return_value = [mock_kb]

        result = check_visibility("kb-1", "user-1", "COMP")
        self.assertTrue(result)

    @patch("api.utils.kb_permission.KnowledgebaseService")
    def test_check_visibility_private_not_owner(self, mock_kb_service):
        """Private KB not accessible by non-owner"""
        from api.utils.kb_permission import check_visibility

        mock_kb = MagicMock()
        mock_kb.visibility = "private"
        mock_kb.owner_id = "owner-1"
        mock_kb_service.query.return_value = [mock_kb]

        result = check_visibility("kb-1", "other-user", "COMP")
        self.assertFalse(result)

    @patch("api.utils.kb_permission.KnowledgebaseService")
    def test_check_visibility_default_private(self, mock_kb_service):
        """Default visibility is private when not set"""
        from api.utils.kb_permission import check_visibility

        mock_kb = MagicMock()
        mock_kb.visibility = None
        mock_kb.owner_id = "owner-1"
        mock_kb_service.query.return_value = [mock_kb]

        result = check_visibility("kb-1", "other-user", "COMP")
        self.assertFalse(result)

    @patch("api.utils.kb_permission.KnowledgebaseService")
    def test_check_visibility_kb_not_found(self, mock_kb_service):
        """Return False when KB not found"""
        from api.utils.kb_permission import check_visibility

        mock_kb_service.query.return_value = []

        result = check_visibility("nonexistent", "user-1", "COMP")
        self.assertFalse(result)

    @patch("api.utils.kb_permission.requests.post")
    def test_notify_parse_complete_success(self, mock_post):
        """Successful parse completion notification"""
        from api.utils.kb_permission import notify_document_parse_complete

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        with patch("api.utils.kb_permission.BFF_CALLBACK_URL", "http://bff/callback"), \
             patch("api.utils.kb_permission.BFF_WEBHOOK_SECRET", "secret123"):
            result = notify_document_parse_complete(
                "kb-1", "doc-1", "test.pdf", "completed", chunk_count=10,
            )
            self.assertTrue(result)

    @patch("api.utils.kb_permission.requests.post")
    def test_notify_parse_complete_failure(self, mock_post):
        """Failed parse completion notification"""
        from api.utils.kb_permission import notify_document_parse_complete

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_post.return_value = mock_response

        with patch("api.utils.kb_permission.BFF_CALLBACK_URL", "http://bff/callback"), \
             patch("api.utils.kb_permission.BFF_WEBHOOK_SECRET", "secret"):
            result = notify_document_parse_complete(
                "kb-1", "doc-1", "test.pdf", "failed", error_message="Parse error",
            )
            self.assertFalse(result)

    def test_notify_parse_complete_no_callback_url(self):
        """Skip notification when callback URL not configured"""
        from api.utils.kb_permission import notify_document_parse_complete

        with patch("api.utils.kb_permission.BFF_CALLBACK_URL", ""):
            result = notify_document_parse_complete(
                "kb-1", "doc-1", "test.pdf", "completed",
            )
            self.assertTrue(result)

    @patch("api.utils.kb_permission.requests.post")
    def test_notify_parse_complete_network_error(self, mock_post):
        """Handle network error during notification"""
        from api.utils.kb_permission import notify_document_parse_complete

        mock_post.side_effect = Exception("Connection refused")

        with patch("api.utils.kb_permission.BFF_CALLBACK_URL", "http://bff/callback"), \
             patch("api.utils.kb_permission.BFF_WEBHOOK_SECRET", "secret"):
            result = notify_document_parse_complete(
                "kb-1", "doc-1", "test.pdf", "completed",
            )
            self.assertFalse(result)

    @patch("api.utils.kb_permission.requests.post")
    def test_notify_parse_complete_includes_webhook_secret(self, mock_post):
        """Webhook secret header is included when configured"""
        from api.utils.kb_permission import notify_document_parse_complete

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        with patch("api.utils.kb_permission.BFF_CALLBACK_URL", "http://bff/callback"), \
             patch("api.utils.kb_permission.BFF_WEBHOOK_SECRET", "my-secret"):
            notify_document_parse_complete("kb-1", "doc-1", "test.pdf", "completed")

        call_headers = mock_post.call_args[1]["headers"]
        self.assertEqual(call_headers["X-Webhook-Secret"], "my-secret")


if __name__ == "__main__":
    unittest.main()
