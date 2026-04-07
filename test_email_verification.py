import os
import tempfile
import unittest
from unittest.mock import patch

import database
import server


class EmailVerificationTests(unittest.TestCase):
    def setUp(self):
        temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = temp_db.name
        temp_db.close()

        database.init_database(self.db_path)
        self.original_conn = server.conn
        self.test_conn = database.create_connection(self.db_path)
        server.conn = self.test_conn
        self.client = server.app.test_client()

    def tearDown(self):
        self.test_conn.close()
        server.conn = self.original_conn
        os.remove(self.db_path)

    def test_build_verification_url_uses_request_host_when_config_is_loopback(self):
        with patch('server.config', side_effect=lambda key, value=None, mode='r': 'http://127.0.0.1:5000' if key == 'public_base_url' else None):
            with server.app.test_request_context('/api/register', base_url='https://chat.example.com'):
                verification_url = server.build_verification_url('abc123')
        self.assertEqual(verification_url, 'https://chat.example.com/verify_email?token=abc123')

    def test_build_verification_url_prefers_configured_public_domain(self):
        with patch('server.config', side_effect=lambda key, value=None, mode='r': 'https://public.example.com' if key == 'public_base_url' else None):
            with server.app.test_request_context('/api/register', base_url='https://internal.example.local'):
                verification_url = server.build_verification_url('abc123')
        self.assertEqual(verification_url, 'https://public.example.com/verify_email?token=abc123')

    def test_verify_email_marks_user_as_verified(self):
        user_id = database.create_user_with_profile(
            self.test_conn,
            'verify_user',
            'verify_user@example.com',
            'password123',
            display_name='Verify User'
        )
        database.set_email_verification_token(self.test_conn, user_id, 'verify-token')

        response = self.client.get('/verify_email?token=verify-token')
        user = database.get_user(self.test_conn, user_id=user_id)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(user[9], 1)
        self.assertIsNone(user[10])


if __name__ == '__main__':
    unittest.main()
