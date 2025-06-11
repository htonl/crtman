#!/usr/bin/env python3
import unittest
import subprocess
import shutil
from pathlib import Path

'''
This python test is much cleaner than the old Makefile test driver.
Documenting it here for legacy purposes.

	# First make the db dir for testing
	mkdir -p db
	# Run the unittests program
	./unittests db com.example.myCA 31536000
	# Verify the CA cert. Verification should succeed, expected output:
	# db/ca.cert.pem: OK
	openssl verify -CAfile db/ca.cert.pem db/ca.cert.pem
	# Create the cert chain for verifying an issued cert. Verification should succeed expected output:
	# db/issued_chain.pem: OK
	cat db/ca.cert.pem db/issued.cert.pem > db/issued_chain.pem
	openssl verify -CAfile db/ca.cert.pem db/issued_chain.pem
	# Try to verify again after revoking the cert. This should fail with expected output:
	# error 23 at 0 depth lookup: certificate revoked
	# error db/issued_chain.pem: verification failed
	openssl verify -CAfile db/ca.cert.pem -CRLfile db/crl.pem -crl_check db/issued_chain.pem
'''

class TestCADaemon(unittest.TestCase):
    DB_DIR = Path('db')
    CA_LABEL = 'com.example.myCA'
    VALIDITY = '31536000'
    TEST_BINARY = './unittests'

    def run_cmd(self, cmd, check=True):
        """Run a shell command, return CompletedProcess with stdout+stderr text."""
        result = subprocess.run(cmd, capture_output=True, text=True)
        if check:
            self.assertEqual(result.returncode, 0,
                             f"Command {' '.join(cmd)} failed:\n{result.stdout}{result.stderr}")
        return result

    def setUp(self):
        # Clean and recreate db directory
        if self.DB_DIR.exists():
            shutil.rmtree(self.DB_DIR)
        self.DB_DIR.mkdir()

    def test_full_ca_flow(self):
        # 1) Run the unittests C program to initialize CA, issue & revoke
        cp = self.run_cmd([self.TEST_BINARY,
                           str(self.DB_DIR),
                           self.CA_LABEL,
                           self.VALIDITY])
        # It should exit 0
        self.assertEqual(cp.returncode, 0)

        # 2) Verify CA cert against itself
        result = self.run_cmd([
            'openssl', 'verify',
            '-CAfile', str(self.DB_DIR / 'ca.cert.pem'),
            str(self.DB_DIR / 'ca.cert.pem')
        ])
        self.assertIn(f"{self.DB_DIR}/ca.cert.pem: OK", result.stdout.strip())

        # 3) Build a chain file and verify issued cert
        chain = self.DB_DIR / 'issued_chain.pem'
        with chain.open('wb') as out:
            out.write((self.DB_DIR / 'ca.cert.pem').read_bytes())
            out.write((self.DB_DIR / 'issued.cert.pem').read_bytes())

        result = self.run_cmd([
            'openssl', 'verify',
            '-CAfile', str(self.DB_DIR / 'ca.cert.pem'),
            str(chain)
        ])
        self.assertIn(f"{chain}: OK", result.stdout.strip())

        # 4) Verify again after revocation; expect failure
        result = subprocess.run([
            'openssl', 'verify',
            '-CAfile', str(self.DB_DIR / 'ca.cert.pem'),
            '-CRLfile', str(self.DB_DIR / 'crl.pem'),
            '-crl_check',
            str(chain)
        ], capture_output=True, text=True)
        # Should exit non-zero
        self.assertNotEqual(result.returncode, 0)
        # Should indicate certificate revoked
        self.assertRegex(result.stdout + result.stderr,
                         r"error 23 at 0 depth lookup: certificate revoked")

if __name__ == '__main__':
    unittest.main(verbosity=2)
