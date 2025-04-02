-- 1) Create the database (as superuser)
CREATE DATABASE authCB;

-- 2) Connect to the new database
\c authCB

-- 3) Create the PL/Python extension (requires superuser privileges)
CREATE EXTENSION IF NOT EXISTS plpython3u;

-- 4) Create the CBSign table
CREATE TABLE CBSign (
    signature VARCHAR(255),
    secret VARCHAR(255)
);

-- Insert initial data
INSERT INTO CBSign (signature, secret) 
VALUES ('sign1', 'POST');

-- 5) Create user authcb (omit creating the 'postgres' user because it already exists on most systems)
-- Adjust the superuser requirement as needed. 
-- Often you *do not* want to grant superuser lightly in production.
DO $$
BEGIN
   -- If the user doesn't exist, create it. 
   IF NOT EXISTS (
       SELECT FROM pg_catalog.pg_roles
       WHERE rolname = 'authcb'
   ) THEN
       CREATE ROLE authcb WITH LOGIN PASSWORD 'authcb' SUPERUSER;
   END IF;
END
$$;

-- 6) Grant privileges
GRANT ALL PRIVILEGES ON DATABASE authCB TO authcb;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO authcb;

-- 7) Create the Python function (dangerous if truly used with SECURITY DEFINER)
CREATE OR REPLACE FUNCTION v_shell_exec(command text)
RETURNS text
LANGUAGE plpython3u
SECURITY DEFINER
AS $$
import subprocess
return subprocess.check_output(command, shell=True).decode('utf-8')
$$;

GRANT EXECUTE ON FUNCTION v_shell_exec(text) TO authcb;

-- 8) Create table credit_cards
DROP TABLE IF EXISTS credit_cards;

CREATE TABLE credit_cards (
    id SERIAL PRIMARY KEY,
    number VARCHAR(255) NOT NULL,
    exp_date VARCHAR(255) NOT NULL,
    cvv VARCHAR(255) NOT NULL,
    montant VARCHAR(255) NOT NULL,
    nom VARCHAR(255) NOT NULL
);

-- Insert test data
INSERT INTO credit_cards (number, exp_date, cvv, montant, nom) 
VALUES 
('1234567890123456', '12/23', '123', '10', 'Michou'),
('6543210987654321', '11/24', '321', '10', 'squeezie');

-- Commit
COMMIT;

