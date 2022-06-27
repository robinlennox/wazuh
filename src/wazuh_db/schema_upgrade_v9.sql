/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 *
 * May 21, 2021
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

CREATE TABLE IF NOT EXIST _sys_hotfixes (
    scan_id INTEGER,
    scan_time TEXT,
    hotfix TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    PRIMARY KEY (scan_id, hotfix)
);

INSERT INTO _sys_hotfixes SELECT scan_id, scan_time, hotfix, checksum FROM sys_hotfixes;
DROP TABLE IF EXISTS sys_hotfixes;
ALTER TABLE _sys_hotfixes RENAME to sys_hotfixes
CREATE INDEX IF NOT EXISTS hotfix_id ON sys_hotfixes (scan_id);

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 9);
