CREATE DATABASE OpenHashAPI;
USE OpenHashAPI;

CREATE TABLE Hashes (
  algorithm      VARCHAR(8) NOT NULL,
  hash     VARCHAR(255) NOT NULL,
  plaintext     VARCHAR(255) NOT NULL,
  validated     BOOLEAN DEFAULT FALSE,
  PRIMARY KEY (`algorithm`, `hash`)
);

CREATE TABLE Users (
    id    int NOT NULL AUTO_INCREMENT,
    username    VARCHAR(32) NOT NULL,
    password    VARCHAR(255) NOT NULL,
    can_login    BOOLEAN NOT NULL,
    can_search    BOOLEAN NOT NULL,
    can_upload    BOOLEAN NOT NULL,
    can_manage    BOOLEAN NOT NULL,
    can_view_private    BOOLEAN NOT NULL,
    can_edit_private    BOOLEAN NOT NULL,
    PRIMARY KEY (`id`, `username`)
);
ALTER TABLE Users ADD UNIQUE (username);

