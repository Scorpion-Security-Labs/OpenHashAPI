#!/bin/bash

# Simple script to back up the OHA database
date=$(date +"%m-%d-%Y")
mysqldump --databases --single-transaction --quick OpenHashAPI > $date-oha.sql
