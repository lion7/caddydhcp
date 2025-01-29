// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package rangeplugin

import (
	"database/sql"
	"fmt"
	"net"

	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
)

func loadDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s", path))
	if err != nil {
		return nil, fmt.Errorf("failed to open database (%T): %w", err, err)
	}
	if _, err := db.Exec("create table if not exists leases4 (mac string not null, ip string not null, expiry int, hostname string not null, primary key (mac, ip))"); err != nil {
		return nil, fmt.Errorf("table creation failed: %w", err)
	}
	return db, nil
}

// loadRecords4 loads the DHCPv4 Records global map with records stored on
// the specified file. The records have to be one per line, a mac address and an
// IP address.
func loadRecords4(db *sql.DB) (map[string]record, error) {
	rows, err := db.Query("select mac, ip, expiry, hostname from leases4")
	if err != nil {
		return nil, fmt.Errorf("failed to query leases database: %w", err)
	}
	defer rows.Close()
	var (
		mac, ip, hostname string
		expiry            int
		records           = make(map[string]record)
	)
	for rows.Next() {
		if err := rows.Scan(&mac, &ip, &expiry, &hostname); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		hwaddr, err := net.ParseMAC(mac)
		if err != nil {
			return nil, fmt.Errorf("malformed hardware address: %s", mac)
		}
		ipaddr := net.ParseIP(ip)
		if ipaddr.To4() == nil {
			return nil, fmt.Errorf("expected an IPv4 address, got: %v", ipaddr)
		}
		records[hwaddr.String()] = record{IP: ipaddr, expires: expiry, hostname: hostname}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed lease database row scanning: %w", err)
	}
	return records, nil
}

// saveIPAddress writes out a lease to storage
func saveIPAddress(db *sql.DB, mac net.HardwareAddr, record record) error {
	stmt, err := db.Prepare(`insert or replace into leases4(mac, ip, expiry, hostname) values (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("statement preparation failed: %w", err)
	}
	defer stmt.Close()
	if _, err := stmt.Exec(
		mac.String(),
		record.IP.String(),
		record.expires,
		record.hostname,
	); err != nil {
		return fmt.Errorf("record insert/update failed: %w", err)
	}
	return nil
}
