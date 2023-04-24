CREATE TABLE "openvpn_instances" (id INTEGER PRIMARY KEY NOT NULL, address TEXT NOT NULL, port INT NOT NULL, pid INT NOT NULL);
CREATE UNIQUE INDEX openvpn_instances_address_port_IDX ON openvpn_instances (address,port);

CREATE TABLE "ippools_v4" (id INTEGER PRIMARY KEY NOT NULL, pool TEXT NOT NULL, pool_offset INT NOT NULL, username TEXT NOT NULL UNIQUE, cid INT NOT NULL, openvpn_instance INT NOT NULL, updated DATETIME NOT NULL, FOREIGN KEY (openvpn_instance) REFERENCES openvpn_instances(id) ON UPDATE CASCADE ON DELETE CASCADE);
CREATE UNIQUE INDEX ippools_v4_pool_offset_IDX ON ippools_v4 (pool,pool_offset);
CREATE UNIQUE INDEX ippools_v4_cid_openvpn_instance_IDX ON ippools_v4 (cid,openvpn_instance);
