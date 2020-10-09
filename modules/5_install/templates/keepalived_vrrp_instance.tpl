vrrp_instance OCP_PLB {
  state <STATE>
  interface <INTERFACE>
  virtual_router_id ${virtual_router_id}
  priority <PRIORITY>
  virtual_ipaddress {
    ${virtual_ipaddress}
  }
  track_script {
    haproxy_check
  }
  authentication {
    auth_type PASS
    auth_pass ${password}
  }
}
