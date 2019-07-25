require 'rest-client'
require 'json'
require "base64"
require 'fog/openstack'


# TODO test this command openstack_compute.addresses.get_address_pools.first
# test his floating_ip_address = openstack_compute.addresses.create pool: pool_name
# inpsect the floating_ip_address object, need .id from it
# Test associate floating_ip_address = openstack_compute.addresses.create pool: pool_name
# Test releasing with this
# openstack_compute.disassociate_address(vm.ems_ref, automated_floating_ip)
# openstack_compute.release_address(automated_floating_ip)

@bootstrap_linux_job_id = $evm.object['bootstrap_linux_job_id']
ANSIBLE_NAMESPACE = 'AutomationManagement/AnsibleTower/Operations/StateMachines'.freeze
ANSIBLE_STATE_MACHINE_CLASS = 'Job'.freeze
ANSIBLE_STATE_MACHINE_INSTANCE = 'default'.freeze


def get_fog_object(provider, type, tenant)
  endpoint='publicURL'
  (provider.api_version == 'v2') ? (conn_ref = '/v2.0/tokens') : (conn_ref = '/v3/auth/tokens')
  (provider.security_protocol == 'non-ssl') ? (proto = 'http') : (proto = 'https')

  connection_hash = {
    :provider => 'OpenStack',
    :openstack_api_key => provider.authentication_password,
    :openstack_username => provider.authentication_userid,
    :openstack_auth_url => "#{proto}://#{provider.hostname}:#{provider.port}#{conn_ref}",
    # in a OSPd environment, this might need to be commented out depending on accessibility of endpoints
    :openstack_endpoint_type => endpoint,
    :openstack_tenant => tenant,
  }
  # if the openstack environment is using keystone v3, add two keys to hash and replace the auth_url
  if provider.api_version == 'v3'
    connection_hash[:connection_options] = {:ssl_verify_peer => false}
    connection_hash[:openstack_domain_id] = provider.uid_ems
    connection_hash[:openstack_project_name] = tenant
    connection_hash[:openstack_auth_url] = "#{proto}://#{provider.hostname}:#{provider.port}/#{conn_ref}"
  end
  return Object::const_get("Fog").const_get("#{type}").new(connection_hash)
end

def add_floating_ip(vm)
    tenant = $evm.vmdb(:cloud_tenant,vm.cloud_tenant_id)
    provider = vm.ext_management_system
    openstack_network = get_fog_object(provider, 'Network', tenant.name)
    openstack_compute = get_fog_object(provider, 'Compute', tenant.name)
    pool = openstack_compute.addresses.get_address_pools.first
    if pool.nil?
      $evm.log(:error, "No public pools available")
      exit MIQ_ERROR
    end
    pool_name = pool['name']
    begin
      floating_ip_address = openstack_compute.addresses.create pool: pool_name
    rescue => e
      $evm.log(:error, "Could not create floatingip #{e}")
      exit MIQ_ERROR
    end
    instance = openstack_compute.servers.get(vm.ems_ref)
    begin
      instance.associate_address floating_ip_address.ip
    rescue => e
      $evm.log(:error, "Could not attach floating ip #{e}")
      exit MIQ_ERROR
    end
    return floating_ip_address
end

def launch_ansible_job(attrs)
  options = {}
  options[:namespace]     = ANSIBLE_NAMESPACE
  options[:class_name]    = ANSIBLE_STATE_MACHINE_CLASS
  options[:instance_name] = ANSIBLE_STATE_MACHINE_INSTANCE
  options[:user_id]       = $evm.root['user'].id
  options[:attrs]         = attrs
  auto_approve            = true
  return $evm.execute('create_automation_request', options, $evm.root['user'].userid, auto_approve)
end

vm = $evm.root['vm']
if vm.floating_ip_addresses.empty?
  floating_ip_address = add_floating_ip(vm)
  vm.custom_set("automated_floating_ip", floating_ip_address.id)
end

# Trigger ansible JOB
$evm.log(:info, "Triggering Ansible Tower Job")
job_attrs = {
    'job_template_id' => @bootstrap_linux_job_id,
    'Vm::vm' => vm.id
}

$evm.log(:info, "sending ansible job with #{job_attrs}")

launch_ansible_job(job_attrs)
