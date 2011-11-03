#!/usr/bin/env python
#TODO
# Error handling
# EBS Support

import sys
sys.path.append(".")
sys.path.append("lib")
import time
from boto.pyami.config import Config
from boto.ec2.connection import EC2Connection
import logger
import getopt
import ConfigParser

SSH_OPTS        = '-o StrictHostKeyChecking=no -i '
log = logger.new_logger("deployEC2")

class ManageEC2(object):
    instance_ids = []

    def __init__(self):
        self.aws_access_key_id  = None
        self.aws_secret_access_key = None
        self.ami = None
        self.key_name = None
        self.instance_type = None
        self.zone = None
        self.security_groups = None
        self.os = None
        self.num_nodes = None
        self.ssh_username = None
        self.ssh_key_path = None
        self.membase_port = None
        self.rest_username = None
        self.rest_password = None
        self.num_ebs = None
        self.ebs_size = None

    def loadConfig(self, path=None):
        # Get all the Configuration
        config = Config(path=path)
        self.aws_access_key_id = config.get('Credentials','aws_access_key_id')
        self.aws_secret_access_key = config.get('Credentials','aws_secret_access_key')
        self.key_name = config.get('Key','key_name')
        self.instance_type = config.get('Instance','instance_type')
        self.zone = config.get('Instance','zone', default='us-east-1c')
        self.security_groups = config.get('Instance','security_groups')

        self.os = config.get('Type','os')
        self.num_nodes = int(config.get('Type','num_nodes'))
        self.ami = config.get('AMI',self.os)
        self.ebs_size = int(config.get('EBS','volume_size', default=0))
        self.num_ebs = int(config.get('EBS','volumes', default=0))
        self.membase_port = config.get('global', 'port', default='8091')
        self.ssh_username = config.get('global', 'username', default='root')
        self.ssh_key_path = config.get('global', 'ssh_key', default='/root/.ssh/QAkey.pem')
        self.rest_username = config.get('membase','rest_username', default='Administrator')
        self.rest_password = config.get('membase','rest_password', default='password')

    def launchInstances(self):
        log.info('Starting {0} EC2 instances of type {1} with image {2}'.format(self.num_nodes, self.os, self.ami))
        try:
            conn = EC2Connection(self.aws_access_key_id, self.aws_secret_access_key)
            reservation = conn.run_instances(self.ami, max_count = self.num_nodes, key_name = self.key_name,
                                         security_groups = [self.security_groups], instance_type = self.instance_type,
                                         placement = self.zone)

            log.info('ReservationID: {0}'.format(reservation.id))
            log.info('Instances: {0}'.format(ManageEC2.get_instances(reservation)))
            #wait for instances to boot up
            self.wait_for_instances_to_boot(reservation)
            if self.num_ebs > 0:
                ManageEC2.launchEBS(conn, reservation, self)
        finally:
            return conn, reservation

    @staticmethod
    def launchEBS(conn, reservation, self):
        ebs = []
        total_ebs = self.num_ebs * self.num_nodes
        log.info("Launching {0} EBS volumes in zone {1}".format(total_ebs, self.zone))
        while total_ebs > 0 :
            ebs_id = conn.create_volume(self.ebs_size, self.zone)
            log.info("EBS volume created {0}".format(ebs_id.id))
            ebs.append(ebs_id.id)
            total_ebs -= 1
        ebs = ManageEC2.utf8_decode_list(ebs)
        log.info("EBS volume ids {0}".format(ebs))
        ManageEC2.attach_ebs(conn, ManageEC2.get_instances(reservation), ebs, self.num_ebs)

    @staticmethod
    def wait_for_instances_to_boot(reservation, timeout_in_seconds=300):
        log.info('Wait for instances to boot up in {0} secs'.format(timeout_in_seconds))
        start = time.time()
        for i in range(len(reservation.instances)):
            current_instance = reservation.instances[i]
            while not current_instance.update() == 'running' and (time.time() - start) <= timeout_in_seconds:
                log.info("{0} -> {1}".format(current_instance.id, current_instance.state))
                time.sleep(5)
            else:
                log.info("{0} -> {1}".format(current_instance.id, current_instance.state))

    @staticmethod
    def get_instances(reservation=None):
        ids = []
        for i in range(len(reservation.instances)):
            ids.append(reservation.instances[i].id)
        return ManageEC2.utf8_decode_list(ids)
    
    @staticmethod
    def get_instance_public_dns(reservation=None):
        public_dns = []
        for i in range(len(reservation.instances)):
            public_dns.append(reservation.instances[i].public_dns_name)
        log.info("Public IPs: {0}".format(ManageEC2.utf8_decode_list(public_dns)))
        return public_dns

    @staticmethod
    def get_instance_private_dns(reservation=None):
        private_dns = []
        for i in range(len(reservation.instances)):
            private_dns.append(reservation.instances[i].private_dns_name)
        log.info("Private IPs: {0}".format(ManageEC2.utf8_decode_list(private_dns)))
        return private_dns

    def terminate_instances(self, conn, reservation):
        ids = self.get_instances(reservation)
        conn.terminate_instances(instance_ids=ids)
        log.info("Terminate instances {0}".format(ids))

    @staticmethod
    def utf8_decode_list(l):
        new_list = []
        for item in l:
            if isinstance(item, unicode):
                new_list.append(item.encode('utf-8'))
        return new_list

    @staticmethod
    def attach_ebs(conn=None, instance_ids=[], volumes=[], num_ebs_per_node=0):
        print conn, instance_ids, volumes, num_ebs_per_node
        if conn is None:
            log.error("No EC2 Connection")
            sys.exit(1)
        log.info("Will try to attach {0} to {1}".format(volumes, instance_ids))
        devices = ['f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p']
        i = 0
        for instance in instance_ids:
            j = 0
            print instance, num_ebs_per_node
            while j < num_ebs_per_node :
                ready = conn.attach_volume(volumes[i], instance, device = '/dev/sd'+devices[j])
                print ready
                if ready:
                    log.info("Attached {0} to {1}".format(volumes[i], instance))
                    i += 1
                    j += 1
                else:
                    log.error("Unable to attach {0} to {1}".format(volumes[i], instance))

def usage(err=None):
    print """\
Launches EC2 Servers and returns a INI file with the list of servers instantiated

Syntax: deployEC2.py [options]

Options:
 -h                      Help
 -l <config_file>        Path to .conf file containing EC2 information
 -f <output_filename>    Path to .ini file which is outputted, default servers.ini

Examples:
 python deployEC2.py -l /etc/boto.cfg -f my_ec2.ini

"""
    sys.exit(err)

def write_config(filepath, dns, public_dns):

        config = ConfigParser.SafeConfigParser()
        config.add_section("global")
        config.set("global", "username", ec2.ssh_username)
        config.set("global", "ssh_key", ec2.ssh_key_path)
        config.set("global", "port", ec2.membase_port)

        config.add_section("servers")
        for i in range(len(dns)):
            config.set("servers", "# "+str(i+1), public_dns[i].encode('utf-8'))
            config.set("servers", str(i+1), dns[i].encode('utf-8'))
        config.add_section("membase")
        config.set("membase", "rest_username", ec2.rest_username)
        config.set("membase", "rest_password", ec2.rest_password)

        # write to file
        FILE = open(filepath, "w")
        log.info("Writing server information into {0}".format(filepath))
        config.write(FILE)
        FILE.close()

if __name__ == "__main__":
    ec2 = ManageEC2()
    filepath = "servers.ini"
    conn = None
    reservation = None

    try:
        (opts, args) = getopt.getopt(sys.argv[1:], 'hl:f:', [])
        for options, argument in opts:
            if options == "-h":
                usage()
            if options == "-l":
                ec2.loadConfig(path=argument)
            if options == "-f":
                filepath = argument
    except IndexError:
        usage()
    except getopt.GetoptError, err:
        usage("ERROR: " + str(err))

    try:
        conn, reservation = ec2.launchInstances()
        write_config(filepath, ManageEC2.get_instance_private_dns(reservation), ManageEC2.get_instance_public_dns(reservation))

    except Exception as ex:
        log.error("Exception {0}".format(ex))
        if reservation is None:
            log.error("No connection object")
        else:
            ec2.terminate_instances(conn, reservation)
        sys.exit(1)
