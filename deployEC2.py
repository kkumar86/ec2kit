#!/usr/bin/env python

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

    def loadConfig(self, path=None):
        # Get all the Configuration
        config = Config(path=path)
        self.aws_access_key_id = config.get('Credentials','aws_access_key_id')
        self.aws_secret_access_key = config.get('Credentials','aws_secret_access_key')
        self.key_name = config.get('Key','key_name')
        self.instance_type = config.get('Instance','instance_type')
        self.zone = config.get('Instance','zone')
        self.security_groups = config.get('Instance','security_groups')

        self.os = config.get('Type','os')
        self.num_nodes = config.get('Type','num_nodes')
        self.ami = config.get('AMI',self.os)
        self.membase_port = config.get('global', 'port')
        self.ssh_username = config.get('global', 'username')
        self.ssh_key_path = config.get('global', 'ssh_key')
        self.rest_username = config.get('membase','rest_username')
        self.rest_password = config.get('membase','rest_password')

    def launchInstances(self):
        log.info('Starting {0} EC2 instances of type {1} with image {2}'.format(self.num_nodes, self.os, self.ami))
        conn = EC2Connection(self.aws_access_key_id,self.aws_secret_access_key)
        reservation = None
        reservation = conn.run_instances(self.ami, max_count = int(self.num_nodes), key_name = self.key_name,
                                         security_groups = [self.security_groups], instance_type = self.instance_type,
                                         placement = self.zone)
        log.info('ReservationID: {0}'.format(reservation.id))
        log.info('Instances: {0}'.format(self.get_instances(reservation)))
        #wait for instances to become green
        self.wait_for_instances_to_boot(reservation)

        return conn, reservation
        #finally:

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
        return ids
    
    @staticmethod
    def get_instance_public_dns(reservation=None):
        public_dns = []
        for i in range(len(reservation.instances)):
            public_dns.append(reservation.instances[i].public_dns_name)
        log.info("Public IPs: {0}".format(public_dns))
        return public_dns

    def terminate_instances(self, conn, reservation):
        ids = self.get_instances(reservation)
        log.info("Terminate instances {0}".format(ids))
        conn.terminate_instances(instance_ids=ids)


def usage(err=None):
    print """\
Creates a INI file with list of Servers (servers.ini)

Syntax: deployEC2.py [options]

Options:
 -l <config_file>        Path to .conf file containing EC2 information

Examples:
 python deployEC2.py -l /etc/boto.cfg

"""
    sys.exit(err)

def write_config(filename, public_dns):
        FILE = open(filename, "w")
        config = ConfigParser.SafeConfigParser()
        config.add_section("global")
        config.set("global", "username", ec2.ssh_username)
        config.set("global", "ssh_key", ec2.ssh_key_path)
        config.set("global", "port", ec2.membase_port)

        config.add_section("servers")
        for i in range(len(public_dns)):
            config.set("servers", str(i+1), public_dns[i].encode('utf-8'))
        config.add_section("membase")
        config.set("membase", "rest_username", ec2.rest_username)
        config.set("membase", "rest_password", ec2.rest_password)

        # write to file
        config.write(FILE)
        FILE.close()

if __name__ == "__main__":
    ec2 = ManageEC2()
    try:
        (opts, args) = getopt.getopt(sys.argv[1:], 'hl:', [])
        for options, argument in opts:
            if options == "-h":
                usage()
            if options == "-l":
                ec2.loadConfig(path=argument)
    except IndexError:
        usage()
    except getopt.GetoptError, err:
        usage("ERROR: " + str(err))
    conn = None
    reservation = None
    filename = "./servers.ini"
    try:
        conn, reservation = ec2.launchInstances()
        write_config(filename, ManageEC2.get_instance_public_dns(reservation))
    finally:
        if reservation is None:
            log.info("No connection object")
            sys.exit(1)
        ec2.terminate_instances(conn, reservation)
