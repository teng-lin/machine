package amazonec2

import (
	"crypto/md5"
	"crypto/rand"
	//"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/service/ec2"
	"github.com/codegangsta/cli"
	"github.com/docker/machine/drivers"
	"github.com/docker/machine/provider"
	"github.com/docker/machine/ssh"
	"github.com/docker/machine/state"
	"github.com/docker/machine/utils"
)

const (
	driverName          = "amazonec2"
	defaultRegion       = "us-east-1"
	defaultInstanceType = "t2.micro"
	defaultRootSize     = 16

	machineSecurityGroupName = "docker-machine"
)

var (
	ipRange          = "0.0.0.0/0"
	dockerPort int64 = 2376
	swarmPort  int64 = 3376
	sshPort    int64 = 22
	trueValue        = true
	zeroValue  int64 = 0
)

type Driver struct {
	Id                 string
	AccessKey          string
	SecretKey          string
	SessionToken       string
	Region             string
	AMI                string
	SSHKeyID           int
	SSHUser            string
	SSHPort            int
	KeyName            string
	InstanceId         string
	InstanceType       string
	IPAddress          string
	PrivateIPAddress   string
	MachineName        string
	SecurityGroupId    string
	SecurityGroupName  string
	ReservationId      string
	RootSize           int64
	IamInstanceProfile string
	VpcId              string
	SubnetId           string
	Zone               string
	CaCertPath         string
	PrivateKeyPath     string
	SwarmMaster        bool
	SwarmHost          string
	SwarmDiscovery     string
	storePath          string
	keyPath            string
}

type CreateFlags struct {
	AccessKey          *string
	SecretKey          *string
	Region             *string
	AMI                *string
	InstanceType       *string
	SubnetId           *string
	RootSize           *int64
	IamInstanceProfile *string
}

func init() {
	drivers.Register(driverName, &drivers.RegisteredDriver{
		New:            NewDriver,
		GetCreateFlags: GetCreateFlags,
	})
}

func GetCreateFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:   "amazonec2-access-key",
			Usage:  "AWS Access Key",
			Value:  "",
			EnvVar: "AWS_ACCESS_KEY_ID",
		},
		cli.StringFlag{
			Name:   "amazonec2-secret-key",
			Usage:  "AWS Secret Key",
			Value:  "",
			EnvVar: "AWS_SECRET_ACCESS_KEY",
		},
		cli.StringFlag{
			Name:   "amazonec2-session-token",
			Usage:  "AWS Session Token",
			Value:  "",
			EnvVar: "AWS_SESSION_TOKEN",
		},
		cli.StringFlag{
			Name:   "amazonec2-ami",
			Usage:  "AWS machine image",
			EnvVar: "AWS_AMI",
		},
		cli.StringFlag{
			Name:   "amazonec2-region",
			Usage:  "AWS region",
			Value:  defaultRegion,
			EnvVar: "AWS_DEFAULT_REGION",
		},
		cli.StringFlag{
			Name:   "amazonec2-vpc-id",
			Usage:  "AWS VPC id",
			Value:  "",
			EnvVar: "AWS_VPC_ID",
		},
		cli.StringFlag{
			Name:   "amazonec2-zone",
			Usage:  "AWS zone for instance (i.e. a,b,c,d,e)",
			Value:  "a",
			EnvVar: "AWS_ZONE",
		},
		cli.StringFlag{
			Name:   "amazonec2-subnet-id",
			Usage:  "AWS VPC subnet id",
			Value:  "",
			EnvVar: "AWS_SUBNET_ID",
		},
		cli.StringFlag{
			Name:   "amazonec2-security-group",
			Usage:  "AWS VPC security group",
			Value:  "docker-machine",
			EnvVar: "AWS_SECURITY_GROUP",
		},
		cli.StringFlag{
			Name:   "amazonec2-instance-type",
			Usage:  "AWS instance type",
			Value:  defaultInstanceType,
			EnvVar: "AWS_INSTANCE_TYPE",
		},
		cli.IntFlag{
			Name:   "amazonec2-root-size",
			Usage:  "AWS root disk size (in GB)",
			Value:  defaultRootSize,
			EnvVar: "AWS_ROOT_SIZE",
		},
		cli.StringFlag{
			Name:  "amazonec2-iam-instance-profile",
			Usage: "AWS IAM Instance Profile",
		},
	}
}

func NewDriver(machineName string, storePath string, caCert string, privateKey string) (drivers.Driver, error) {
	id := generateId()
	return &Driver{
		Id:             id,
		MachineName:    machineName,
		storePath:      storePath,
		CaCertPath:     caCert,
		PrivateKeyPath: privateKey,
	}, nil
}

func GetKeyPairs(e *ec2.EC2) ([]*ec2.KeyPairInfo, error) {

	resp, err := e.DescribeKeyPairs(nil)

	if err != nil {
		return nil, err
	}

	return resp.KeyPairs, nil
}

func GetKeyPair(e *ec2.EC2, name string) (*ec2.KeyPairInfo, error) {

	keyPairs, err := GetKeyPairs(e)

	if err != nil {
		return nil, err
	}

	if keyPairs != nil {
		for _, key := range keyPairs {
			if *key.KeyName == name {
				return key, nil
			}
		}
	}
	return nil, nil

}

func RunInstances(e *ec2.EC2,
	ami string,
	instanceType string,
	region string,
	zone string,
	minCount int64,
	maxCount int64,
	securityGroupId string,
	keyName string,
	subnetId string,
	rootSize int64,
	iamInstanceProfile string) (*ec2.Instance, error) {

	var iamInstanceProfileSpec *ec2.IAMInstanceProfileSpecification = nil

	//
	if len(iamInstanceProfile) > 0 {
		iamInstanceProfileSpec = &ec2.IAMInstanceProfileSpecification{
			Name: aws.String(iamInstanceProfile),
		}
	}

	volumeSize := rootSize
	volumeType := "gp2"
	ebs := &ec2.EBSBlockDevice{
		DeleteOnTermination: &trueValue,
		VolumeSize:          &volumeSize,
		VolumeType:          &volumeType,
	}

	deviceName := string("/dev/sda1")
	virtualName := string("")

	blm := ec2.BlockDeviceMapping{
		DeviceName:  &deviceName,
		VirtualName: &virtualName,
		EBS:         ebs,
	}

	blockDeviceMappings := []*ec2.BlockDeviceMapping{&blm}

	instNetworkSpec := ec2.InstanceNetworkInterfaceSpecification{
		DeviceIndex: &zeroValue,
		SubnetID:    &subnetId,
		Groups:      []*string{&securityGroupId},
		AssociatePublicIPAddress: &trueValue,
	}
	networkInterface := []*ec2.InstanceNetworkInterfaceSpecification{&instNetworkSpec}

	availability := region + zone
	request := ec2.RunInstancesInput{
		BlockDeviceMappings: blockDeviceMappings,
		ImageID:             &ami,
		MinCount:            &minCount,
		MaxCount:            &maxCount,
		KeyName:             &keyName,
		Placement: &ec2.Placement{
			AvailabilityZone: &availability,
		},

		InstanceType:       &instanceType,
		NetworkInterfaces:  networkInterface,
		IAMInstanceProfile: iamInstanceProfileSpec,
	}

	//instance, err := d.getClient().RunInstance(d.AMI, d.InstanceType, d.Zone, 1, 1, d.SecurityGroupId, d.KeyName, d.SubnetId, bdm, d.IamInstanceProfile)
	response, err := e.RunInstances(&request)

	var instance *ec2.Instance = nil

	if len(response.Instances) > 0 {
		instance = response.Instances[0]
	}

	return instance, err
}

func CreateTags(e *ec2.EC2, instanceId string, tags map[string]string) error {

	ec2tags := []*ec2.Tag{}

	for k, v := range tags {
		key := k
		val := v
		ec2tags = append(ec2tags, &ec2.Tag{
			Key:   &key,
			Value: &val,
		})
	}

	request := ec2.CreateTagsInput{
		Resources: []*string{&instanceId},
		Tags:      ec2tags,
	}

	_, err := e.CreateTags(&request)
	return err
}

func StartInstance(cli *ec2.EC2, instanceId string) error {
	request := ec2.StartInstancesInput{
		InstanceIDs: []*string{&instanceId},
	}

	_, err := cli.StartInstances(&request)
	return err
}

func StopInstance(e *ec2.EC2, instanceId string, force bool) error {

	request := ec2.StopInstancesInput{
		Force:       &force,
		InstanceIDs: []*string{&instanceId},
	}
	_, err := e.StopInstances(&request)

	return err
}

func GetInstance(e *ec2.EC2, instanceId string) (*ec2.Instance, error) {

	var instance *ec2.Instance = nil

	request := ec2.DescribeInstancesInput{
		InstanceIDs: []*string{&instanceId},
	}

	resp, err := e.DescribeInstances(&request)

	if err != nil || len(resp.Reservations) == 0 {
		return instance, err
	}
	reservation := resp.Reservations[0]

	if len(reservation.Instances) == 0 {
		return instance, err
	}

	instance = reservation.Instances[0]
	return instance, err
}

func ImportKeyPair(e *ec2.EC2, keyName string, publicKey []byte) error {

	request := ec2.ImportKeyPairInput{
		KeyName:           &keyName,
		PublicKeyMaterial: publicKey,
	}

	_, err := e.ImportKeyPair(&request)

	return err
}

func TerminateInstance(e *ec2.EC2, instanceId string) error {

	request := ec2.TerminateInstancesInput{
		InstanceIDs: []*string{&instanceId},
	}
	_, err := e.TerminateInstances(&request)

	return err
}

func GetSecurityGroups(e *ec2.EC2) ([]*ec2.SecurityGroup, error) {

	securityGroups := []*ec2.SecurityGroup{}

	resp, err := e.DescribeSecurityGroups(nil)

	if err != nil {
		return securityGroups, err
	}

	securityGroups = resp.SecurityGroups
	return securityGroups, err
}

func GetSecurityGroupById(e *ec2.EC2, id string) (*ec2.SecurityGroup, error) {

	groups, err := GetSecurityGroups(e)

	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if *g.GroupID == id {
			return g, nil
		}
	}

	return nil, nil
}

func CreateSecurityGroup(e *ec2.EC2, groupName string,
	description string, vpcid string) (*ec2.SecurityGroup, error) {

	var securityGroup *ec2.SecurityGroup = nil

	request := ec2.CreateSecurityGroupInput{
		Description: &description,
		GroupName:   &groupName,
		VPCID:       &vpcid,
	}

	resp, err := e.CreateSecurityGroup(&request)

	if err != nil {
		return securityGroup, err
	}

	securityGroup, err = GetSecurityGroupById(e, *resp.GroupID)

	return securityGroup, err
}

func AuthorizeSecurityGroup(e *ec2.EC2, securityGroupId string, perms []*ec2.IPPermission) error {
	request := ec2.AuthorizeSecurityGroupIngressInput{
		GroupID:       &securityGroupId,
		IPPermissions: perms,
	}
	_, err := e.AuthorizeSecurityGroupIngress(&request)
	return err
}

func DeleteSecurityGroup(e *ec2.EC2, securityGroupId string) error {
	request := ec2.DeleteSecurityGroupInput{
		GroupID: &securityGroupId,
	}

	_, err := e.DeleteSecurityGroup(&request)
	return err
}

func DeleteKeyPair(e *ec2.EC2, keyName string) error {
	request := ec2.DeleteKeyPairInput{
		KeyName: &keyName,
	}
	_, err := e.DeleteKeyPair(&request)
	return err
}

func GetSubnets(e *ec2.EC2, regionZone string, vpcId string) ([]*ec2.Subnet, error) {
	// TODO: move outside of this function
	//regionZone := d.Region + d.Zone
	availabilityZone := "availabilityZone"
	availabilityZoneFilter := ec2.Filter{
		Name:   &availabilityZone,
		Values: []*string{&regionZone},
	}

	vpcid := "vpc-id"
	vpcIDFilter := ec2.Filter{
		Name:   &vpcid,
		Values: []*string{&vpcId},
	}

	filter := []*ec2.Filter{&availabilityZoneFilter, &vpcIDFilter}

	request := ec2.DescribeSubnetsInput{Filters: filter}

	result, err := e.DescribeSubnets(&request)

	if err != nil {
		return []*ec2.Subnet{}, err
	}

	return result.Subnets, err
}

func (d *Driver) GetProviderType() provider.ProviderType {
	return provider.Remote
}

func (d *Driver) AuthorizePort(ports []*drivers.Port) error {
	return nil
}

func (d *Driver) DeauthorizePort(ports []*drivers.Port) error {
	return nil
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	region, err := validateAwsRegion(flags.String("amazonec2-region"))
	if err != nil {
		return err
	}

	image := flags.String("amazonec2-ami")
	if len(image) == 0 {
		image = regionDetails[region].AmiId
	}

	d.AccessKey = flags.String("amazonec2-access-key")
	d.SecretKey = flags.String("amazonec2-secret-key")
	d.SessionToken = flags.String("amazonec2-session-token")
	d.Region = region
	d.AMI = image
	d.InstanceType = flags.String("amazonec2-instance-type")
	d.VpcId = flags.String("amazonec2-vpc-id")
	d.SubnetId = flags.String("amazonec2-subnet-id")
	d.SecurityGroupName = flags.String("amazonec2-security-group")
	zone := flags.String("amazonec2-zone")
	d.Zone = zone[:]
	d.RootSize = int64(flags.Int("amazonec2-root-size"))
	d.IamInstanceProfile = flags.String("amazonec2-iam-instance-profile")
	d.SwarmMaster = flags.Bool("swarm-master")
	d.SwarmHost = flags.String("swarm-host")
	d.SwarmDiscovery = flags.String("swarm-discovery")
	d.SSHUser = "ubuntu"
	d.SSHPort = 22

	if d.AccessKey == "" {
		return fmt.Errorf("amazonec2 driver requires the --amazonec2-access-key option")
	}

	if d.SecretKey == "" {
		return fmt.Errorf("amazonec2 driver requires the --amazonec2-secret-key option")
	}

	if d.SubnetId == "" && d.VpcId == "" {
		return fmt.Errorf("amazonec2 driver requires either the --amazonec2-subnet-id or --amazonec2-vpc-id option")
	}

	if d.isSwarmMaster() {
		u, err := url.Parse(d.SwarmHost)
		if err != nil {
			return fmt.Errorf("error parsing swarm host: %s", err)
		}

		parts := strings.Split(u.Host, ":")
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return err
		}

		swarmPort = int64(port)
	}

	return nil
}

func (d *Driver) GetMachineName() string {
	return d.MachineName
}

func (d *Driver) DriverName() string {
	return driverName
}

func (d *Driver) checkPrereqs() error {
	// check for existing keypair
	cli := d.getClient()
	key, err := GetKeyPair(cli, d.MachineName)
	if err != nil {
		return err
	}

	if key != nil {
		return fmt.Errorf("There is already a keypair with the name %s.  Please either remove that keypair or use a different machine name.", d.MachineName)
	}

	if d.SubnetId == "" {

		regionZone := d.Region + d.Zone
		subnets, err := GetSubnets(cli, regionZone, d.VpcId)
		if err != nil {
			return err
		}

		if len(subnets) == 0 {
			return fmt.Errorf("unable to find a subnet in the zone: %s", regionZone)
		}

		d.SubnetId = *subnets[0].SubnetID

		// try to find default
		if len(subnets) > 1 {
			for _, subnet := range subnets {
				if *subnet.DefaultForAZ {
					d.SubnetId = *subnet.SubnetID
					break
				}
			}
		}
	}

	return nil
}

func (d *Driver) PreCreateCheck() error {
	return d.checkPrereqs()
}

func (d *Driver) instanceIpAvailable() bool {
	ip, err := d.GetIP()
	if err != nil {
		log.Debug(err)
	}
	if ip != "" {
		d.IPAddress = ip
		log.Debugf("Got the IP Address, it's %q", d.IPAddress)
		return true
	}
	return false
}

func (d *Driver) Create() error {
	if err := d.checkPrereqs(); err != nil {
		return err
	}

	log.Infof("Launching instance...")

	if err := d.createKeyPair(); err != nil {
		return fmt.Errorf("unable to create key pair: %s", err)
	}

	if err := d.configureSecurityGroup(d.SecurityGroupName); err != nil {
		return err
	}

	cli := d.getClient()

	log.Debugf("launching instance in subnet %s", d.SubnetId)
	instance, err := RunInstances(cli, d.AMI, d.InstanceType, d.Region, d.Zone, 1, 1,
		d.SecurityGroupId, d.KeyName, d.SubnetId, d.RootSize, d.IamInstanceProfile)

	if err != nil {
		return fmt.Errorf("Error launching instance: %s", err)
	}

	//instance := response.Instances[0]
	d.InstanceId = *instance.InstanceID

	log.Debug("waiting for ip address to become available")
	if err := utils.WaitFor(d.instanceIpAvailable); err != nil {
		return err
	}

	if len(instance.NetworkInterfaces) > 0 {
		d.PrivateIPAddress = *instance.NetworkInterfaces[0].PrivateIPAddress
	}

	d.waitForInstance()

	log.Debugf("created instance ID %s, IP address %s, Private IP address %s",
		d.InstanceId,
		d.IPAddress,
		d.PrivateIPAddress,
	)

	log.Infof("Waiting for SSH on %s:%d", d.IPAddress, 22)

	if err := ssh.WaitForTCP(fmt.Sprintf("%s:%d", d.IPAddress, 22)); err != nil {
		return err
	}

	log.Debug("Settings tags for instance")
	tags := map[string]string{
		"Name": d.MachineName,
	}

	if err = CreateTags(cli, d.InstanceId, tags); err != nil {
		return err
	}

	return nil
}

func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	if ip == "" {
		return "", nil
	}
	return fmt.Sprintf("tcp://%s:%d", ip, dockerPort), nil
}

func (d *Driver) GetIP() (string, error) {
	instance, err := d.getInstance()
	if err != nil {
		return "", err
	}
	ip := ""
	if instance != nil && instance.PublicIPAddress != nil {
		ip = *instance.PublicIPAddress
	}
	return ip, nil
}

func (d *Driver) GetState() (state.State, error) {
	instance, err := d.getInstance()
	if err != nil {
		return state.Error, err
	}

	ec2state := *instance.State

	switch *ec2state.Name {
	case "pending":
		return state.Starting, nil
	case "running":
		return state.Running, nil
	case "stopping":
		return state.Stopping, nil
	case "shutting-down":
		return state.Stopping, nil
	case "stopped":
		return state.Stopped, nil
	default:
		return state.Error, nil
	}
	return state.None, nil
}

func (d *Driver) GetSSHHostname() (string, error) {
	// TODO: use @nathanleclaire retry func here (ehazlett)
	return d.GetIP()
}

func (d *Driver) GetSSHPort() (int, error) {
	if d.SSHPort == 0 {
		d.SSHPort = 22
	}

	return d.SSHPort, nil
}

func (d *Driver) GetSSHUsername() string {
	if d.SSHUser == "" {
		d.SSHUser = "ubuntu"
	}

	return d.SSHUser
}

func (d *Driver) Start() error {
	cli := d.getClient()
	if err := StartInstance(cli, d.InstanceId); err != nil {
		return err
	}

	if err := d.waitForInstance(); err != nil {
		return err
	}

	return nil
}

func (d *Driver) Stop() error {
	cli := d.getClient()
	if err := StopInstance(cli, d.InstanceId, false); err != nil {
		return err
	}
	return nil
}

func (d *Driver) Remove() error {

	if err := d.terminate(); err != nil {
		return fmt.Errorf("unable to terminate instance: %s", err)
	}

	// remove keypair
	if err := d.deleteKeyPair(); err != nil {
		return fmt.Errorf("unable to remove key pair: %s", err)
	}

	return nil
}

func (d *Driver) Restart() error {
	cli := d.getClient()
	if err := StartInstance(cli, d.InstanceId); err != nil {
		return fmt.Errorf("unable to restart instance: %s", err)
	}
	return nil
}

func (d *Driver) Kill() error {
	cli := d.getClient()
	if err := StopInstance(cli, d.InstanceId, true); err != nil {
		return err
	}
	return nil
}

func (d *Driver) getClient() *ec2.EC2 {

	creds := aws.Creds(d.AccessKey, d.SecretKey, d.SessionToken)
	config := aws.Config{
		Credentials: creds,
		Region:      d.Region,
	}
	cli := ec2.New(&config)
	return cli
}

func (d *Driver) GetSSHKeyPath() string {
	return filepath.Join(d.storePath, "id_rsa")
}

func (d *Driver) getInstance() (*ec2.Instance, error) {
	cli := d.getClient()
	instance, err := GetInstance(cli, d.InstanceId)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

func (d *Driver) instanceIsRunning() bool {
	st, err := d.GetState()
	if err != nil {
		log.Debug(err)
	}
	if st == state.Running {
		return true
	}
	return false
}

func (d *Driver) waitForInstance() error {
	if err := utils.WaitFor(d.instanceIsRunning); err != nil {
		return err
	}

	return nil
}

func (d *Driver) createKeyPair() error {

	if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return err
	}

	publicKey, err := ioutil.ReadFile(d.GetSSHKeyPath() + ".pub")
	if err != nil {
		return err
	}

	keyName := d.MachineName

	log.Debugf("creating key pair: %s", keyName)

	cli := d.getClient()
	if err := ImportKeyPair(cli, keyName, publicKey); err != nil {
		return err
	}

	d.KeyName = keyName
	return nil
}

func (d *Driver) terminate() error {
	if d.InstanceId == "" {
		return fmt.Errorf("unknown instance")
	}

	log.Debugf("terminating instance: %s", d.InstanceId)

	cli := d.getClient()

	if err := TerminateInstance(cli, d.InstanceId); err != nil {
		return fmt.Errorf("unable to terminate instance: %s", err)
	}

	return nil
}

func (d *Driver) isSwarmMaster() bool {
	return d.SwarmMaster
}

func (d *Driver) securityGroupAvailableFunc(id string) func() bool {
	return func() bool {
		cli := d.getClient()
		_, err := GetSecurityGroupById(cli, id)
		if err == nil {
			return true
		}
		log.Debug(err)
		return false
	}
}

func (d *Driver) configureSecurityGroup(groupName string) error {
	log.Debugf("configuring security group in %s", d.VpcId)

	var securityGroup *ec2.SecurityGroup

	cli := d.getClient()
	groups, err := GetSecurityGroups(cli)
	if err != nil {
		return err
	}

	for _, grp := range groups {
		if *grp.GroupName == groupName {
			log.Debugf("found existing security group (%s) in %s", groupName, d.VpcId)
			securityGroup = grp
			break
		}
	}

	// if not found, create
	if securityGroup == nil {
		log.Debugf("creating security group (%s) in %s", groupName, d.VpcId)
		group, err := CreateSecurityGroup(cli, groupName, "Docker Machine", d.VpcId)
		if err != nil {
			return err
		}
		securityGroup = group
		// wait until created (dat eventual consistency)
		log.Debugf("waiting for group (%s) to become available", group.GroupID)
		if err := utils.WaitFor(d.securityGroupAvailableFunc(*group.GroupID)); err != nil {
			return err
		}
	}

	d.SecurityGroupId = *securityGroup.GroupID

	perms := d.configureSecurityGroupPermissions(securityGroup)

	if len(perms) != 0 {
		log.Debugf("authorizing group %s with permissions: %v", securityGroup.GroupName, perms)
		if err := AuthorizeSecurityGroup(cli, d.SecurityGroupId, perms); err != nil {
			return err
		}

	}

	return nil
}

func (d *Driver) configureSecurityGroupPermissions(group *ec2.SecurityGroup) []*ec2.IPPermission {
	hasSshPort := false
	hasDockerPort := false
	hasSwarmPort := false
	for _, p := range group.IPPermissions {
		switch *p.FromPort {
		case 22:
			hasSshPort = true
		case dockerPort:
			hasDockerPort = true
		case swarmPort:
			hasSwarmPort = true
		}
	}

	perms := []*ec2.IPPermission{}
	ec2IPRange := ec2.IPRange{CIDRIP: &ipRange}
	ipprotocol := "tcp"

	if !hasSshPort {
		perms = append(perms, &ec2.IPPermission{
			IPProtocol: &ipprotocol,
			FromPort:   &sshPort,
			ToPort:     &sshPort,
			IPRanges:   []*ec2.IPRange{&ec2IPRange},
		})
	}

	if !hasDockerPort {
		perms = append(perms, &ec2.IPPermission{
			IPProtocol: &ipprotocol,
			FromPort:   &dockerPort,
			ToPort:     &dockerPort,
			IPRanges:   []*ec2.IPRange{&ec2IPRange},
		})
	}

	if !hasSwarmPort && d.SwarmMaster {
		perms = append(perms, &ec2.IPPermission{
			IPProtocol: &ipprotocol,
			FromPort:   &swarmPort,
			ToPort:     &swarmPort,
			IPRanges:   []*ec2.IPRange{&ec2IPRange},
		})
	}

	log.Debugf("configuring security group authorization for %s", ipRange)

	return perms
}

func (d *Driver) deleteSecurityGroup() error {
	log.Debugf("deleting security group %s", d.SecurityGroupId)

	cli := d.getClient()
	if err := DeleteSecurityGroup(cli, d.SecurityGroupId); err != nil {
		return err
	}

	return nil
}

func (d *Driver) deleteKeyPair() error {
	log.Debugf("deleting key pair: %s", d.KeyName)

	cli := d.getClient()
	if err := DeleteKeyPair(cli, d.KeyName); err != nil {
		return err
	}

	return nil
}

func generateId() string {
	rb := make([]byte, 10)
	_, err := rand.Read(rb)
	if err != nil {
		log.Fatalf("unable to generate id: %s", err)
	}

	h := md5.New()
	io.WriteString(h, string(rb))
	return fmt.Sprintf("%x", h.Sum(nil))
}
