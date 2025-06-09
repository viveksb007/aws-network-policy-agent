package fwruleprocessor

import (
	"net"
	"sort"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestBpfClient_computeMapEntriesFromEndpointRules(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	//protocolUDP := corev1.ProtocolUDP
	//protocolSCTP := corev1.ProtocolSCTP

	var testIP v1alpha1.NetworkAddress
	var gotKeys []string

	nodeIP := "10.1.1.1"
	_, nodeIPCIDR, _ := net.ParseCIDR(nodeIP + "/32")
	nodeIPKey := utils.ComputeTrieKey(*nodeIPCIDR, false)
	// nodeIPValue := utils.ComputeTrieValue([]v1alpha1.Port{}, test_bpfClientLogger, true, false)

	var testPort int32
	testPort = 80
	testIP = "10.1.1.2/32"
	_, testIPCIDR, _ := net.ParseCIDR(string(testIP))

	testIPKey := utils.ComputeTrieKey(*testIPCIDR, false)
	//      cidrWithPPValue := utils.ComputeTrieValue(testL4Info, test_bpfClientLogger, false, false)
	type args struct {
		firewallRules []EbpfFirewallRules
	}

	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr error
	}{
		{
			name: "CIDR with Port and Protocol",
			args: args{
				[]EbpfFirewallRules{
					{
						IPCidr: "10.1.1.2/32",
						L4Info: []v1alpha1.Port{
							{
								Protocol: &protocolTCP,
								Port:     &testPort,
							},
						},
					},
				},
			},
			want: []string{string(nodeIPKey), string(testIPKey)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewFirewallRuleProcessor("10.1.1.1", "/32", false).ComputeMapEntriesFromEndpointRules(tt.args.firewallRules)
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				for key, _ := range got {
					gotKeys = append(gotKeys, key)
				}
				sort.Strings(tt.want)
				sort.Strings(gotKeys)
				assert.Equal(t, tt.want, gotKeys)
			}
		})
	}
}

func TestBpfClient_CheckAndDeriveCatchAllIPPorts(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port80 int32 = 80

	type want struct {
		catchAllL4Info           []v1alpha1.Port
		isCatchAllIPEntryPresent bool
		allowAllPortAndProtocols bool
	}

	l4InfoWithCatchAllEntry := []EbpfFirewallRules{
		{
			IPCidr: "0.0.0.0/0",
			L4Info: []v1alpha1.Port{
				{
					Protocol: &protocolTCP,
					Port:     &port80,
				},
			},
		},
	}

	l4InfoWithNoCatchAllEntry := []EbpfFirewallRules{
		{
			IPCidr: "1.1.1.1/32",
			L4Info: []v1alpha1.Port{
				{
					Protocol: &protocolTCP,
					Port:     &port80,
				},
			},
		},
	}

	l4InfoWithCatchAllEntryAndAllProtocols := []EbpfFirewallRules{
		{
			IPCidr: "0.0.0.0/0",
		},
	}

	tests := []struct {
		name          string
		firewallRules []EbpfFirewallRules
		want          want
	}{
		{
			name:          "Catch All Entry present",
			firewallRules: l4InfoWithCatchAllEntry,
			want: want{
				catchAllL4Info: []v1alpha1.Port{
					{
						Protocol: &protocolTCP,
						Port:     &port80,
					},
				},
				isCatchAllIPEntryPresent: true,
				allowAllPortAndProtocols: false,
			},
		},

		{
			name:          "No Catch All Entry present",
			firewallRules: l4InfoWithNoCatchAllEntry,
			want: want{
				isCatchAllIPEntryPresent: false,
				allowAllPortAndProtocols: false,
			},
		},

		{
			name:          "Catch All Entry With no Port info",
			firewallRules: l4InfoWithCatchAllEntryAndAllProtocols,
			want: want{
				isCatchAllIPEntryPresent: true,
				allowAllPortAndProtocols: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCatchAllL4Info, gotIsCatchAllIPEntryPresent, gotAllowAllPortAndProtocols := NewFirewallRuleProcessor("10.1.1.1", "/32", false).checkAndDeriveCatchAllIPPorts(tt.firewallRules)
			assert.Equal(t, tt.want.catchAllL4Info, gotCatchAllL4Info)
			assert.Equal(t, tt.want.isCatchAllIPEntryPresent, gotIsCatchAllIPEntryPresent)
			assert.Equal(t, tt.want.allowAllPortAndProtocols, gotAllowAllPortAndProtocols)
		})
	}
}

func TestBpfClient_CheckAndDeriveL4InfoFromAnyMatchingCIDRs(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port80 int32 = 80

	type want struct {
		matchingCIDRL4Info []v1alpha1.Port
	}

	sampleNonHostCIDRs := map[string][]v1alpha1.Port{
		"1.1.1.0/24": {
			{
				Protocol: &protocolTCP,
				Port:     &port80,
			},
		},
	}

	tests := []struct {
		name         string
		firewallRule string
		nonHostCIDRs map[string][]v1alpha1.Port
		want         want
	}{
		{
			name:         "Match Present",
			firewallRule: "1.1.1.2/32",
			nonHostCIDRs: sampleNonHostCIDRs,
			want: want{
				matchingCIDRL4Info: []v1alpha1.Port{
					{
						Protocol: &protocolTCP,
						Port:     &port80,
					},
				},
			},
		},

		{
			name:         "No Match",
			firewallRule: "2.1.1.2/32",
			nonHostCIDRs: sampleNonHostCIDRs,
			want:         want{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatchingCIDRL4Info := checkAndDeriveL4InfoFromAnyMatchingCIDRs(tt.firewallRule, tt.nonHostCIDRs)
			assert.Equal(t, tt.want.matchingCIDRL4Info, gotMatchingCIDRL4Info)
		})
	}
}

func TestBpfClient_AddCatchAllL4Entry(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port80 int32 = 80

	l4InfoWithNoCatchAllEntry := EbpfFirewallRules{
		IPCidr: "1.1.1.1/32",
		L4Info: []v1alpha1.Port{
			{
				Protocol: &protocolTCP,
				Port:     &port80,
			},
		},
	}

	l4InfoWithCatchAllL4Info := EbpfFirewallRules{
		IPCidr: "1.1.1.1/32",
		L4Info: []v1alpha1.Port{
			{
				Protocol: &protocolTCP,
				Port:     &port80,
			},
			{
				Protocol: &CATCH_ALL_PROTOCOL,
			},
		},
	}

	tests := []struct {
		name          string
		firewallRules EbpfFirewallRules
	}{
		{
			name:          "Append Catch All Entry",
			firewallRules: l4InfoWithNoCatchAllEntry,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addCatchAllL4Entry(&tt.firewallRules)
			assert.Equal(t, tt.firewallRules, l4InfoWithCatchAllL4Info)
		})
	}
}

func TestMergeDuplicateL4Info(t *testing.T) {
	type mergeDuplicatePortsTestCase struct {
		Name     string
		Ports    []v1alpha1.Port
		Expected []v1alpha1.Port
	}
	protocolTCP := corev1.ProtocolTCP
	protocolUDP := corev1.ProtocolUDP

	testCases := []mergeDuplicatePortsTestCase{
		{
			Name: "Merge Duplicate Ports with nil Protocol",
			Ports: []v1alpha1.Port{
				{Protocol: &protocolTCP, Port: Int32Ptr(80), EndPort: Int32Ptr(8080)},
				{Protocol: nil, Port: Int32Ptr(53), EndPort: Int32Ptr(53)},
				{Protocol: nil, Port: Int32Ptr(53), EndPort: Int32Ptr(53)},
				{Protocol: &protocolTCP, Port: Int32Ptr(80), EndPort: Int32Ptr(8080)},
				{Protocol: &protocolTCP, Port: Int32Ptr(8081), EndPort: Int32Ptr(8081)},
			},
			Expected: []v1alpha1.Port{
				{Protocol: &protocolTCP, Port: Int32Ptr(80), EndPort: Int32Ptr(8080)},
				{Protocol: nil, Port: Int32Ptr(53), EndPort: Int32Ptr(53)},
				{Protocol: &protocolTCP, Port: Int32Ptr(8081), EndPort: Int32Ptr(8081)},
			},
		},
		{
			Name: "Merge Duplicate Ports with nil EndPort",
			Ports: []v1alpha1.Port{
				{Protocol: &protocolUDP, Port: Int32Ptr(53), EndPort: nil},
				{Protocol: &protocolUDP, Port: Int32Ptr(53), EndPort: nil},
			},
			Expected: []v1alpha1.Port{
				{Protocol: &protocolUDP, Port: Int32Ptr(53), EndPort: nil},
			},
		},
		{
			Name: "Merge Duplicate Ports with nil Port",
			Ports: []v1alpha1.Port{
				{Protocol: &protocolTCP, Port: nil, EndPort: Int32Ptr(8080)},
				{Protocol: &protocolTCP, Port: nil, EndPort: Int32Ptr(8080)},
			},
			Expected: []v1alpha1.Port{
				{Protocol: &protocolTCP, Port: nil, EndPort: Int32Ptr(8080)},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mergedPorts := mergeDuplicateL4Info(tc.Ports)
			assert.Equal(t, len(tc.Expected), len(mergedPorts))
		})
	}
}

func Int32Ptr(i int32) *int32 {
	return &i
}
