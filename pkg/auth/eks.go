//go:build !nocloud && !noaws

package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"k8s.io/client-go/rest"
)

const (
	clusterIDHeader = "x-k8s-aws-id"
	tokenExpiration = 15 * time.Minute
	tokenPrefix     = "k8s-aws-v1."
)

type EKSProvider struct {
	cfg       aws.Config
	eksClient *eks.Client
	stsClient *sts.Client
	regions   []string
	roleARN   string
}

type EKSProviderOptions struct {
	Region  string
	Regions []string
	RoleARN string
	Profile string
}

func NewEKSProvider(ctx context.Context, opts EKSProviderOptions) (*EKSProvider, error) {
	cfgOpts := []func(*config.LoadOptions) error{}

	if opts.Region != "" {
		cfgOpts = append(cfgOpts, config.WithRegion(opts.Region))
	}

	if opts.Profile != "" {
		cfgOpts = append(cfgOpts, config.WithSharedConfigProfile(opts.Profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	if opts.RoleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		creds := stscreds.NewAssumeRoleProvider(stsClient, opts.RoleARN)
		cfg.Credentials = aws.NewCredentialsCache(creds)
	}

	regions := opts.Regions
	if len(regions) == 0 && opts.Region != "" {
		regions = []string{opts.Region}
	}

	return &EKSProvider{
		cfg:       cfg,
		eksClient: eks.NewFromConfig(cfg),
		stsClient: sts.NewFromConfig(cfg),
		regions:   regions,
		roleARN:   opts.RoleARN,
	}, nil
}

func (p *EKSProvider) Name() string {
	return "aws"
}

func (p *EKSProvider) GetRestConfig(ctx context.Context, clusterName string) (*rest.Config, error) {
	describeOutput, err := p.eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
		Name: aws.String(clusterName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to access cluster (check credentials and permissions)")
	}

	cluster := describeOutput.Cluster
	if cluster == nil {
		return nil, fmt.Errorf("cluster not found")
	}

	caData, err := base64.StdEncoding.DecodeString(aws.ToString(cluster.CertificateAuthority.Data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode CA data")
	}

	token, err := p.generateToken(ctx, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to generate authentication token")
	}

	return &rest.Config{
		Host:        aws.ToString(cluster.Endpoint),
		BearerToken: token,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: caData,
		},
		QPS:   50,
		Burst: 100,
	}, nil
}

func (p *EKSProvider) generateToken(ctx context.Context, clusterName string) (string, error) {
	presignClient := sts.NewPresignClient(p.stsClient)

	presignedReq, err := presignClient.PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{},
		func(po *sts.PresignOptions) {
			po.ClientOptions = append(po.ClientOptions, func(o *sts.Options) {
				o.APIOptions = append(o.APIOptions, smithyhttp.AddHeaderValue(clusterIDHeader, clusterName))
			})
		},
	)
	if err != nil {
		return "", fmt.Errorf("failed to generate presigned request")
	}

	token := tokenPrefix + base64.RawURLEncoding.EncodeToString([]byte(presignedReq.URL))

	return token, nil
}

func (p *EKSProvider) ListClusters(ctx context.Context) ([]ClusterInfo, error) {
	var allClusters []ClusterInfo

	for _, region := range p.regions {
		clusters, err := p.listClustersInRegion(ctx, region)
		if err != nil {
			continue
		}
		allClusters = append(allClusters, clusters...)
	}

	return allClusters, nil
}

func (p *EKSProvider) listClustersInRegion(ctx context.Context, region string) ([]ClusterInfo, error) {
	regionalCfg := p.cfg.Copy()
	regionalCfg.Region = region
	eksClient := eks.NewFromConfig(regionalCfg)

	var clusters []ClusterInfo
	paginator := eks.NewListClustersPaginator(eksClient, &eks.ListClustersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list clusters")
		}

		for _, clusterName := range page.Clusters {
			describeOutput, err := eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
				Name: aws.String(clusterName),
			})
			if err != nil {
				continue
			}

			cluster := describeOutput.Cluster
			tags := make(map[string]string)
			for k, v := range cluster.Tags {
				tags[k] = v
			}

			clusters = append(clusters, ClusterInfo{
				Name:     clusterName,
				Provider: "aws",
				Region:   region,
				Endpoint: aws.ToString(cluster.Endpoint),
				Version:  aws.ToString(cluster.Version),
				Tags:     tags,
			})
		}
	}

	return clusters, nil
}

func (p *EKSProvider) GetClusterInfo(ctx context.Context, clusterName string) (*ClusterInfo, error) {
	describeOutput, err := p.eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
		Name: aws.String(clusterName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to access cluster (check credentials and permissions)")
	}

	cluster := describeOutput.Cluster
	tags := make(map[string]string)
	for k, v := range cluster.Tags {
		tags[k] = v
	}

	return &ClusterInfo{
		Name:     clusterName,
		Provider: "aws",
		Region:   p.cfg.Region,
		Endpoint: aws.ToString(cluster.Endpoint),
		Version:  aws.ToString(cluster.Version),
		Tags:     tags,
	}, nil
}

func init() {
	// Register EKS provider availability
	registerCloudProvider("aws")
}
