package aws

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// eksToken returns a function that makes a bearer token for an EKS cluster's
// API server from the caller's AWS identity, the way `aws eks get-token`
// does: a presigned STS GetCallerIdentity request that names the cluster in
// a signed header. The cluster maps that identity to Kubernetes permissions
// (an access entry or the aws-auth ConfigMap); without a mapping the API
// server answers 401 or 403. The token lives for about a minute and is never
// stored.
func eksToken(cfg aws.Config, cluster string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		presigner := sts.NewPresignClient(sts.NewFromConfig(cfg))
		req, err := presigner.PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(po *sts.PresignOptions) {
			po.ClientOptions = append(po.ClientOptions, func(o *sts.Options) {
				o.APIOptions = append(o.APIOptions,
					smithyhttp.SetHeaderValue("x-k8s-aws-id", cluster),
					smithyhttp.SetHeaderValue("X-Amz-Expires", "60"),
				)
			})
		})
		if err != nil {
			return "", fmt.Errorf("eks token for %s: %w", cluster, err)
		}
		return "k8s-aws-v1." + base64.RawURLEncoding.EncodeToString([]byte(req.URL)), nil
	}
}
