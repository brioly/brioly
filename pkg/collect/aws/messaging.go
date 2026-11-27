package aws

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"github.com/brioly/brioly/pkg/facts"
)

// ---- SQS ----

// queueAttributes are the only attributes asked for. The queue's policy,
// its message counts and its timestamps are never requested.
var queueAttributes = []sqstypes.QueueAttributeName{
	sqstypes.QueueAttributeNameQueueArn, sqstypes.QueueAttributeNameFifoQueue, sqstypes.QueueAttributeNameRedrivePolicy,
	sqstypes.QueueAttributeNameKmsMasterKeyId, sqstypes.QueueAttributeNameSqsManagedSseEnabled,
	sqstypes.QueueAttributeNameVisibilityTimeout, sqstypes.QueueAttributeNameMessageRetentionPeriod,
}

// collectSQS lists queues and reads the named attributes of each. No
// message is received.
func (s *scan) collectSQS() {
	if s.c.SQS == nil {
		return
	}
	var urls []string
	p := sqs.NewListQueuesPaginator(s.c.SQS, &sqs.ListQueuesInput{MaxResults: aws.Int32(1000)})
	var err, aerr error
	for p.HasMorePages() {
		var out *sqs.ListQueuesOutput
		if out, err = p.NextPage(s.ctx); err != nil {
			break
		}
		urls = append(urls, out.QueueUrls...)
	}
	for _, u := range urls {
		out, e := s.c.SQS.GetQueueAttributes(s.ctx, &sqs.GetQueueAttributesInput{QueueUrl: aws.String(u), AttributeNames: queueAttributes})
		if e != nil {
			aerr = firstErr(aerr, e)
			continue
		}
		a := out.Attributes
		name := u[strings.LastIndex(u, "/")+1:]
		arn := a["QueueArn"]
		if arn == "" {
			arn = "arn:" + s.acct.Partition + ":sqs:" + s.region + ":" + s.acct.ID + ":" + name
		}
		f := s.fact(arn, "aws.sqs.queue", name)
		f.Attributes["fifo"] = a["FifoQueue"] == "true"
		switch {
		case a["KmsMasterKeyId"] != "":
			f.Attributes["encryption"] = "kms"
		case a["SqsManagedSseEnabled"] == "true":
			f.Attributes["encryption"] = "sse-sqs"
		default:
			f.Attributes["encryption"] = "none"
		}
		var redrive struct {
			Target string `json:"deadLetterTargetArn"`
			// AWS writes the count as a number or as a string.
			Max json.RawMessage `json:"maxReceiveCount"`
		}
		f.Attributes["dead_letter_queue"] = ""
		if json.Unmarshal([]byte(a["RedrivePolicy"]), &redrive) == nil && redrive.Target != "" {
			f.Attributes["dead_letter_queue"] = redrive.Target[strings.LastIndex(redrive.Target, ":")+1:]
			if n, e := strconv.Atoi(strings.Trim(string(redrive.Max), `"`)); e == nil {
				f.Attributes["max_receive_count"] = n
			}
			s.routesToARN(f.ID, redrive.Target)
		}
		if n, e := strconv.Atoi(a["VisibilityTimeout"]); e == nil {
			f.Attributes["visibility_timeout_s"] = n
		}
		if n, e := strconv.Atoi(a["MessageRetentionPeriod"]); e == nil {
			f.Attributes["retention_s"] = n
		}
		s.add(f)
	}
	s.coverParts("aws.sqs.queue", err, aerr, "queue attributes")
}

// ---- SNS ----

// arnProtocols are the subscription protocols whose endpoint is an AWS
// resource. The endpoint of any other protocol (an email address, a phone
// number, a URL that may carry a token) is never kept.
var arnProtocols = map[string]bool{"sqs": true, "lambda": true, "firehose": true}

func (s *scan) collectSNS() {
	if s.c.SNS == nil {
		return
	}
	var topics []string
	p := sns.NewListTopicsPaginator(s.c.SNS, &sns.ListTopicsInput{})
	var err error
	for p.HasMorePages() {
		var out *sns.ListTopicsOutput
		if out, err = p.NextPage(s.ctx); err != nil {
			break
		}
		for _, t := range out.Topics {
			topics = append(topics, aws.ToString(t.TopicArn))
		}
	}
	type subs struct {
		protocols []string
		count     int
		targets   []string
	}
	byTopic := map[string]*subs{}
	sp := sns.NewListSubscriptionsPaginator(s.c.SNS, &sns.ListSubscriptionsInput{})
	var serr error
	for sp.HasMorePages() {
		var out *sns.ListSubscriptionsOutput
		if out, serr = sp.NextPage(s.ctx); serr != nil {
			break
		}
		for _, sub := range out.Subscriptions {
			t := byTopic[aws.ToString(sub.TopicArn)]
			if t == nil {
				t = &subs{}
				byTopic[aws.ToString(sub.TopicArn)] = t
			}
			protocol := aws.ToString(sub.Protocol)
			t.count++
			t.protocols = append(t.protocols, protocol)
			if arnProtocols[protocol] {
				t.targets = append(t.targets, lambdaARN(aws.ToString(sub.Endpoint)))
			}
		}
	}
	for _, arn := range topics {
		name := arn[strings.LastIndex(arn, ":")+1:]
		f := s.fact(arn, "aws.sns.topic", name)
		f.Attributes["fifo"] = strings.HasSuffix(name, ".fifo")
		if serr == nil {
			t := byTopic[arn]
			if t == nil {
				t = &subs{}
			}
			f.Attributes["subscription_protocols"] = facts.SortedStrings(t.protocols)
			f.Attributes["subscription_count"] = t.count
			for _, target := range facts.SortedStrings(t.targets) {
				s.routesToARN(f.ID, target)
			}
		}
		s.add(f)
	}
	s.coverParts("aws.sns.topic", err, serr, "subscriptions")
}

// ---- Lambda event sources ----

// collectEventSources links a queue or a table (through its stream) to the
// function it triggers. Mappings are not facts; what was read of them is
// recorded as coverage of its own, so that a role without this permission
// leaves the functions themselves complete.
func (s *scan) collectEventSources() {
	if s.c.Lambda == nil {
		return
	}
	p := lambda.NewListEventSourceMappingsPaginator(s.c.Lambda, &lambda.ListEventSourceMappingsInput{})
	var err error
	for p.HasMorePages() {
		var out *lambda.ListEventSourceMappingsOutput
		if out, err = p.NextPage(s.ctx); err != nil {
			break
		}
		for _, m := range out.EventSourceMappings {
			source, fn := aws.ToString(m.EventSourceArn), lambdaARN(aws.ToString(m.FunctionArn))
			// A table's stream is named after the table.
			if i := strings.Index(source, "/stream/"); i >= 0 && strings.Contains(source, ":dynamodb:") {
				source = source[:i]
			}
			if source != "" && fn != "" {
				s.edge(facts.EdgeRoutesTo, facts.AWSID(source), facts.AWSID(fn))
			}
		}
	}
	s.cover("aws.lambda.event_source_mapping", err)
}
