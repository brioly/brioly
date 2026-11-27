package aws

import (
	"encoding/json"
	"fmt"
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
		if len(urls) > maxQueues {
			break
		}
	}
	var limit error
	if len(urls) > maxQueues {
		urls, limit = urls[:maxQueues], errLimit("queues", maxQueues)
	}
	for _, u := range urls {
		out, e := s.c.SQS.GetQueueAttributes(s.ctx, &sqs.GetQueueAttributesInput{QueueUrl: aws.String(u), AttributeNames: queueAttributes})
		name := u[strings.LastIndex(u, "/")+1:]
		// A queue's ARN follows from its URL: account and name.
		arn := "arn:" + s.acct.Partition + ":sqs:" + s.region + ":" + s.acct.ID + ":" + name
		if parts := strings.Split(u, "/"); len(parts) >= 2 {
			arn = "arn:" + s.acct.Partition + ":sqs:" + s.region + ":" + parts[len(parts)-2] + ":" + name
		}
		switch {
		case gone(e):
			continue // deleted after it was listed
		case refused(e):
			// This queue's own policy refuses: it exists, and its
			// settings are not known.
			f := s.fact(arn, "aws.sqs.queue", name)
			_ = unread(&f, "attributes", e)
			s.add(f)
			continue
		case e != nil:
			aerr = firstErr(aerr, e)
			continue
		}
		a := out.Attributes
		if a["QueueArn"] != "" {
			arn = a["QueueArn"]
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
	s.coverLimit("aws.sqs.queue", err, aerr, limit, "queue attributes")
}

// ---- SNS ----

// arnProtocols are the subscription protocols whose endpoint is an AWS
// resource. The endpoint of any other protocol (an email address, a phone
// number, a URL that may carry a token) is never kept.
var arnProtocols = map[string]bool{"sqs": true, "lambda": true, "firehose": true}

// collectSNS lists topics and, per topic, its subscriptions: at most
// maxSubscriptionPage pages. A topic with more (a topic of mobile devices
// can have millions) is marked as not read for its subscriptions rather
// than read in part: which ones a part holds is not something to rely on.
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
		if len(topics) > maxTopics {
			break
		}
	}
	var limit error
	if len(topics) > maxTopics {
		topics, limit = topics[:maxTopics], errLimit("topics", maxTopics)
	}
	type read struct {
		fact    facts.Fact
		targets []string
		err     error
		gone    bool
	}
	reads := make([]read, len(topics))
	parallel(len(topics), func(i int) {
		arn, r := topics[i], &reads[i]
		name := arn[strings.LastIndex(arn, ":")+1:]
		f := s.fact(arn, "aws.sns.topic", name)
		f.Attributes["fifo"] = strings.HasSuffix(name, ".fifo")
		defer func() { r.fact = f }()
		var protocols, targets []string
		count := 0
		var token *string
		for page := 0; ; page++ {
			if page == maxSubscriptionPage {
				f.Attributes["unread"] = []string{fmt.Sprintf("subscriptions (more than %d)", maxSubscriptionPage*100)}
				return
			}
			out, e := s.c.SNS.ListSubscriptionsByTopic(s.ctx, &sns.ListSubscriptionsByTopicInput{TopicArn: aws.String(arn), NextToken: token})
			if gone(e) {
				r.gone = true
				return
			}
			if e != nil {
				r.err = unread(&f, "subscriptions", e)
				return
			}
			for _, sub := range out.Subscriptions {
				protocol := aws.ToString(sub.Protocol)
				count++
				protocols = append(protocols, protocol)
				if arnProtocols[protocol] {
					targets = append(targets, lambdaARN(aws.ToString(sub.Endpoint)))
				}
			}
			if token = out.NextToken; aws.ToString(token) == "" {
				break
			}
		}
		f.Attributes["subscription_protocols"] = facts.SortedStrings(protocols)
		f.Volatile = map[string]any{"subscription_count": count}
		r.targets = facts.SortedStrings(targets)
	})
	var serr error
	for _, r := range reads {
		if r.gone {
			continue
		}
		s.add(r.fact)
		for _, t := range r.targets {
			s.routesToARN(r.fact.ID, t)
		}
		serr = firstErr(serr, r.err)
	}
	s.coverLimit("aws.sns.topic", err, serr, limit, "subscriptions")
}

// ---- Lambda event sources ----

// EventSourceCoverage is the coverage kind of Lambda event source mappings,
// and the producer of the relationships read from them.
const EventSourceCoverage = "aws.lambda.event_source_mapping"

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
				// The relationship names the listing it was read from, so
				// that a scan in which that listing fails keeps it
				// (facts.CarryForward).
				s.res.Edges = append(s.res.Edges, facts.NewEdge(facts.EdgeRoutesTo, facts.AWSID(source), facts.AWSID(fn),
					facts.Derivation{Type: facts.Observed, Producer: EventSourceCoverage}, nil))
			}
		}
	}
	s.cover(EventSourceCoverage, err)
}
